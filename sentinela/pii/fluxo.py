"""Taint analysis de dados pessoais: do campo com dado pessoal até uma saída insegura.

Reaproveita o ``TaintAnalyzer`` do Sentinela (mesmo rastreamento entre
variáveis, atribuições e funções do arquivo) e troca só três peças:

* **fonte**: qualquer referência cujo nome indica dado pessoal
  (``usuario.cpf``, ``diagnostico``, ``senhaDigitada``);
* **sanitizador**: além da lista do ``pii.yml``, qualquer chamada cujo nome
  indica proteção (``mascararCpf``, ``hashSenha``, ``criptografar``);
* **achado**: o id da regra leva a categoria do dado
  (``pii.vazamento.log.saude``), e a severidade vem da categoria, porque um
  diagnóstico no log é mais grave que um e-mail no log.

O achado tem evidência de fluxo, então o Security Gate bloqueia quando a
severidade passa do limite da política.
"""

from __future__ import annotations

from functools import cache
from importlib import resources
from pathlib import Path

import yaml
from tree_sitter import Node

from sentinela.engine.models import Engine, Finding, Severity
from sentinela.engine.taint import SinkSpec, TaintAnalyzer, TaintSpec, Trace
from sentinela.pii.categorias import CategoriaPII, classificar_nome, nome_protegido, palavras
from sentinela.pii.valores import mascarar_dados_pessoais

# Partes do nome de uma chamada que indicam que o valor sai protegido.
_PROTECAO = {
    "mascarar",
    "mascara",
    "mask",
    "masked",
    "hash",
    "hashear",
    "sha256",
    "digest",
    "criptografar",
    "criptografa",
    "encrypt",
    "cifrar",
    "anonimizar",
    "anonymize",
    "pseudonimizar",
    "redact",
    "ocultar",
    "validar",
    "valido",
    "valida",
    "validate",
    "is",
    "tamanho",
    "length",
    "contar",
    "count",
}

DESCRICAO_SAIDA = {
    "log": "o log do sistema, que costuma ser lido por várias pessoas e enviado a outros serviços",
    "armazenamento": "o armazenamento do aparelho ou do servidor, sem criptografia",
    "url": "a URL, que fica no histórico, nos logs dos servidores e nos proxies",
    "notificacao": "uma notificação, que aparece na tela bloqueada do celular",
    "analytics": "uma ferramenta de analytics de terceiros",
    "area-transferencia": "a área de transferência, que outros apps conseguem ler",
}


def tipo_saida(rule_id: str) -> str:
    """``pii.vazamento.log.saude`` -> ``log``."""

    partes = rule_id.split(".")
    return partes[2] if len(partes) > 2 else ""


@cache
def carregar_spec_pii(linguagem: str, rules_dir: str | None = None) -> TaintSpec | None:
    directory = Path(rules_dir) if rules_dir else Path(str(resources.files("sentinela") / "rules"))
    arquivo = directory / "pii.yml"
    if not arquivo.exists():
        return None
    bruto = (yaml.safe_load(arquivo.read_text(encoding="utf-8")) or {}).get(linguagem)
    if not bruto:
        return None
    sinks = tuple(
        SinkSpec(
            id=sink["id"],
            title=sink["title"],
            severity=Severity.parse(sink["severity"]),
            cwe=sink["cwe"],
            owasp=sink.get("owasp", ""),
            calls=tuple(sink.get("calls", ())),
            args=sink.get("args", "any"),
            require_kwarg={},
            member_assign=tuple(sink.get("member_assign", ())),
            remediation=" ".join(str(sink.get("remediation", "")).split()),
            example=str(sink.get("example", "")).rstrip(),
        )
        for sink in bruto.get("sinks", [])
    )
    return TaintSpec(
        language=linguagem,
        source_members=(),
        source_calls=(),
        param_annotations=(),
        sanitizers=tuple(bruto.get("sanitizers", ())),
        sinks=sinks,
    )


class AnalisadorFluxoPII(TaintAnalyzer):
    """Taint analysis em que a fonte é o dado pessoal, e não a entrada do atacante."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._categorias: dict[str, CategoriaPII] = {}

    def _source_trace(self, reference: str, node: Node) -> Trace | None:
        categoria = classificar_nome(reference)
        if categoria is None:
            return None
        origem = f"`{reference}` ({categoria.rotulo})"
        self._categorias[origem] = categoria
        return Trace(source=origem, steps=(self._step(node, "source"),))

    def _taint(self, node: Node | None, env: dict[str, Trace]) -> Trace | None:
        # ``usuario.senhaHash``: o campo já é a versão protegida do dado, mesmo que
        # o objeto ``usuario`` tenha outros dados pessoais.
        if node is not None:
            referencia = self.adapter.reference_name(node)
            if referencia and "." in referencia and nome_protegido(referencia):
                return None
        return super()._taint(node, env)

    def _is_sanitizer(self, call_name: str) -> bool:
        if super()._is_sanitizer(call_name):
            return True
        ultima_parte = call_name.rsplit(".", 1)[-1]
        return bool(set(palavras(ultima_parte)) & _PROTECAO)

    def _record(
        self,
        sink: SinkSpec,
        node: Node,
        trace: Trace,
        sink_name: str,
        emit: bool,
        sink_hits: list[tuple[SinkSpec, Node, str]] | None,
    ) -> None:
        if sink_hits is not None:
            sink_hits.append((sink, node, sink_name))
        categoria = self._categorias.get(trace.source)
        if not emit or categoria is None:
            return
        rule_id = f"{sink.id}.{categoria.id}"
        line = self.adapter.line(node)
        if (line, rule_id) in self._findings:
            return
        saida = DESCRICAO_SAIDA.get(tipo_saida(sink.id), "uma saída insegura")
        sensivel = " É um dado pessoal sensível pela LGPD (art. 5º, II)." if categoria.sensivel else ""
        steps = [
            type(step)(step.line, step.kind, mascarar_dados_pessoais(step.code))
            for step in trace.extend(self._step(node, "sink")).steps
        ]
        self._findings[(line, rule_id)] = Finding(
            rule_id=rule_id,
            title=f"{sink.title}: {categoria.rotulo}",
            language=self.adapter.name,
            file_path=self.path,
            line=line,
            end_line=self.adapter.end_line(node),
            column=node.start_point[1] + 1,
            severity=categoria.severidade,
            cwe=sink.cwe,
            owasp=sink.owasp,
            message=f"{categoria.rotulo} vindo de {trace.source} chega a `{sink_name}`: {saida}.{sensivel}",
            snippet=mascarar_dados_pessoais(self._line_text(line)),
            engines={Engine.TAINT},
            taint_path=steps,
            remediation=sink.remediation,
            safe_example=sink.example,
            references=[
                f"https://cwe.mitre.org/data/definitions/{sink.cwe.split('-')[-1]}.html",
                "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
            ],
        )


__all__ = ["DESCRICAO_SAIDA", "AnalisadorFluxoPII", "carregar_spec_pii", "tipo_saida"]
