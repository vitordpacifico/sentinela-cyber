from __future__ import annotations

from tree_sitter import Node

from sentinela.engine.languages.base import FileContext, LanguageAdapter
from sentinela.engine.models import Engine, Finding, Severity
from sentinela.pii.categorias import CategoriaPII, classificar_nome
from sentinela.pii.fluxo import AnalisadorFluxoPII, carregar_spec_pii
from sentinela.pii.valores import encontrar_cns, encontrar_cpfs, mascarar_dados_pessoais

_DECLARACOES = {
    "pair",
    "property_signature",
    "public_field_definition",
    "shorthand_property_identifier",
    "field_declaration",
    "keyword_argument",
}

_REFERENCIAS = [
    "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
    "https://cwe.mitre.org/data/definitions/359.html",
]


def analisar_dados_pessoais(
    adapter: LanguageAdapter,
    root: Node,
    ctx: FileContext,
    *,
    path: str,
    source_lines: list[str],
    rules_dir: str | None = None,
) -> tuple[list[Finding], list[Finding]]:

    padroes = [*_mapear(adapter, root, path, source_lines), *_valores_reais(adapter, root, path, source_lines)]
    spec = carregar_spec_pii(adapter.rules_language, rules_dir)
    fluxo = AnalisadorFluxoPII(adapter, spec, ctx, path=path, source_lines=source_lines).run(root) if spec else []
    return padroes, fluxo


def _nomes_declarados(adapter: LanguageAdapter, node: Node) -> list[str]:
    if node.type in adapter.assignment_types:
        return [nome for nome, _ in adapter.assignment_targets(node)]
    if node.type in adapter.function_types:
        return [param.name for param in adapter.function_params(node)]
    if node.type not in _DECLARACOES:
        return []
    if node.type == "shorthand_property_identifier":
        return [adapter.text(node)]
    if node.type == "field_declaration":
        return [
            adapter.text(declarador.child_by_field_name("name"))
            for declarador in node.named_children
            if declarador.type == "variable_declarator"
        ]
    chave = node.child_by_field_name("key") or node.child_by_field_name("name")
    if chave is None:
        return []
    valor = adapter.string_value(chave)
    return [valor if valor is not None else adapter.text(chave)]


def _mapear(adapter: LanguageAdapter, root: Node, path: str, lines: list[str]) -> list[Finding]:
    achados: dict[tuple[str, str], Finding] = {}
    for node in adapter.walk(root):
        for nome in _nomes_declarados(adapter, node):
            categoria = classificar_nome(nome)
            if categoria is None:
                continue
            chave = (categoria.id, nome.split(".")[-1].lower())
            if chave not in achados:
                achados[chave] = _achado_mapa(adapter, node, nome, categoria, path, lines)
    return list(achados.values())


def _achado_mapa(
    adapter: LanguageAdapter,
    node: Node,
    nome: str,
    categoria: CategoriaPII,
    path: str,
    lines: list[str],
) -> Finding:
    linha = adapter.line(node)
    sensivel = " É um dado pessoal sensível pela LGPD (art. 5º, II)." if categoria.sensivel else ""
    return Finding(
        rule_id=f"pii.mapa.{categoria.id}",
        title=f"Dado pessoal mapeado: {categoria.rotulo}",
        language=adapter.name,
        file_path=path,
        line=linha,
        end_line=linha,
        column=node.start_point[1] + 1,
        severity=Severity.INFO,
        cwe="CWE-359",
        owasp="",
        message=f"`{nome}` guarda {categoria.descricao_cidadao}.{sensivel} Confira se o dado é necessário e se está protegido.",
        snippet=_linha(lines, linha),
        engines={Engine.RULE},
        remediation=(
            "Colete só o necessário (LGPD, art. 6º, III), proteja o dado em repouso com criptografia "
            "e nunca envie para logs, URLs ou notificações."
        ),
        references=list(_REFERENCIAS),
    )


def _valores_reais(adapter: LanguageAdapter, root: Node, path: str, lines: list[str]) -> list[Finding]:
    achados: list[Finding] = []
    for valor, node in adapter.string_literals(root):
        for tipo, encontrados in (("cpf", encontrar_cpfs(valor)), ("cns", encontrar_cns(valor))):
            if not encontrados:
                continue
            linha = adapter.line(node)
            nome = "CPF" if tipo == "cpf" else "Cartão Nacional de Saúde (Cartão SUS)"
            achados.append(
                Finding(
                    rule_id=f"pii.valor.{tipo}",
                    title=f"{nome} válido escrito no código",
                    language=adapter.name,
                    file_path=path,
                    line=linha,
                    end_line=adapter.end_line(node),
                    column=node.start_point[1] + 1,
                    severity=Severity.HIGH,
                    cwe="CWE-359",
                    owasp="A04:2021 - Insecure Design",
                    message=(
                        f"O texto contém um {nome} com dígitos verificadores corretos "
                        f"({mascarar_dados_pessoais(encontrados[0])}). Pode ser o documento de uma pessoa real "
                        "e fica para sempre no histórico do repositório."
                    ),
                    snippet=_linha(lines, linha),
                    engines={Engine.RULE},
                    remediation=(
                        "Use dados fictícios gerados para teste, nunca documentos reais. Se o documento já foi "
                        "enviado ao repositório, remova do histórico e avise o encarregado de dados (DPO)."
                    ),
                    safe_example="const CPF_TESTE = gerarCpfFicticio(); // gerado na hora, não pertence a ninguém",
                    references=list(_REFERENCIAS),
                ),
            )
    return achados


def _linha(lines: list[str], numero: int) -> str:
    texto = lines[numero - 1].strip()[:200] if 1 <= numero <= len(lines) else ""
    return mascarar_dados_pessoais(texto)


__all__ = ["analisar_dados_pessoais"]
