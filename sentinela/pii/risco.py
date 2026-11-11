from __future__ import annotations

from collections import defaultdict
from typing import Any

from sentinela.pii.alerta import alerta_padrao, categoria_do_achado
from sentinela.pii.categorias import CATEGORIAS

PESO_SAIDA = {
    "url": 1.0,
    "armazenamento": 0.8,
    "log": 0.7,
    "analytics": 0.7,
    "notificacao": 0.6,
    "area-transferencia": 0.5,
    "valor": 0.9,
}
LIMITE_MAPEAMENTO = 15.0
FAIXAS = ((80, "critico", "Crítico"), (50, "alto", "Alto"), (20, "moderado", "Moderado"), (0, "baixo", "Baixo"))
_STATUS_FECHADOS = {"false_positive", "accepted_risk", "fixed"}


def _campo(achado: Any, nome: str, padrao: Any = None) -> Any:
    if isinstance(achado, dict):
        return achado.get(nome, padrao)
    valor = getattr(achado, nome, padrao)
    return getattr(valor, "value", valor)


def risco_do_achado(rule_id: str) -> float:

    categoria = categoria_do_achado(rule_id)
    partes = rule_id.split(".")
    if categoria is None or partes[1] == "mapa":
        return 0.0
    saida = "valor" if partes[1] == "valor" else partes[2]
    return round(categoria.peso * PESO_SAIDA.get(saida, 0.7), 4)


def faixa(indice: int) -> tuple[str, str]:
    return next((nivel, rotulo) for minimo, nivel, rotulo in FAIXAS if indice >= minimo)


def calcular_risco_cidadao(achados: list[Any]) -> dict[str, Any]:
    abertos = [
        a
        for a in achados
        if str(_campo(a, "rule_id", "")).startswith("pii.") and _campo(a, "status", "open") not in _STATUS_FECHADOS
    ]

    sobra = 1.0
    por_categoria: dict[str, dict[str, Any]] = defaultdict(lambda: {"mapeados": 0, "vazamentos": 0, "sobra": 1.0})
    mapeadas: set[str] = set()
    graves: list[tuple[float, Any]] = []

    for achado in abertos:
        rule_id = str(_campo(achado, "rule_id"))
        categoria = categoria_do_achado(rule_id)
        if categoria is None:
            continue
        info = por_categoria[categoria.id]
        if rule_id.startswith("pii.mapa."):
            info["mapeados"] += 1
            mapeadas.add(categoria.id)
            continue
        r = risco_do_achado(rule_id)
        sobra *= 1 - r
        info["vazamentos"] += 1
        info["sobra"] *= 1 - r
        graves.append((r, achado))

    parte_a = 100 * (1 - sobra)
    pesos = {c.id: c.peso for c in CATEGORIAS}
    parte_b = min(LIMITE_MAPEAMENTO, 2 * sum(pesos[c] for c in mapeadas))
    indice = round(parte_a + parte_b * (1 - parte_a / 100))
    nivel, rotulo = faixa(indice)

    categorias = [
        {
            "id": c.id,
            "rotulo": c.rotulo,
            "sensivel": c.sensivel,
            "mapeados": por_categoria[c.id]["mapeados"],
            "vazamentos": por_categoria[c.id]["vazamentos"],
            "contribuicao": round(100 * (1 - por_categoria[c.id]["sobra"])),
        }
        for c in CATEGORIAS
        if c.id in por_categoria
    ]
    categorias.sort(key=lambda c: (-c["vazamentos"], -c["contribuicao"], -c["mapeados"]))

    graves.sort(key=lambda par: -par[0])
    alertas = [
        {
            "id": _campo(achado, "id"),
            "titulo": _campo(achado, "title"),
            "arquivo": _campo(achado, "file_path"),
            "linha": _campo(achado, "line"),
            "risco": round(r * 100),
            "alerta_cidadao": _campo(achado, "alerta_cidadao")
            or alerta_padrao(str(_campo(achado, "rule_id")), str(_campo(achado, "remediation", ""))),
        }
        for r, achado in graves[:5]
    ]

    vazamentos = sum(1 for _, a in graves if str(_campo(a, "rule_id")).startswith("pii.vazamento."))
    valores = len(graves) - vazamentos
    return {
        "indice": indice,
        "nivel": nivel,
        "rotulo": rotulo,
        "resumo": _resumo(vazamentos, valores, categorias),
        "vazamentos": vazamentos,
        "valores_reais": valores,
        "dados_mapeados": sum(c["mapeados"] for c in categorias),
        "categorias": categorias,
        "alertas": alertas,
        "componentes": {"vazamentos": round(parte_a, 1), "mapeamento": round(parte_b, 1)},
        "formula": "Índice = A + B × (1 − A/100), em que A = 100 × (1 − Π(1 − peso da categoria × peso da saída)) "
        "e B = mín(15, 2 × soma dos pesos das categorias mapeadas).",
    }


def _resumo(vazamentos: int, valores: int, categorias: list[dict[str, Any]]) -> str:
    if not vazamentos and not valores:
        return "Nenhum vazamento de dado pessoal encontrado. O índice reflete só os dados que o sistema guarda."
    descricoes = {c.id: c.descricao_cidadao for c in CATEGORIAS}
    afetadas = [descricoes[c["id"]] for c in categorias if c["vazamentos"]]
    partes = []
    if vazamentos:
        partes.append(f"{vazamentos} {'vazamento' if vazamentos == 1 else 'vazamentos'} de dados pessoais")
    if valores:
        partes.append(f"{valores} {'documento real' if valores == 1 else 'documentos reais'} no código")
    texto = " e ".join(partes)
    if afetadas:
        texto += f", envolvendo {', '.join(afetadas[:-1]) + ' e ' + afetadas[-1] if len(afetadas) > 1 else afetadas[0]}"
    return texto[:1].upper() + texto[1:] + "."


__all__ = ["FAIXAS", "PESO_SAIDA", "calcular_risco_cidadao", "faixa", "risco_do_achado"]
