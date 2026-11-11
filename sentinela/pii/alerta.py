from __future__ import annotations

from typing import Any

from sentinela.pii.categorias import POR_ID, CategoriaPII

_CONSEQUENCIA = {
    "saude": "Isso pode causar constrangimento, discriminação no trabalho ou no plano de saúde, e golpes.",
    "sensivel": "Isso pode causar discriminação e constrangimento.",
    "documento": "Com o CPF, golpistas abrem contas, pedem crédito e aplicam golpes em nome da pessoa.",
    "credencial": "Com a senha, alguém pode entrar na conta e agir como se fosse a pessoa.",
    "localizacao": "A localização revela onde a pessoa mora ou onde está agora.",
    "contato": "Telefone e e-mail expostos aumentam golpes por mensagem e ligações falsas.",
    "identificacao": "Esses dados ajudam golpistas a se passar pela pessoa.",
    "registro": "Esses dados ajudam golpistas a se passar pela pessoa.",
}

_EXPOSICAO = {
    "log": "Pessoas da equipe técnica e serviços que recebem os registros do sistema podem ver {dado} de quem usa o app.",
    "armazenamento": "Se o celular ou o servidor for perdido, roubado ou invadido, alguém pode ler {dado} sem precisar de senha.",
    "url": "{Dado} ficam gravados no histórico do navegador e nos registros dos servidores por onde a requisição passa.",
    "notificacao": "{Dado} aparecem na tela bloqueada do celular, onde qualquer pessoa por perto consegue ler.",
    "analytics": "{Dado} são enviados a uma empresa de analytics, fora do controle do serviço público.",
    "area-transferencia": "Outros aplicativos instalados no celular podem ler {dado} copiados.",
    "valor": "Um documento verdadeiro ficou gravado no código do sistema, e qualquer pessoa com acesso ao código consegue copiá-lo.",
}


def categoria_do_achado(rule_id: str) -> CategoriaPII | None:

    partes = rule_id.split(".")
    if len(partes) < 3 or partes[0] != "pii":
        return None
    if partes[1] == "vazamento" and len(partes) >= 4:
        return POR_ID.get(partes[3])
    if partes[1] == "valor":
        return POR_ID["saude"] if partes[2] == "cns" else POR_ID["documento"]
    if partes[1] == "mapa":
        return POR_ID.get(partes[2])
    return None


def alerta_padrao(rule_id: str, remediation: str = "") -> dict[str, Any] | None:

    categoria = categoria_do_achado(rule_id)
    partes = rule_id.split(".")
    if categoria is None or partes[1] == "mapa":
        return None
    saida = "valor" if partes[1] == "valor" else partes[2]
    dado = categoria.descricao_cidadao
    exposicao = _EXPOSICAO.get(saida, "{Dado} podem ficar expostos.").format(
        dado=dado, Dado=dado[:1].upper() + dado[1:]
    )
    return {
        "titulo": f"Risco de exposição: {categoria.rotulo}",
        "o_que_pode_acontecer": f"{exposicao} {_CONSEQUENCIA.get(categoria.id, '')}".strip(),
        "quem_e_afetado": "Todas as pessoas cadastradas que usam esta parte do sistema.",
        "o_que_fazer": remediation or "A equipe deve impedir que o dado chegue a essa saída ou protegê-lo antes.",
        "gravidade": "crítica" if categoria.sensivel else "alta" if categoria.peso >= 0.8 else "média",
        "origem": "regras",
    }


__all__ = ["alerta_padrao", "categoria_do_achado"]
