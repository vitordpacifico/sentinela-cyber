from __future__ import annotations

import re

_CPF = re.compile(r"(?<!\d)(\d{3})[.\s]?(\d{3})[.\s]?(\d{3})[-.\s]?(\d{2})(?!\d)")
_CNS = re.compile(r"(?<!\d)([1-2789]\d{2})\s?(\d{4})\s?(\d{4})\s?(\d{4})(?!\d)")
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_TELEFONE = re.compile(r"\(?\b(\d{2})\)?\s?(9?\d{4})[-\s]?(\d{4})\b")


def cpf_valido(numero: str) -> bool:
    digitos = re.sub(r"\D", "", numero)
    if len(digitos) != 11 or len(set(digitos)) == 1:
        return False
    for tamanho in (9, 10):
        soma = sum(int(digitos[i]) * (tamanho + 1 - i) for i in range(tamanho))
        verificador = (soma * 10) % 11 % 10
        if verificador != int(digitos[tamanho]):
            return False
    return True


def cns_valido(numero: str) -> bool:
    digitos = re.sub(r"\D", "", numero)
    if len(digitos) != 15 or digitos[0] not in "12789":
        return False
    return sum(int(d) * (15 - i) for i, d in enumerate(digitos)) % 11 == 0


def encontrar_cpfs(texto: str) -> list[str]:
    return [m.group(0) for m in _CPF.finditer(texto) if cpf_valido(m.group(0))]


def encontrar_cns(texto: str) -> list[str]:
    return [m.group(0) for m in _CNS.finditer(texto) if cns_valido(m.group(0))]


def mascarar_dados_pessoais(texto: str) -> str:

    if not texto:
        return texto

    def cpf(m: re.Match[str]) -> str:
        return f"***.***.***-{m.group(4)}" if cpf_valido(m.group(0)) else m.group(0)

    def cns(m: re.Match[str]) -> str:
        return f"*** **** **** {m.group(4)}" if cns_valido(m.group(0)) else m.group(0)

    texto = _CNS.sub(cns, texto)
    texto = _CPF.sub(cpf, texto)
    texto = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", texto)
    texto = _TELEFONE.sub(lambda m: f"(**) {'*' * len(m.group(2))}-{m.group(3)}", texto)
    return texto


__all__ = ["cns_valido", "cpf_valido", "encontrar_cns", "encontrar_cpfs", "mascarar_dados_pessoais"]
