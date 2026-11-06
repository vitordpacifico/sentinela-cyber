"""Categorias de dados pessoais e a regra que reconhece cada uma pelo nome.

O nome de um campo ou variável (``cpfDoMorador``, ``data_nascimento``,
``usuario.senha``) é quebrado em palavras e comparado com os termos de cada
categoria. Assim o motor reconhece o dado em Python, JavaScript, TypeScript e
Java, em português ou inglês, em camelCase ou snake_case.

A classificação segue a LGPD (Lei 13.709/2018): dados de saúde, origem racial,
religião, vida sexual, biometria e genética são **dados pessoais sensíveis**
(art. 5º, II) e pesam mais no índice Risco Cidadão.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinela.engine.models import Severity


@dataclass(frozen=True)
class CategoriaPII:
    id: str
    rotulo: str
    sensivel: bool
    peso: float  # 0 a 1: quanto a exposição deste dado prejudica o cidadão
    severidade: Severity  # severidade de um vazamento comprovado
    descricao_cidadao: str  # como o dado aparece num alerta para o cidadão
    termos: tuple[tuple[str, ...], ...]  # cada termo é uma sequência de palavras


def _termos(*textos: str) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(texto.split()) for texto in textos)


CATEGORIAS: tuple[CategoriaPII, ...] = (
    CategoriaPII(
        id="saude",
        rotulo="Saúde",
        sensivel=True,
        peso=1.0,
        severidade=Severity.CRITICAL,
        descricao_cidadao="informações de saúde",
        termos=_termos(
            "saude",
            "diagnostico",
            "diagnosticos",
            "doenca",
            "doencas",
            "cid",
            "sintoma",
            "sintomas",
            "medicamento",
            "medicamentos",
            "remedio",
            "remedios",
            "alergia",
            "alergias",
            "deficiencia",
            "deficiencias",
            "prontuario",
            "laudo",
            "exame",
            "exames",
            "tratamento",
            "gestante",
            "gravidez",
            "comorbidade",
            "comorbidades",
            "vacina",
            "vacinas",
            "hiv",
            "tipo sanguineo",
            "cartao sus",
            "cns",
            "health",
            "diagnosis",
            "disease",
            "illness",
            "medication",
            "medications",
            "allergy",
            "allergies",
            "disability",
            "medical",
            "prescription",
            "pregnant",
            "symptom",
            "symptoms",
        ),
    ),
    CategoriaPII(
        id="sensivel",
        rotulo="Outros dados sensíveis",
        sensivel=True,
        peso=1.0,
        severidade=Severity.CRITICAL,
        descricao_cidadao="dados sensíveis, como raça, religião ou biometria",
        termos=_termos(
            "raca",
            "etnia",
            "religiao",
            "orientacao sexual",
            "biometria",
            "biometrico",
            "genetico",
            "opiniao politica",
            "filiacao sindical",
            "race",
            "ethnicity",
            "religion",
            "biometric",
            "sexual orientation",
            "genetic",
        ),
    ),
    CategoriaPII(
        id="documento",
        rotulo="CPF e documentos",
        sensivel=False,
        peso=0.8,
        severidade=Severity.HIGH,
        descricao_cidadao="CPF ou outros documentos",
        termos=_termos(
            "cpf",
            "rg",
            "cnh",
            "passaporte",
            "titulo eleitor",
            "pis",
            "nis",
            "pasep",
            "ssn",
            "passport",
            "documento",
            "document number",
        ),
    ),
    CategoriaPII(
        id="credencial",
        rotulo="Senhas e credenciais",
        sensivel=False,
        peso=0.9,
        severidade=Severity.HIGH,
        descricao_cidadao="senha ou código de acesso",
        termos=_termos("senha", "senhas", "password", "passwd", "pwd", "pin", "token", "otp", "secret", "segredo"),
    ),
    CategoriaPII(
        id="localizacao",
        rotulo="Localização",
        sensivel=False,
        peso=0.6,
        severidade=Severity.MEDIUM,
        descricao_cidadao="localização",
        termos=_termos(
            "latitude",
            "longitude",
            "geolocalizacao",
            "localizacao atual",
            "coordenadas",
            "geolocation",
            "lat lng",
            "gps",
        ),
    ),
    CategoriaPII(
        id="contato",
        rotulo="Contato e endereço",
        sensivel=False,
        peso=0.5,
        severidade=Severity.MEDIUM,
        descricao_cidadao="telefone, e-mail ou endereço",
        termos=_termos(
            "email",
            "e mail",
            "telefone",
            "celular",
            "whatsapp",
            "phone",
            "endereco",
            "logradouro",
            "cep",
            "address",
            "zipcode",
            "zip code",
        ),
    ),
    CategoriaPII(
        id="identificacao",
        rotulo="Identificação pessoal",
        sensivel=False,
        peso=0.4,
        severidade=Severity.MEDIUM,
        descricao_cidadao="nome completo ou data de nascimento",
        termos=_termos(
            "nome completo",
            "nome mae",
            "nome da mae",
            "data nascimento",
            "data de nascimento",
            "nascimento",
            "idade",
            "sexo",
            "genero",
            "full name",
            "birth date",
            "birthdate",
            "date of birth",
            "gender",
        ),
    ),
    CategoriaPII(
        id="registro",
        rotulo="Cadastro de pessoa",
        sensivel=False,
        peso=0.3,
        severidade=Severity.MEDIUM,
        descricao_cidadao="dados do cadastro",
        termos=_termos(
            "usuario",
            "usuarios",
            "paciente",
            "pacientes",
            "cidadao",
            "cidadaos",
            "morador",
            "moradores",
            "pessoa",
            "pessoas",
            "titular",
            "cadastro",
            "user",
            "patient",
            "citizen",
            "person",
        ),
    ),
)

POR_ID = {categoria.id: categoria for categoria in CATEGORIAS}

# Palavras que indicam que o dado já está protegido: não é mais o dado pessoal em si.
_PROTEGIDO = {
    "hash",
    "hashed",
    "sal",
    "salt",
    "mascara",
    "mascarado",
    "mascarada",
    "masked",
    "mask",
    "criptografado",
    "criptografada",
    "encrypted",
    "cifrado",
    "anonimizado",
    "pseudonimizado",
    "regex",
    "padrao",
    "pattern",
    "validar",
    "valido",
    "valida",
    "valid",
    "is",
    "formato",
    "format",
    "rotulo",
    "label",
    "placeholder",
    "erro",
    "error",
    "mensagem",
    "message",
    "tamanho",
    "length",
    "min",
    "max",
    "minimo",
    "maximo",
    "chave",
    "key",
    "campo",
    "field",
    "input",
    "ref",
    "visivel",
    "mostrar",
    "esconder",
    "show",
    "hide",
}

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_ACENTOS = str.maketrans(
    "áàâãäéèêëíìîïóòôõöúùûüçÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇ", "aaaaaeeeeiiiiooooouuuucAAAAAEEEEIIIIOOOOOUUUUC"
)


def palavras(nome: str) -> list[str]:
    """``cpfDoMorador`` -> ["cpf", "do", "morador"]; ``data_nascimento`` -> ["data", "nascimento"]."""

    texto = _CAMEL.sub(" ", nome.translate(_ACENTOS))
    return [parte for parte in re.split(r"[^A-Za-z0-9]+", texto.lower()) if parte]


def _contem(sequencia: list[str], termo: tuple[str, ...]) -> bool:
    tamanho = len(termo)
    return any(tuple(sequencia[i : i + tamanho]) == termo for i in range(len(sequencia) - tamanho + 1))


def nome_protegido(nome: str) -> bool:
    """``usuario.senhaHash`` ou ``cpfMascarado``: o último segmento indica dado já protegido."""

    ultimo = nome.split(".")[-1]
    return bool(set(palavras(ultimo)) & _PROTEGIDO)


def classificar_nome(nome: str) -> CategoriaPII | None:
    """Categoria do dado pessoal que o nome indica, ou ``None``.

    Usa só o último segmento de nomes pontuados (``usuario.senha`` -> senha),
    mas cai para o objeto inteiro (``usuario.id`` -> cadastro de pessoa).
    Nomes que indicam dado já protegido (``senhaHash``, ``cpfMascarado``) ou
    que são só metadados do campo (``cpfValido``, ``emailInput``) são ignorados.
    """

    segmentos = [s for s in nome.split(".") if s]
    if not segmentos:
        return None
    for candidato in (segmentos[-1], *reversed(segmentos[:-1])):
        partes = palavras(candidato)
        if not partes or set(partes) & _PROTEGIDO:
            if candidato is segmentos[-1]:
                return None
            continue
        for categoria in CATEGORIAS:
            if any(_contem(partes, termo) for termo in categoria.termos):
                return categoria
    return None


__all__ = ["CATEGORIAS", "POR_ID", "CategoriaPII", "classificar_nome", "nome_protegido", "palavras"]
