"""Módulo de dados pessoais (PII) do Sentinela, criado para a Global Solution 2026.2.

Responde a três perguntas sobre o código analisado:

1. **Onde o sistema guarda dados pessoais?** (``detector``: mapeamento pelo nome
   de campos e variáveis, e CPF ou Cartão SUS reais escritos no código);
2. **Esses dados vazam?** (``fluxo``: taint analysis do dado pessoal até uma
   saída insegura, como log, armazenamento sem criptografia ou URL);
3. **Qual o risco para o cidadão?** (``risco``: índice Risco Cidadão, de 0 a 100,
   e ``alerta``: explicação em linguagem simples para quem não é técnico).
"""

from sentinela.pii.categorias import CATEGORIAS, CategoriaPII, classificar_nome
from sentinela.pii.detector import analisar_dados_pessoais
from sentinela.pii.risco import calcular_risco_cidadao
from sentinela.pii.valores import mascarar_dados_pessoais

__all__ = [
    "CATEGORIAS",
    "CategoriaPII",
    "analisar_dados_pessoais",
    "calcular_risco_cidadao",
    "classificar_nome",
    "mascarar_dados_pessoais",
]
