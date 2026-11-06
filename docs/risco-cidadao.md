# Indicador Risco Cidadão

Um número de 0 a 100 que responde: **quanto os dados das pessoas atendidas pelo sistema estão expostos?**

O índice serve para quem não é técnico, como um gestor público ou a coordenação do projeto, acompanhar o risco num só número. Ele é calculado em `sentinela/pii/risco.py`.

## Fórmula

**1. Risco de cada achado** (de 0 a 1):

```
r = peso da categoria do dado × peso da saída
```

| Categoria | Peso | | Saída | Peso |
|---|---:|---|---|---:|
| Saúde | 1,0 | | URL | 1,0 |
| Outros dados sensíveis | 1,0 | | Documento real no código | 0,9 |
| Senhas e credenciais | 0,9 | | Armazenamento sem criptografia | 0,8 |
| CPF e documentos | 0,8 | | Log | 0,7 |
| Localização | 0,6 | | Analytics | 0,7 |
| Contato e endereço | 0,5 | | Notificação | 0,6 |
| Identificação pessoal | 0,4 | | Área de transferência | 0,5 |
| Cadastro de pessoa | 0,3 | | | |

**2. Vazamentos** (parte A). Os riscos se somam como probabilidades independentes. A pergunta é: qual a chance de pelo menos um vazamento atingir o cidadão?

```
A = 100 × (1 − Π(1 − r))
```

**3. Mapeamento** (parte B). Dado guardado sem vazamento é exposição potencial, então pesa pouco:

```
B = mín(15, 2 × soma dos pesos das categorias mapeadas)
```

**4. Índice:**

```
Índice = A + B × (1 − A/100)
```

O resultado é arredondado. Quando A já é alto, o mapeamento quase não muda o resultado.

## Faixas

| Índice | Faixa | Leitura |
|---|---|---|
| 0–19 | Baixo | Nenhum vazamento relevante; o sistema só guarda dados |
| 20–49 | Moderado | Vazamentos de dados de menor impacto, como e-mail ou telefone |
| 50–79 | Alto | Vazamento de CPF, senha ou saúde em saída de menor exposição |
| 80–100 | Crítico | Dado sensível ou documento em saída de grande exposição, ou vários vazamentos juntos |

## Exemplos

| Situação | Cálculo | Índice |
|---|---|---:|
| Só mapeamento de saúde e contato | A = 0; B = 2 × (1,0 + 0,5) = 3 | 3 (Baixo) |
| E-mail no log | A = 100 × 0,35 = 35 | 35 (Moderado) |
| Diagnóstico na URL | A = 100 × 1,0 = 100 | 100 (Crítico) |
| Protótipo com falhas (5 vazamentos e 1 CPF real) | A ≈ 100 | 100 (Crítico) |

## Regras

- Só contam achados **abertos** ou **confirmados**. Falso positivo, risco aceito e corrigido saem da conta. Assim, a revisão feita no painel muda o índice.
- O índice usa o último scan concluído do projeto.
