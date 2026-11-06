# Global Solution 2026.2: módulo de dados pessoais do Sentinela

Entrega de **Cybersecurity** da Global Solution 2026.2 (FIAP, Engenharia de Software, 3º ano), tema CitizenTech.

O Sentinela é a ferramenta de SAST do grupo, criada no Projeto Integrador. Para a GS, ganhou um **módulo novo de dados pessoais** que protege os cidadãos atendidos pela nossa CitizenTech: o **SENTINELA**, app de alerta antecipado de alagamentos ([app de Mobile](https://github.com/vitordpacifico/sentinela-mobile)).

| Integrante | RM |
|---|---|
| Victor Pacifico Dias | 558017 |
| Gustavo Ruiz Vieira Paulino | 554779 |
| Guilherme Abe | 554743 |
| Eduardo | A preencher |
| Heloísa | A preencher |

## A missão e onde cada parte está

| Missão | O que foi feito | Onde está |
|---|---|---|
| **01. Mapeamento de PII** | Regras novas no motor de parsing (Tree-sitter) que reconhecem 8 categorias de dados pessoais pelo nome de campos, variáveis e parâmetros, e acham **CPF e Cartão SUS válidos** escritos no código (com cálculo dos dígitos verificadores). Suporte novo a **TypeScript**, a linguagem do app. | `sentinela/pii/categorias.py`, `sentinela/pii/valores.py`, `sentinela/pii/detector.py`, `sentinela/engine/languages/typescript.py` |
| **02. Taint Analysis** | Segue o dado pessoal até 6 tipos de saída insegura: log, armazenamento sem criptografia, URL, notificação, analytics e área de transferência. Reconhece proteções (mascarar, hash, criptografar, `expo-secure-store`). O **Security Gate bloqueia** o merge quando o vazamento é de dado sensível, CPF ou senha. | `sentinela/pii/fluxo.py`, `sentinela/rules/pii.yml` |
| **03. Tradução via IA** | O LLM local (Llama via Ollama) escreve um **alerta ao cidadão** em linguagem simples: o que pode acontecer, quem é afetado e o que fazer. O código chega à IA com **CPF, e-mail e telefone mascarados**. Sem IA, um alerta escrito por regras ocupa o lugar. | `sentinela/ai/assistant.py`, `sentinela/pii/alerta.py`, `sentinela/pii/valores.py` |
| **04. Dashboard Executivo** | Indicador **Risco Cidadão** (0 a 100) com medidor, faixa de risco, dados pessoais por categoria e alertas ao cidadão. Também na API, na CLI e no relatório Markdown. | `sentinela/pii/risco.py`, `sentinela/api/static/`, `GET /api/scans/{id}/risco-cidadao` |

## Categorias de dados pessoais

| Categoria | Exemplos de nome reconhecido | Sensível (LGPD, art. 5º, II) | Peso |
|---|---|:---:|---:|
| Saúde | `diagnostico`, `medicamentos`, `condicaoDeSaude`, `cartaoSus`, `alergias` | Sim | 1,0 |
| Outros dados sensíveis | `raca`, `religiao`, `biometria` | Sim | 1,0 |
| Senhas e credenciais | `senha`, `password`, `token`, `pin` | | 0,9 |
| CPF e documentos | `cpf`, `rg`, `cnh`, `passaporte` | | 0,8 |
| Localização | `latitude`, `longitude`, `gps` | | 0,6 |
| Contato e endereço | `email`, `telefone`, `cep`, `endereco` | | 0,5 |
| Identificação pessoal | `dataNascimento`, `nomeCompleto`, `sexo` | | 0,4 |
| Cadastro de pessoa | `usuario`, `paciente`, `cidadao`, `morador` | | 0,3 |

Nomes que indicam dado já protegido ou que não são o dado em si são ignorados: `senhaHash`, `cpfMascarado`, `cpfValido`, `emailInput`. Funciona em camelCase e snake_case, em português e inglês, e em Python, JavaScript, TypeScript e Java.

## Saídas inseguras (taint analysis)

| Saída | Por que expõe o cidadão | CWE | Peso |
|---|---|---|---:|
| URL (`fetch`, `axios.get`, `Linking.openURL`) | Fica no histórico, nos logs de servidores e em proxies | CWE-598 | 1,0 |
| Armazenamento sem criptografia (`AsyncStorage`, `localStorage`, arquivos) | Qualquer um com acesso ao aparelho ou ao servidor lê | CWE-312 | 0,8 |
| Log (`console.*`, `logger.*`, `print`, `System.out`) | Lido pela equipe e enviado a outros serviços | CWE-532 | 0,7 |
| Analytics (`logEvent`, `analytics.track`) | Vai para empresa terceira | CWE-359 | 0,7 |
| Notificação (`scheduleNotificationAsync`) | Aparece na tela bloqueada | CWE-359 | 0,6 |
| Área de transferência (`Clipboard.setString`) | Outros apps leem | CWE-200 | 0,5 |

A severidade de um vazamento vem da categoria do dado: saúde e dados sensíveis são **críticos**, CPF e senha são **altos**, e os demais são **médios**. Com a política padrão (`fail_on: high`), o gate bloqueia vazamento de saúde, CPF e senha, e só avisa nos demais.

## Indicador Risco Cidadão

Detalhado em [risco-cidadao.md](risco-cidadao.md). Em resumo:

- Cada vazamento vale `peso da categoria × peso da saída`. Por exemplo, um diagnóstico na URL vale 1,0, e um e-mail no log vale 0,35.
- Os vazamentos se somam como probabilidades: `A = 100 × (1 − Π(1 − r))`.
- O mapeamento, ou seja, dado guardado sem vazamento, pesa no máximo 15 pontos.
- As faixas são: **0–19 Baixo**, **20–49 Moderado**, **50–79 Alto** e **80–100 Crítico**.

## Auditoria do Protótipo

| Alvo | Gate | Risco Cidadão | Achados |
|---|---|---|---|
| `exemplos/prototipo-com-falhas` (falhas inseridas de propósito) | **Bloqueado** | **100, Crítico** | 5 vazamentos e 1 CPF real no código |
| `exemplos/prototipo-corrigido` (mesma função, corrigida) | Aprovado | 7, Baixo | 0 vazamentos |
| App SENTINELA de Mobile (`GS-Mobile/src`, código real) | Aprovado | 3, Baixo | 0 vazamentos; 100 campos com dado pessoal mapeados |

**O que a auditoria mudou no app.** Os campos mapeados mostraram onde o app guardava o telefone e o CEP do cidadão. Seguindo esses campos, a revisão manual achou um problema que o scanner não pega sozinho, porque o dado passa por dois arquivos (veja as limitações): esses dados iam para o AsyncStorage, que grava **sem criptografia**. O app foi corrigido, e agora o telefone e o CEP ficam no cofre do sistema (`expo-secure-store`: Keychain no iOS, Keystore no Android). A correção está no commit [45dc17f do app](https://github.com/vitordpacifico/sentinela-mobile/commit/45dc17f).

As evidências ficam em [`evidencias/`](../evidencias). Cada alvo tem o relatório Markdown, o JSON completo, o SARIF e a saída do terminal. Há também os prints do painel.

Para gerar tudo de novo:

```bash
python scripts/auditoria_gs.py
```

Com a IA escrevendo os alertas (é preciso ter o [Ollama](https://ollama.com) instalado e rodar `ollama pull llama3.2` antes):

```bash
python scripts/auditoria_gs.py --ai
```

## Como demonstrar no painel

```bash
python scripts/demo_gs.py --ai
```

```bash
sentinela serve
```

Abra `http://localhost:8000`.

- O projeto **prototipo-com-falhas** mostra o Risco Cidadão crítico e os alertas.
- O projeto **sentinela-app** mostra a queda das falhas ao longo de uma semana: o protótipo com falhas, depois corrigido, e por fim o app real.

Sem `--ai`, os alertas são escritos por regras e o painel avisa isso.

## Roteiro do vídeo

O PDF não fixa um tempo para o vídeo de Cyber. O roteiro cabe em 3 minutos.

Antes de gravar, rode `python scripts/demo_gs.py --ai` e deixe `sentinela serve` aberto em outra janela.

| Tempo | Mostrar | O que falar |
|---|---|---|
| 0:00 | Este documento, na tabela da missão | "O app SENTINELA guarda dados de moradores. Criamos no Sentinela um módulo que acha dados pessoais no código e bloqueia o merge quando eles vazam." |
| 0:20 | `exemplos/prototipo-com-falhas/cadastroMorador.ts` | "Este protótipo tem 5 vazamentos colocados de propósito: o diagnóstico vai para o celular sem criptografia e para a notificação, e o CPF vai para o log, para a URL e para o celular sem criptografia. Além disso, há um CPF real escrito no código." |
| 0:40 | Terminal: `sentinela scan exemplos/prototipo-com-falhas --policy exemplos/politica-auditoria.yml --no-bandit` | Mostrar o caminho do dado (de onde veio até onde vazou), o **gate bloqueado** e o Risco Cidadão 100. |
| 1:20 | O mesmo comando em `exemplos/prototipo-corrigido` | "Com as correções, o gate aprova e o risco cai para Baixo." |
| 1:40 | Painel, projeto `prototipo-com-falhas` | O medidor do **Risco Cidadão** (crítico), a tabela por categoria e os alertas ao cidadão escritos pela IA. Abrir um vazamento e mostrar o alerta. |
| 2:20 | Painel, projeto `sentinela-app` | "Ao longo da semana, as falhas caíram e o app real ficou com risco Baixo." Mostrar a tendência. |
| 2:40 | O parágrafo "O que a auditoria mudou no app" | "A auditoria achou o telefone e o CEP sem criptografia no app de Mobile, e nós corrigimos." |

## Limitações conhecidas

- **O fluxo é seguido dentro do mesmo arquivo.** Se um dado passa por funções de arquivos diferentes, ele não é rastreado. Um exemplo é o app de Mobile, antes da correção: o telefone e o CEP passavam do serviço de usuários para o serviço genérico de armazenamento, e esse caminho não aparecia. Quem achou o problema foi a revisão manual dos campos mapeados.
- **O reconhecimento é pelo nome.** Um campo com nome genérico, como `valor`, não é reconhecido como dado pessoal. Por outro lado, `tipoCidadao` é mapeado como cadastro de pessoa, mesmo sem ser um dado pessoal.
- **Uma saída que recebe dois dados gera um achado só.** O achado mostra a primeira categoria encontrada. Por exemplo, CPF e senha no mesmo `console.log` aparecem como um vazamento de CPF.
- **A IA local recomenda, mas não decide.** O alerta escrito pela IA não muda a severidade nem o gate, como já era no Sentinela.
