# Uso de IA

As regras gerais da Global Solution pedem o registro dos prompts usados (página 21 do PDF da GS).

**Ferramenta:** Claude Code (modelo Claude Opus 5.5).

Abaixo estão os prompts principais da construção do módulo, em ordem. O texto de cada um foi revisado para ficar claro e completo, sem mudar o que foi pedido.

## Prompts

### 1. Entender a missão e escolher a base (05/11/2026)

> Leia as páginas 28 e 29 do PDF da Global Solution, que estão em imagem, e explique o que a disciplina de Cybersecurity pede: as três missões, o que vai no ZIP e como a nota é distribuída. Separe o que o PDF exige do que é dedução. Depois, avalie se o Sentinela, a ferramenta de SAST que o grupo criou no Projeto Integrador, serve como base, já que a missão fala em "novas regras no motor de parsing" e em "Dashboard Atualizado".

**Resultado:** Leitura das missões e da pontuação, com a proposta de usar o Sentinela como base. Fork em `vitordpacifico/sentinela-cyber`, com os 63 testes originais rodando.

### 2. Implementar o módulo de dados pessoais (06/11/2026)

> No Sentinela, implemente um módulo de dados pessoais com as três missões e o indicador. (1) Mapeamento de PII: regras no motor de parsing que reconheçam CPF, saúde, senhas e outras categorias pelo nome de campos e variáveis, em português e inglês, e que achem CPF e Cartão SUS verdadeiros pelo dígito verificador. (2) Taint analysis: siga o dado pessoal até saídas inseguras (log, URL, armazenamento sem criptografia, notificação, analytics e área de transferência), reconheça mascaramento e criptografia, e faça o Security Gate bloquear vazamento de saúde, CPF e senha. (3) IA: o LLM local escreve um alerta ao cidadão em linguagem simples e sugere a correção, recebendo o código com os dados pessoais mascarados. (4) Indicador Risco Cidadão de 0 a 100 na API, na CLI, no relatório e no painel. Adicione suporte a TypeScript, a linguagem do app, crie um protótipo com falhas inseridas de propósito e a versão corrigida, e cubra tudo com testes.

**Resultado:** Módulo `sentinela/pii/` com 9 categorias, CPF e Cartão SUS por dígito verificador, taint até 6 saídas, mascaramento antes da IA, alerta ao cidadão e Risco Cidadão na API, na CLI, no relatório e no painel. Suporte a TypeScript, protótipo com falhas e corrigido, scripts da auditoria, da demonstração e do ZIP, e 45 testes novos.

### 3. Auditar o app real do grupo (07/11/2026)

> Rode o módulo no código real do app Pluvia de Mobile. O documento de definição pede o mapeamento de dados pessoais em fotos e localização, então crie a categoria "Fotos e imagens" e reforce a de localização. Registre as evidências da auditoria (relatório, JSON, SARIF e saída do terminal) e, se o mapeamento mostrar algum dado pessoal mal protegido no app, corrija no repositório de Mobile.

**Resultado:** Categoria "Fotos e imagens", auditoria do app aprovada com Risco Cidadão baixo e evidências em `evidencias/`. A auditoria levou à correção do telefone e do CEP sem criptografia no app de Mobile.

### 4. Testar a IA de verdade (11/11/2026)

> Instale o Ollama e o modelo `llama3.2` e rode a auditoria com a IA ligada. Confira se cada vazamento recebe um alerta ao cidadão e uma correção realmente escritos pela IA, e não pelo texto de reserva. Se a resposta não chegar, vier cortada ou fora do formato, descubra a causa e corrija até os 6 vazamentos do protótipo terem alerta e correção da IA.

**Resultado:** Causas encontradas e corrigidas: limite de 60 segundos curto para o processador, resposta cortada, alerta fora do formato JSON e IA chamada para achados de mapeamento. Limite de 180 segundos, resposta mais longa, segunda tentativa e correção recomendada da regra enviada como referência. Os 6 vazamentos passaram a ter alerta e correção da IA.

### 5. Revisão final e evidências (15/11/2026)

> Faça uma revisão completa do repositório para a entrega: testes, lint, Security Gate, os três scans comparados com a documentação, links quebrados e qualquer dado pessoal nosso nas evidências. Garanta que a auditoria e o painel mostrem os mesmos números, que gráficos sem dados não pareçam quebrados e que a Ficha da CitizenTech esteja no início do README. Refaça as evidências com a IA ligada.

**Resultado:** Auditoria e painel com os mesmos números (testes do app fora da conta), gráficos vazios trocados por mensagens, triagem por IA sem os achados de mapeamento, Ficha da CitizenTech no README, evidências refeitas e 115 testes passando.

## Decisões sugeridas pela IA, para o grupo revisar

- Usar o Sentinela do grupo como base, porque o PDF fala em "novas regras no motor de parsing", "o LLM" e "Dashboard Atualizado".
- Reconhecer dado pessoal pelo nome do campo, mais CPF e Cartão SUS pelo valor.
- Pesos das categorias e das saídas, e a fórmula do Risco Cidadão (`docs/risco-cidadao.md`).
- Gravidade do vazamento definida pela categoria do dado: saúde é crítica; CPF e senha são altos.
- Protótipo de auditoria com CPF e saúde, já que o app de Mobile entregue não coleta esses dados.
- Fotos com o mesmo peso da localização (0,6), porque podem mostrar rosto, placa ou casa.

## Verificações feitas

- 115 testes automatizados passando, incluindo os 63 originais do Sentinela.
- `ruff check` e `ruff format` sem erros.
- O Security Gate do próprio repositório continua aprovado.
- Auditoria executada nos três alvos, com as evidências em `evidencias/`.
- Painel conferido no navegador, com prints em `evidencias/`.
- IA local testada com o Ollama e o modelo `llama3.2`: os 6 vazamentos do protótipo receberam alerta ao cidadão e correção escritos pela IA (evidências em `evidencias/`).

## Revisão humana

- [x] Ollama instalado e alertas gerados pela IA
- [ ] Cada arquivo do módulo lido e explicado pelo grupo
