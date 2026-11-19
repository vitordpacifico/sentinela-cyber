# Uso de IA

As regras gerais da Global Solution permitem a IA como copiloto, desde que os prompts fiquem registrados (página 21 do PDF da GS).

**Ferramenta:** Claude Code (modelo Claude Opus 5.5).

## Como usamos a IA

A base é o Sentinela, ferramenta de SAST que o grupo criou no Projeto Integrador. As missões vieram do PDF, e o desenho do módulo (as categorias de dado pessoal, as saídas inseguras, os pesos e a fórmula do Risco Cidadão) foi decidido pelo grupo. Usamos a IA como copiloto para tirar dúvidas de Tree-sitter e de taint analysis, revisar o que já tínhamos escrito e investigar erros. Toda sugestão foi conferida rodando a auditoria e o painel.

Abaixo estão os prompts mais importantes, em ordem. O texto foi revisado para ficar claro, sem mudar o que foi pedido.

## Prompts

### 1. Ler a missão no PDF (05/11/2026)

> As páginas 28 e 29 do PDF da GS estão em imagem. Confira com a gente o que a disciplina de Cybersecurity pede: as três missões, o que vai no ZIP e a pontuação. Pensamos em usar o Sentinela do Projeto Integrador como base, porque a missão fala em "novas regras no motor de parsing". Faz sentido ou o professor espera uma ferramenta nova?

**Resultado:** Confirmamos as missões e a pontuação, e decidimos seguir com o Sentinela, que já tinha motor de parsing, LLM e painel.

### 2. Reconhecer dado pessoal pelo nome (06/11/2026)

> Montamos uma lista de categorias de dado pessoal (saúde, documentos, senhas, localização, contato) e queremos reconhecê-las pelo nome de campos e variáveis. O problema: `senhaHash` e `cpfMascarado` não deveriam contar, e nomes em camelCase e snake_case precisam funcionar. Como separar as palavras do nome e evitar esses falsos positivos?

**Resultado:** Escrevemos a separação de palavras e a lista de nomes protegidos em `sentinela/pii/categorias.py`, com testes para cada caso.

### 3. CPF e Cartão SUS verdadeiros no código (06/11/2026)

> Queremos acusar CPF e Cartão SUS escritos no código, mas só os verdadeiros, para não marcar qualquer sequência de números. Revise a nossa conta do dígito verificador do CPF e explique como funciona a validação do Cartão Nacional de Saúde.

**Resultado:** Validação de CPF e CNS em `sentinela/pii/valores.py`, também usada para mascarar esses números antes de o código ir para a IA.

### 4. Taint até saídas inseguras (06/11/2026)

> O Sentinela já segue entrada externa até funções perigosas. Queremos usar o mesmo motor para seguir o dado pessoal até log, URL, armazenamento sem criptografia e notificação, tratando mascaramento e hash como limpeza. Como encaixar isso no motor de taint que já existe sem quebrar as regras antigas?

**Resultado:** Criamos as regras de vazamento em `sentinela/rules/pii.yml` e o fluxo em `sentinela/pii/fluxo.py`. Os 63 testes originais continuaram passando.

### 5. Alerta ao cidadão pela IA (06/11/2026)

> A IA do Sentinela já avalia cada achado. Para os vazamentos de dado pessoal, queremos que ela escreva um alerta em linguagem simples para o cidadão (o que pode acontecer, quem é afetado e o que fazer). Como mudar o prompt para a resposta vir sempre nesse formato, e como garantir que o CPF não chegue aberto à IA?

**Resultado:** Prompt com o formato do alerta ao cidadão, mascaramento de CPF, Cartão SUS, e-mail e telefone antes da IA, e um alerta escrito por regras quando a IA está desligada.

### 6. A IA não respondia a tempo (11/11/2026)

> Instalamos o Ollama com o `llama3.2` e rodamos a auditoria, mas os alertas continuam vindo do texto de reserva, não da IA. Ajude a investigar o que acontece com a resposta.

**Resultado:** Descobrimos que o modelo, rodando no processador, levava mais de 60 segundos, a resposta vinha cortada e a IA também era chamada para os achados de mapeamento. Aumentamos o limite para 180 segundos, deixamos a resposta mais longa e tiramos o mapeamento da IA. Os 6 vazamentos do protótipo passaram a ter alerta e correção escritos pela IA.

### 7. Números diferentes na auditoria e no painel (15/11/2026)

> Na revisão final, a auditoria do app mostra 142 campos com dado pessoal e o painel mostra 103. Revise com a gente de onde vem essa diferença.

**Resultado:** A auditoria contava os arquivos de teste do app, que só têm dados fictícios. Passamos a ignorá-los nos dois lugares, e agora os números batem.

## Decisões do projeto

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
