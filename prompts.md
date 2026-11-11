# Uso de IA

As regras gerais da Global Solution pedem o registro dos prompts usados (página 21 do PDF da GS).

**Ferramenta:** Claude Code (modelo Claude Opus 5.5).

Os pedidos abaixo foram reescritos em linguagem formal, mantendo o conteúdo de cada um.

## Prompts

### 1. Entender a missão de Cybersecurity (05/11/2026)

**Pedido:** Explicar, com base no PDF da GS, o que a disciplina pede e se os checkpoints anteriores do professor fazem parte da entrega.

**Resultado:** Leitura das páginas 28 e 29, que são imagens no PDF. A IA deixou claro o que o PDF exige e o que é dedução, e propôs usar o Sentinela do grupo como base.

### 2. Usar o Sentinela como base (06/11/2026)

**Pedido:** Fazer o fork do repositório do Sentinela, criado pelo Gustavo no Projeto Integrador, e usá-lo como base da entrega.

**Resultado:** Fork em `vitordpacifico/sentinela-cyber`, ambiente instalado e testes originais rodados (63 passando, depois de corrigir um teste que quebrava com a versão nova da biblioteca Celery).

### 3. Implementar o módulo de dados pessoais (06/11/2026)

**Pedido:** Implementar as quatro partes da missão: mapeamento de PII, taint analysis, alerta ao cidadão escrito pela IA e o indicador Risco Cidadão no painel.

**Resultado:**

- Suporte a TypeScript no motor de parsing.
- Módulo `sentinela/pii/` com as categorias de dados pessoais, a detecção de CPF e Cartão SUS válidos, a taint analysis até saídas inseguras e o mascaramento antes da IA.
- Alerta ao cidadão no prompt da IA, com coluna nova no banco e migração.
- Indicador Risco Cidadão na API, na CLI, no relatório Markdown e no painel.
- Protótipo com falhas inseridas de propósito e versão corrigida, para a auditoria.
- Scripts da auditoria, da demonstração no painel e do ZIP de entrega.
- 45 testes novos (108 no total).

### 4. Fechar a entrega (06/11/2026)

**Pedido:** Deixar o código de Cyber e de Mobile completos para a validação, antes dos prints e do vídeo.

**Resultado:** O problema que a auditoria apontou no app (telefone e CEP sem criptografia) foi corrigido no repositório de Mobile. A auditoria e os prints do painel foram refeitos, o roteiro do vídeo foi reduzido para 3 minutos e o script da demonstração passou a poder rodar de novo sem duplicar scans.

### 5. Acompanhar a mudança do app para o Pluvia (07/11/2026)

**Pedido:** Adaptar a entrega ao documento de definição do grupo, que troca o app de Mobile pelo Pluvia (proposta "Alaga") e pede, em Cyber, o mapeamento de dados pessoais em fotos e localização.

**Resultado:** Categoria nova "Fotos e imagens" no mapeamento de PII, termo "coordenada" na localização, auditoria refeita no código do Pluvia (aprovado, Risco Cidadão 6, 140 campos mapeados), prints do painel refeitos e documentação atualizada. 3 testes novos (111 no total).

### 6. Testar a IA de verdade (11/11/2026)

**Pedido:** Instalar o Ollama e testar a IA do módulo.

**Resultado:** Ollama e `llama3.2` instalados. O teste mostrou que nenhuma resposta da IA era aproveitada: o modelo levava mais que o limite de 60 segundos, a resposta era cortada e o alerta ficava fora do formato pedido, e a IA era chamada também para os achados de mapeamento. Correções: limite de 180 segundos, resposta mais longa, alerta dentro do formato JSON, correção recomendada da regra enviada como referência, uma segunda tentativa quando a resposta vem incompleta e mapeamento fora da IA. Modelo padrão trocado para `llama3.2`. Evidências e prints do painel refeitos com a IA. 3 testes novos (114 no total).

## Decisões sugeridas pela IA, para o grupo revisar

- Usar o Sentinela do grupo como base, porque o PDF fala em "novas regras no motor de parsing", "o LLM" e "Dashboard Atualizado".
- Reconhecer dado pessoal pelo nome do campo, mais CPF e Cartão SUS pelo valor.
- Pesos das categorias e das saídas, e a fórmula do Risco Cidadão (`docs/risco-cidadao.md`).
- Gravidade do vazamento definida pela categoria do dado: saúde é crítica; CPF e senha são altos.
- Protótipo de auditoria com CPF e saúde, já que o app de Mobile entregue não coleta esses dados.
- Fotos com o mesmo peso da localização (0,6), porque podem mostrar rosto, placa ou casa.

## Verificações feitas

- 114 testes automatizados passando, incluindo os 63 originais do Sentinela.
- `ruff check` e `ruff format` sem erros.
- O Security Gate do próprio repositório continua aprovado.
- Auditoria executada nos três alvos, com as evidências em `evidencias/`.
- Painel conferido no navegador, com prints em `evidencias/`.

- IA local testada com o Ollama e o modelo `llama3.2`: os 6 vazamentos do protótipo receberam alerta ao cidadão e correção escritos pela IA (evidências em `evidencias/`).

## Revisão humana

- [x] Ollama instalado e alertas gerados pela IA
- [ ] Cada arquivo do módulo lido e explicado pelo grupo
