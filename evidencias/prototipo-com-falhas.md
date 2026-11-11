<!-- sentinela-report -->
## 🛡️ Sentinela — análise de segurança

⛔ **Security Gate: bloqueado**

🟥 critical: **2** · 🟧 high: **4** · 🟨 medium: **0** · 🟦 low: **0**

### Risco Cidadão: **100/100** (Crítico)

5 vazamentos de dados pessoais e 1 documento real no código, envolvendo CPF ou outros documentos e informações de saúde.

| Dado pessoal | Campos mapeados | Vazamentos |
|---|---:|---:|
| CPF e documentos | 2 | 4 |
| Saúde | 3 | 2 |
| Senhas e credenciais | 1 | 0 |
| Contato e endereço | 1 | 0 |
| Cadastro de pessoa | 1 | 0 |

> **Vulnerabilidade de segurança em dados pessoais** (`prototipo-com-falhas/cadastroMorador.ts:36`, escrito por IA)  
> Seus dados pessoais podem ser acessados por terceiros não autorizados, o que pode causar constrangimento e discriminação.  
> **Quem é afetado:** Cidadãos que utilizam o aplicativo  
> **O que fazer:** A equipe deve corrigir a vulnerabilidade armazenando os dados pessoais com criptografia.

> **Dado pessoal exposto na URL** (`prototipo-com-falhas/cadastroMorador.ts:39`, escrito por IA)  
> Você pode ser vítima de golpe ou fraude, pois seu CPF e telefone estão sendo enviados para o servidor sem segurança.  
> **Quem é afetado:** cidadãos que utilizam o aplicativo  
> **O que fazer:** A equipe deve corrigir a falha removendo o dado pessoal do URL e enviando apenas o CPF em um corpo de requisição HTTPS.

> **Uso de CPFs reais no código** (`prototipo-com-falhas/cadastroMorador.ts:28`, escrito por IA)  
> Você pode ser vítima de golpe ou discriminação se o seu CPF for usado de forma ilegal.  
> **Quem é afetado:** cidadãos que tiverem seus CPFs usados de forma ilegal  
> **O que fazer:** Remova o CPF do código e avise o encarregado de dados (DPO)

**O que bloqueia o merge:**
- `prototipo-com-falhas/cadastroMorador.ts:36` Dado pessoal salvo sem criptografia: Saúde
- `prototipo-com-falhas/cadastroMorador.ts:46` Dado pessoal em notificação: Saúde
- `prototipo-com-falhas/cadastroMorador.ts:32` Dado pessoal escrito no log: CPF e documentos
- `prototipo-com-falhas/cadastroMorador.ts:35` Dado pessoal salvo sem criptografia: CPF e documentos
- `prototipo-com-falhas/cadastroMorador.ts:39` Dado pessoal exposto na URL: CPF e documentos

### Achados

<details><summary>🟥 <b>Dado pessoal salvo sem criptografia: Saúde</b> — <code>prototipo-com-falhas/cadastroMorador.ts:36</code> (CWE-312, confiança high)</summary>

Saúde vindo de `cadastro.condicaoDeSaude` (Saúde) chega a `@react-native-async-storage/async-storage.setItem`: o armazenamento do aparelho ou do servidor, sem criptografia. É um dado pessoal sensível pela LGPD (art. 5º, II).

```typescript
await AsyncStorage.setItem("cadastro:saude", cadastro.condicaoDeSaude);
```

**Caminho do dado:**
1. linha 36 (source): `await AsyncStorage.setItem("cadastro:saude", cadastro.condicaoDeSaude);`
2. linha 36 (sink): `await AsyncStorage.setItem("cadastro:saude", cadastro.condicaoDeSaude);`

**IA (llama3.2):** vulnerabilidade real, confiança high. O dado pessoal de saúde é armazenado sem criptografia, o que pode ser acessado por terceiros não autorizados.

**Como corrigir:** Guarde dados pessoais com criptografia (expo-secure-store, Keychain, Keystore) ou não guarde no aparelho.

```typescript
await SecureStore.setItemAsync('cpf', cpf);
```

<sub>regra `pii.vazamento.armazenamento.saude` · motores: taint · fingerprint `cd2a0ec01af5`</sub>
</details>

<details><summary>🟥 <b>Dado pessoal em notificação: Saúde</b> — <code>prototipo-com-falhas/cadastroMorador.ts:46</code> (CWE-359, confiança high)</summary>

Saúde vindo de `remedios` (Saúde) chega a `expo-notifications.scheduleNotificationAsync`: uma notificação, que aparece na tela bloqueada do celular. É um dado pessoal sensível pela LGPD (art. 5º, II).

```typescript
await Notifications.scheduleNotificationAsync({
```

**Caminho do dado:**
1. linha 47 (source): `content: { title: "Evacuação", body: `Leve seus remédios: ${remedios}` },`
2. linha 46 (sink): `await Notifications.scheduleNotificationAsync({`

**IA (llama3.2):** vulnerabilidade real, confiança high. O dado pessoal de saúde está sendo exibido na tela bloqueada do celular sem a necessidade de login, o que expõe os dados pessoais de cidadãos.

**Como corrigir:** A notificação aparece na tela bloqueada. Mostre só um aviso genérico e o detalhe dentro do app, depois do login.

```typescript
await Notifications.scheduleNotificationAsync({ content: { title: "Você tem um novo aviso" }, trigger: null });
```

<sub>regra `pii.vazamento.notificacao.saude` · motores: taint · fingerprint `4d2f48b403a1`</sub>
</details>

<details><summary>🟧 <b>CPF válido escrito no código</b> — <code>prototipo-com-falhas/cadastroMorador.ts:28</code> (CWE-359, confiança medium)</summary>

O texto contém um CPF com dígitos verificadores corretos (***.***.***-09). Pode ser o documento de uma pessoa real e fica para sempre no histórico do repositório.

```typescript
const CPF_DE_TESTE = "***.***.***-09";
```

**IA (llama3.2):** vulnerabilidade real, confiança high. O CPF escrito no código é um documento real e não um valor fictício, pois é escrito como ***.***.***-09, que é um formato de CPF válido.
Severidade sugerida: `critical` (não aplicada automaticamente).

**Como corrigir:** Use dados fictícios gerados para teste, nunca documentos reais. Se o documento já foi enviado ao repositório, remova do histórico e avise o encarregado de dados (DPO).

```typescript
const CPF_TESTE = gerarCpfFicticio();
```

<sub>regra `pii.valor.cpf` · motores: rule · fingerprint `c14d2e9d0ed4`</sub>
</details>

<details><summary>🟧 <b>Dado pessoal escrito no log: CPF e documentos</b> — <code>prototipo-com-falhas/cadastroMorador.ts:32</code> (CWE-532, confiança high)</summary>

CPF e documentos vindo de `cadastro.cpf` (CPF e documentos) chega a `console.log`: o log do sistema, que costuma ser lido por várias pessoas e enviado a outros serviços.

```typescript
console.log("Novo cadastro", cadastro.cpf, cadastro.senha);
```

**Caminho do dado:**
1. linha 32 (source): `console.log("Novo cadastro", cadastro.cpf, cadastro.senha);`
2. linha 32 (sink): `console.log("Novo cadastro", cadastro.cpf, cadastro.senha);`

**IA (llama3.2):** vulnerabilidade real, confiança high. O código expõe CPF e senha em logs, o que pode ser visto por várias pessoas e enviado a outros serviços.
Severidade sugerida: `critical` (não aplicada automaticamente).

**Como corrigir:** Não escreva dados pessoais em logs. Registre só um identificador técnico ou o dado mascarado.

```typescript
console.log("cadastro concluído", { usuarioId: usuario.id });
```

<sub>regra `pii.vazamento.log.documento` · motores: taint · fingerprint `168606409973`</sub>
</details>

<details><summary>🟧 <b>Dado pessoal salvo sem criptografia: CPF e documentos</b> — <code>prototipo-com-falhas/cadastroMorador.ts:35</code> (CWE-312, confiança high)</summary>

CPF e documentos vindo de `cadastro.cpf` (CPF e documentos) chega a `@react-native-async-storage/async-storage.setItem`: o armazenamento do aparelho ou do servidor, sem criptografia.

```typescript
await AsyncStorage.setItem("cadastro:cpf", cadastro.cpf);
```

**Caminho do dado:**
1. linha 35 (source): `await AsyncStorage.setItem("cadastro:cpf", cadastro.cpf);`
2. linha 35 (sink): `await AsyncStorage.setItem("cadastro:cpf", cadastro.cpf);`

**IA (llama3.2):** vulnerabilidade real, confiança high. O dado pessoal CPF está sendo armazenado sem criptografia, o que pode ser acessado por terceiros
Severidade sugerida: `critical` (não aplicada automaticamente).

**Como corrigir:** Guarde dados pessoais com criptografia (expo-secure-store, Keychain, Keystore) ou não guarde no aparelho.

```typescript
await SecureStore.setItemAsync('cpf', cadastro.cpf);
```

<sub>regra `pii.vazamento.armazenamento.documento` · motores: taint · fingerprint `bd4c4d57bb42`</sub>
</details>

<details><summary>🟧 <b>Dado pessoal exposto na URL: CPF e documentos</b> — <code>prototipo-com-falhas/cadastroMorador.ts:39</code> (CWE-598, confiança high)</summary>

CPF e documentos vindo de `cadastro.cpf` (CPF e documentos) chega a `fetch`: a URL, que fica no histórico, nos logs dos servidores e nos proxies.

```typescript
const resposta = await fetch(`${API}/moradores?cpf=${cadastro.cpf}&telefone=${cadastro.telefone}`);
```

**Caminho do dado:**
1. linha 39 (source): `const resposta = await fetch(`${API}/moradores?cpf=${cadastro.cpf}&telefone=${cadastro.telefone}`);`
2. linha 39 (sink): `const resposta = await fetch(`${API}/moradores?cpf=${cadastro.cpf}&telefone=${cadastro.telefone}`);`

**IA (llama3.2):** vulnerabilidade real, confiança high. O dado pessoal CPF e telefone está sendo enviado na URL, o que pode ser capturado por atacantes e utilizado para realizar ataques de phishing ou outras formas de fraude.
Severidade sugerida: `critical` (não aplicada automaticamente).

**Como corrigir:** Envie dados pessoais no corpo de uma requisição HTTPS (POST), nunca na URL, que fica em histórico, logs e proxies.

```typescript
const resposta = await fetch(`https://api.exemplo.gov.br/cadastro`, { method: 'POST', body: JSON.stringify({ cpf }) });
```

<sub>regra `pii.vazamento.url.documento` · motores: taint · fingerprint `dba19fb9d22b`</sub>
</details>
