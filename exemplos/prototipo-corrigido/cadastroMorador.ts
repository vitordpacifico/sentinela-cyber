/**
 * PROTÓTIPO CORRIGIDO: a mesma funcionalidade de exemplos/prototipo-com-falhas,
 * sem os vazamentos de dados pessoais.
 *
 * Correções:
 * 1. Sem documento real no código: o teste gera um CPF fictício na hora.
 * 2. O log registra só que o cadastro aconteceu, sem dado pessoal.
 * 3. CPF e saúde vão para o armazenamento criptografado (expo-secure-store).
 * 4. Os dados vão no corpo de uma requisição HTTPS (POST), não na URL.
 * 5. A notificação é genérica; o detalhe aparece dentro do app, depois do login.
 */
import * as Notifications from "expo-notifications";
import * as SecureStore from "expo-secure-store";

export interface CadastroMorador {
  nome: string;
  cpf: string;
  telefone: string;
  condicaoDeSaude: string;
  medicamentos: string[];
  senha: string;
}

const API = "https://api.sentinela.exemplo";

export async function salvarCadastro(cadastro: CadastroMorador) {
  console.info("Novo cadastro recebido");

  await SecureStore.setItemAsync("cadastro:cpf", cadastro.cpf);
  await SecureStore.setItemAsync("cadastro:saude", cadastro.condicaoDeSaude);

  const resposta = await fetch(`${API}/moradores`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cpf: cadastro.cpf, telefone: cadastro.telefone }),
  });
  return resposta.json();
}

export async function avisarEvacuacao() {
  await Notifications.scheduleNotificationAsync({
    content: { title: "Evacuação", body: "Abra o app para ver as orientações para você." },
    trigger: null,
  });
}
