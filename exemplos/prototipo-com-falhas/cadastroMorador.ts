/**
 * PROTÓTIPO DE TESTE COM FALHAS INSERIDAS DE PROPÓSITO. NÃO É O APP ENTREGUE.
 *
 * Simula uma versão do cadastro do app SENTINELA que pediria CPF e condição de
 * saúde, para a Defesa Civil priorizar a evacuação de quem tem mobilidade
 * reduzida. Cada falha abaixo é um erro comum em apps reais e serve para mostrar
 * a taint analysis de dados pessoais em ação. A versão corrigida está em
 * exemplos/prototipo-corrigido.
 *
 * O CPF de teste (123.456.789-09) é o exemplo clássico de CPF válido usado em
 * documentação. Nenhum dado aqui pertence a uma pessoa real.
 */
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as Notifications from "expo-notifications";

export interface CadastroMorador {
  nome: string;
  cpf: string;
  telefone: string;
  condicaoDeSaude: string;
  medicamentos: string[];
  senha: string;
}

const API = "http://api.sentinela.exemplo";

// FALHA 1: documento com dígitos verificadores válidos escrito no código.
const CPF_DE_TESTE = "123.456.789-09";

export async function salvarCadastro(cadastro: CadastroMorador) {
  // FALHA 2: CPF e senha no log.
  console.log("Novo cadastro", cadastro.cpf, cadastro.senha);

  // FALHA 3: CPF e condição de saúde gravados sem criptografia no celular.
  await AsyncStorage.setItem("cadastro:cpf", cadastro.cpf);
  await AsyncStorage.setItem("cadastro:saude", cadastro.condicaoDeSaude);

  // FALHA 4: CPF e telefone na URL, que fica em logs de servidores e proxies.
  const resposta = await fetch(`${API}/moradores?cpf=${cadastro.cpf}&telefone=${cadastro.telefone}`);
  return resposta.json();
}

export async function avisarEvacuacao(cadastro: CadastroMorador) {
  // FALHA 5: medicamentos (dado de saúde) na notificação, visível na tela bloqueada.
  const remedios = cadastro.medicamentos.join(", ");
  await Notifications.scheduleNotificationAsync({
    content: { title: "Evacuação", body: `Leve seus remédios: ${remedios}` },
    trigger: null,
  });
}

export function cpfParaTeste(): string {
  return CPF_DE_TESTE;
}
