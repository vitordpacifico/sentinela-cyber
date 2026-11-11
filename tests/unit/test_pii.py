import pytest

from sentinela.ai.assistant import build_prompt, parse_assessment
from sentinela.engine.languages import detect_language, get_adapter
from sentinela.engine.models import Severity
from sentinela.engine.scanner import ScanOptions, scan_source
from sentinela.gate import GatePolicy, evaluate
from sentinela.pii.alerta import alerta_padrao, categoria_do_achado
from sentinela.pii.categorias import classificar_nome, palavras
from sentinela.pii.risco import calcular_risco_cidadao, faixa, risco_do_achado
from sentinela.pii.valores import cns_valido, cpf_valido, encontrar_cpfs, mascarar_dados_pessoais

OPTS = ScanOptions(use_bandit=False)


def ids(findings, prefixo="pii."):
    return sorted(f.rule_id for f in findings if f.rule_id.startswith(prefixo))


@pytest.mark.parametrize(
    ("nome", "categoria"),
    [
        ("cpf", "documento"),
        ("usuario.cpfDoMorador", "documento"),
        ("data_nascimento", "identificacao"),
        ("condicaoDeSaude", "saude"),
        ("diagnosticoCID", "saude"),
        ("cartaoSus", "saude"),
        ("senhaDigitada", "credencial"),
        ("user.password", "credencial"),
        ("telefoneCelular", "contato"),
        ("usuario.id", "registro"),
        ("raca", "sensivel"),
        ("relato.fotoUri", "imagem"),
        ("selfieDoUsuario", "imagem"),
        ("carro.latitude", "localizacao"),
    ],
)
def test_classifica_dado_pessoal_pelo_nome(nome, categoria):
    assert classificar_nome(nome).id == categoria


@pytest.mark.parametrize(
    "nome", ["senhaHash", "usuario.senhaHash", "cpfMascarado", "cpfValido", "emailInput", "ponto.nome", "total"]
)
def test_ignora_dado_protegido_ou_que_nao_e_pessoal(nome):
    assert classificar_nome(nome) is None


def test_quebra_nomes_em_palavras():
    assert palavras("cpfDoMorador") == ["cpf", "do", "morador"]
    assert palavras("data_nascimento") == ["data", "nascimento"]
    assert palavras("condiçãoDeSaúde") == ["condicao", "de", "saude"]


def test_cpf_com_digitos_verificadores():
    assert cpf_valido("123.456.789-09")
    assert cpf_valido("12345678909")
    assert not cpf_valido("123.456.789-00")
    assert not cpf_valido("111.111.111-11")
    assert encontrar_cpfs("pedido 1234 do cpf 123.456.789-09 ok") == ["123.456.789-09"]


def test_cartao_sus_valido():
    assert cns_valido("700000000000005")
    assert not cns_valido("700000000000006")
    assert not cns_valido("300000000000003")


def test_mascara_dados_pessoais_em_texto():
    texto = "cpf 123.456.789-09, email ana.souza@exemplo.com, tel (11) 98765-4321"
    mascarado = mascarar_dados_pessoais(texto)
    assert "123.456" not in mascarado and "***.***.***-09" in mascarado
    assert "ana.souza" not in mascarado and "a***@exemplo.com" in mascarado
    assert "98765" not in mascarado and "4321" in mascarado


def test_typescript_e_detectado_e_usa_regras_do_javascript():
    assert detect_language("src/app.tsx") == "typescript"
    adapter = get_adapter("typescript")
    assert adapter.rules_language == "javascript"
    root = adapter.parse("function f(cpf: string, opcoes?: { a: number }) {}").root_node
    params = adapter.function_params(next(adapter.functions(root)))
    assert [p.name for p in params] == ["cpf", "opcoes"]


def test_taint_de_injecao_atravessa_tipos_do_typescript():
    codigo = 'import { exec } from "child_process";\nfunction f(req: any) { exec(req.query.cmd as string); }\n'
    assert "javascript.taint.command-injection" in [f.rule_id for f in scan_source("a.ts", codigo, "typescript", OPTS)]


TS_VAZAMENTOS = """
import AsyncStorage from "@react-native-async-storage/async-storage";
import * as Notifications from "expo-notifications";
export async function salvar(paciente: Paciente) {
  console.log("cadastro", paciente.cpf);
  const cpfLimpo = paciente.cpf.replace(/\\D/g, "");
  await AsyncStorage.setItem("cpf", cpfLimpo);
  await fetch(`https://api.exemplo/pacientes?cpf=${cpfLimpo}`);
  const remedios = paciente.medicamentos.join(", ");
  await Notifications.scheduleNotificationAsync({ content: { body: remedios }, trigger: null });
}
"""


def test_rastreia_dado_pessoal_ate_saidas_inseguras_em_typescript():
    findings = scan_source("salvar.ts", TS_VAZAMENTOS, "typescript", OPTS)
    assert ids(findings, "pii.vazamento") == [
        "pii.vazamento.armazenamento.documento",
        "pii.vazamento.log.documento",
        "pii.vazamento.notificacao.saude",
        "pii.vazamento.url.documento",
    ]
    saude = next(f for f in findings if f.rule_id == "pii.vazamento.notificacao.saude")
    assert saude.severity is Severity.CRITICAL
    assert [s.kind for s in saude.taint_path][0] == "source"
    assert "LGPD" in saude.message


def test_mascarar_criptografar_e_hash_interrompem_o_fluxo():
    codigo = """
import * as SecureStore from "expo-secure-store";
export async function salvar(usuario: Usuario) {
  console.log("cpf", mascararCpf(usuario.cpf));
  console.log("hash", usuario.senhaHash);
  await SecureStore.setItemAsync("cpf", usuario.cpf);
  await fetch("https://api.exemplo/cadastro", { method: "POST", body: JSON.stringify({ cpf: usuario.cpf }) });
}
"""
    assert ids(scan_source("seguro.ts", codigo, "typescript", OPTS), "pii.vazamento") == []


def test_fluxo_de_pii_em_python_e_java():
    python = 'import logging, requests\ndef f(cpf, telefone):\n    logging.info("cpf=%s", cpf)\n    requests.get(f"https://x/?t={telefone}")\n'
    assert ids(scan_source("a.py", python, "python", OPTS), "pii.vazamento") == [
        "pii.vazamento.log.documento",
        "pii.vazamento.url.contato",
    ]
    java = "class A { void f(String senha) { System.out.println(senha); } }"
    assert ids(scan_source("A.java", java, "java", OPTS), "pii.vazamento") == ["pii.vazamento.log.credencial"]


def test_mapeia_campos_com_dado_pessoal_sem_bloquear():
    codigo = "interface Morador { nome: string; cpf: string; diagnostico: string; email: string }\n"
    findings = scan_source("tipos.ts", codigo, "typescript", OPTS)
    assert ids(findings, "pii.mapa") == ["pii.mapa.contato", "pii.mapa.documento", "pii.mapa.saude"]
    assert all(f.severity is Severity.INFO for f in findings)


def test_cpf_real_no_codigo_vira_achado_mascarado():
    (achado,) = [
        f
        for f in scan_source("seed.ts", 'const CPF = "123.456.789-09";\n', "typescript", OPTS)
        if f.rule_id == "pii.valor.cpf"
    ]
    assert "123.456" not in achado.snippet + achado.message + achado.context


def test_modulo_pode_ser_desligado():
    assert (
        ids(scan_source("salvar.ts", TS_VAZAMENTOS, "typescript", ScanOptions(use_bandit=False, dados_pessoais=False)))
        == []
    )


def test_security_gate_bloqueia_vazamento_de_cpf_e_so_avisa_de_email():
    cpf = scan_source("a.ts", "function f(u: U) { console.log(u.cpf); }\n", "typescript", OPTS)
    assert evaluate(cpf, GatePolicy()).status == "failed"
    email = scan_source("b.ts", "function f(u: U) { console.log(u.email); }\n", "typescript", OPTS)
    assert evaluate(email, GatePolicy()).status != "failed"


def test_risco_por_categoria_e_saida():
    assert risco_do_achado("pii.vazamento.url.saude") == 1.0
    assert risco_do_achado("pii.vazamento.log.contato") == 0.35
    assert risco_do_achado("pii.mapa.saude") == 0.0


def test_indice_combina_vazamentos_e_mapeamento():
    so_mapa = calcular_risco_cidadao([{"rule_id": "pii.mapa.saude"}, {"rule_id": "pii.mapa.contato"}])
    assert so_mapa["indice"] == 3 and so_mapa["nivel"] == "baixo"

    um_email = calcular_risco_cidadao([{"rule_id": "pii.vazamento.log.contato"}])
    assert um_email["indice"] == 35 and um_email["nivel"] == "moderado"

    grave = calcular_risco_cidadao([{"rule_id": "pii.vazamento.url.saude"}])
    assert grave["indice"] == 100 and grave["nivel"] == "critico"
    assert grave["alertas"][0]["alerta_cidadao"]["origem"] == "regras"


def test_achados_fechados_saem_do_indice():
    achados = [{"rule_id": "pii.vazamento.url.saude", "status": "false_positive"}]
    assert calcular_risco_cidadao(achados)["indice"] == 0


@pytest.mark.parametrize(
    ("indice", "nivel"), [(0, "baixo"), (19, "baixo"), (20, "moderado"), (50, "alto"), (80, "critico")]
)
def test_faixas_do_indice(indice, nivel):
    assert faixa(indice)[0] == nivel


def test_alerta_padrao_em_linguagem_simples():
    alerta = alerta_padrao("pii.vazamento.notificacao.saude")
    assert "tela bloqueada" in alerta["o_que_pode_acontecer"]
    assert alerta["gravidade"] == "crítica"
    assert alerta_padrao("pii.mapa.saude") is None
    assert categoria_do_achado("pii.valor.cns").id == "saude"


def test_prompt_pede_alerta_ao_cidadao_so_para_dado_pessoal():
    findings = scan_source("salvar.ts", TS_VAZAMENTOS, "typescript", OPTS)
    pii = next(f for f in findings if f.rule_id.startswith("pii.vazamento"))
    assert "alerta_cidadao" in build_prompt(pii)
    injecao = scan_source(
        "a.ts",
        'import { exec } from "child_process";\nfunction f(req: any) { exec(req.query.c); }\n',
        "typescript",
        OPTS,
    )
    assert "alerta_cidadao" not in build_prompt(next(f for f in injecao if f.rule_id.startswith("javascript.taint")))


def test_le_o_alerta_escrito_pela_ia():
    corpo = {
        "verdict": "true_positive",
        "confidence": "high",
        "rationale": "linha 4 grava o CPF",
        "alerta_cidadao": {
            "titulo": "Seu CPF pode vazar",
            "o_que_pode_acontecer": "Golpistas podem usar o CPF.",
            "quem_e_afetado": "Moradores cadastrados.",
            "o_que_fazer": "Parar de gravar o CPF no log.",
        },
    }
    assert (
        parse_assessment(corpo, model="llama3.2", current=Severity.HIGH).alerta_cidadao["titulo"]
        == "Seu CPF pode vazar"
    )
    corpo["alerta_cidadao"]["o_que_fazer"] = ""
    assert parse_assessment(corpo, model="llama3.2", current=Severity.HIGH).alerta_cidadao is None
