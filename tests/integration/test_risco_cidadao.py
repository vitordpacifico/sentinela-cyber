"""Risco Cidadão pela API: scan com vazamento, painel e relatório."""

from pathlib import Path

PROTOTIPO = Path(__file__).resolve().parents[2] / "exemplos" / "prototipo-com-falhas" / "cadastroMorador.ts"
CORRIGIDO = Path(__file__).resolve().parents[2] / "exemplos" / "prototipo-corrigido" / "cadastroMorador.ts"


def _scan(client, project, arquivo):
    body = {
        "project": project,
        "files": [{"path": "src/cadastroMorador.ts", "content": arquivo.read_text(encoding="utf-8")}],
    }
    return client.post("/api/scans", json=body).json()


def test_prototipo_com_falhas_fica_critico_e_bloqueado(client):
    scan = _scan(client, "sentinela-app", PROTOTIPO)
    risco = client.get(f"/api/scans/{scan['id']}/risco-cidadao").json()
    assert risco["nivel"] == "critico"
    assert risco["vazamentos"] >= 4
    assert client.get(f"/api/scans/{scan['id']}/gate").json()["status"] == "failed"

    achados = client.get(f"/api/scans/{scan['id']}/findings").json()
    vazamento = next(f for f in achados if f["rule_id"].startswith("pii.vazamento"))
    assert vazamento["alerta_cidadao"]["origem"] == "regras"
    assert "Risco Cidadão" in client.get(f"/api/scans/{scan['id']}/report.md").text


def test_painel_mostra_a_queda_do_risco_depois_da_correcao(client):
    _scan(client, "sentinela-app", PROTOTIPO)
    _scan(client, "sentinela-app", CORRIGIDO)
    metricas = client.get("/api/projects/sentinela-app/metrics").json()
    assert metricas["risco_cidadao"]["nivel"] == "baixo"
    assert metricas["risco_cidadao"]["vazamentos"] == 0


def test_risco_da_cli_respeita_a_politica(tmp_path):
    import json

    from sentinela.cli import main

    pasta = tmp_path / "app"
    pasta.mkdir()
    (pasta / "cadastro.ts").write_text("export function f(cpf: string) { console.log(cpf); }\n", encoding="utf-8")
    politica = tmp_path / "politica.yml"
    politica.write_text('gate:\n  ignore_paths: ["*cadastro.ts"]\n', encoding="utf-8")
    saida = tmp_path / "r.json"

    main(["scan", str(pasta), "--json", str(saida), "--no-bandit", "--quiet", "--no-fail"])
    assert json.loads(saida.read_text(encoding="utf-8"))["risco_cidadao"]["indice"] >= 50

    main(["scan", str(pasta), "--policy", str(politica), "--json", str(saida), "--no-bandit", "--quiet", "--no-fail"])
    assert json.loads(saida.read_text(encoding="utf-8"))["risco_cidadao"]["indice"] == 0
