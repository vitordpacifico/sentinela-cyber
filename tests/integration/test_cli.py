import json

from sentinela.cli import main


def test_cli_blocks_and_writes_reports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text(
        "from flask import request\ndef v(c):\n    c.execute('SELECT ' + request.args['q'])\n"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("eval(a)")
    code = main(["scan", ".", "--sarif", "out.sarif", "--markdown", "out.md", "--json", "out.json", "--quiet"])
    assert code == 1
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["gate"]["status"] == "failed"
    assert [f["file_path"] for f in data["findings"]] == ["app.py"]
    assert json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "bloqueado" in (tmp_path / "out.md").read_text(encoding="utf-8")


def test_cli_policy_and_no_fail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
    (tmp_path / ".sentinela.yml").write_text("gate:\n  fail_on: critical\n")
    assert main(["scan", ".", "--quiet", "--no-bandit"]) == 0
    (tmp_path / ".sentinela.yml").write_text("gate:\n  fail_on: high\n  require_strong_evidence: false\n")
    assert main(["scan", ".", "--quiet", "--no-bandit"]) == 1
    assert main(["scan", ".", "--quiet", "--no-bandit", "--no-fail"]) == 0


def test_cli_dados_mapeados_ignoram_caminhos_da_politica(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    codigo = "def salvar(email, telefone):\n    return {'email': email, 'telefone': telefone}\n"
    (tmp_path / "app.py").write_text(codigo)
    (tmp_path / "__tests__").mkdir()
    (tmp_path / "__tests__" / "fixtura.py").write_text(codigo)
    (tmp_path / ".sentinela.yml").write_text('gate:\n  ignore_paths:\n    - "__tests__/*"\n')
    assert main(["scan", ".", "--no-bandit", "--json", "out.json"]) == 0
    saida = capsys.readouterr().out
    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    no_app = sum(1 for f in data["findings"] if f["file_path"] == "app.py" and f["rule_id"].startswith("pii.mapa."))
    nos_testes = sum(1 for f in data["findings"] if f["file_path"].startswith("__tests__/"))
    assert no_app > 0 and nos_testes == no_app
    assert data["risco_cidadao"]["dados_mapeados"] == no_app
    assert f"Dados pessoais mapeados: {no_app} campo(s)" in saida
    assert f"{nos_testes} campo(s) em caminhos ignorados" in saida


def test_cli_nothing_to_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "notes.txt").write_text("nada")
    assert main(["scan", "."]) == 0
