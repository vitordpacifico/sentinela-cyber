"""Gera as evidências da Auditoria do Protótipo (Global Solution 2026.2).

Roda o Sentinela em três alvos e grava, para cada um, o relatório em Markdown,
o resultado completo em JSON, o SARIF e a saída do terminal:

* ``prototipo-com-falhas``: protótipo de teste com vazamentos inseridos de propósito;
* ``prototipo-corrigido``: o mesmo protótipo depois das correções;
* ``app-mobile``: o código real do app Pluvia de Mobile (pasta ``src``).

    python scripts/auditoria_gs.py                       # app em ../GS-Mobile
    python scripts/auditoria_gs.py --app C:/caminho/GS-Mobile --ai   # com a IA local (Ollama)
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
from pathlib import Path

from sentinela.cli import main as sentinela

RAIZ = Path(__file__).resolve().parents[1]


def auditar(nome: str, alvo: Path, saida: Path, *, ai: bool, model: str) -> None:
    saida = saida.resolve()
    saida.mkdir(parents=True, exist_ok=True)
    alvo = alvo.resolve()
    argumentos = [
        "scan",
        alvo.name,
        "--project",
        nome,
        "--policy",
        str(RAIZ / "exemplos" / "politica-auditoria.yml"),
        "--markdown",
        str(saida / f"{nome}.md"),
        "--json",
        str(saida / f"{nome}.json"),
        "--sarif",
        str(saida / f"{nome}.sarif"),
        "--no-bandit",
        "--no-fail",
    ]
    if ai:
        argumentos += ["--ai", "--model", model]
    terminal = io.StringIO()
    anterior = Path.cwd()
    os.chdir(alvo.parent)
    try:
        with contextlib.redirect_stdout(terminal):
            sentinela(argumentos)
    finally:
        os.chdir(anterior)
    texto = terminal.getvalue()
    (saida / f"{nome}-terminal.txt").write_text(texto, encoding="utf-8")
    print(f"=== {nome}\n{texto}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app", default=str(RAIZ.parent / "GS-Mobile"), help="pasta do app Pluvia de Mobile")
    parser.add_argument("--saida", default=str(RAIZ / "evidencias"), help="onde gravar as evidências")
    parser.add_argument("--ai", action="store_true", help="usa a IA local (Ollama) para escrever os alertas")
    parser.add_argument("--model", default="llama3.2", help="modelo do Ollama")
    args = parser.parse_args()

    saida = Path(args.saida)
    exemplos = RAIZ / "exemplos"
    auditar("prototipo-com-falhas", exemplos / "prototipo-com-falhas", saida, ai=args.ai, model=args.model)
    auditar("prototipo-corrigido", exemplos / "prototipo-corrigido", saida, ai=args.ai, model=args.model)
    app = Path(args.app) / "src"
    if app.exists():
        auditar("app-mobile", app, saida, ai=args.ai, model=args.model)
    else:
        print(f"App de Mobile não encontrado em {app}; pulando.")


if __name__ == "__main__":
    main()
