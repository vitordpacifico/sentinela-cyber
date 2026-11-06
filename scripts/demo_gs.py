"""Prepara o dashboard para a demonstração da Global Solution 2026.2.

Cria dois projetos:

* ``prototipo-com-falhas``: um scan do protótipo com vazamentos de dados
  pessoais. O painel mostra o Risco Cidadão crítico e os alertas ao cidadão.
* ``sentinela-app``: três scans, como se o pipeline tivesse rodado ao longo de
  uma semana: o protótipo com falhas (há 6 dias), o protótipo corrigido (há 3
  dias) e o código real do app SENTINELA de Mobile (hoje). A tendência mostra a
  queda das falhas, e o Risco Cidadão fica baixo.

    python scripts/demo_gs.py                 # IA desligada: alertas escritos por regras
    python scripts/demo_gs.py --ai            # IA local (Ollama) escreve os alertas
    sentinela serve                           # depois abra http://localhost:8000
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinela import services
from sentinela.ai.assistant import OllamaAssistant
from sentinela.storage.db import create_all, session_scope
from sentinela.storage.models import Scan

RAIZ = Path(__file__).resolve().parents[1]
PROJETO = "sentinela-app"
EXTENSOES = {".ts", ".tsx", ".js", ".jsx", ".py", ".java"}


def arquivos(pasta: Path, prefixo: str = "") -> list[tuple[str, str]]:
    return [
        (f"{prefixo}{caminho.relative_to(pasta).as_posix()}", caminho.read_text(encoding="utf-8"))
        for caminho in sorted(pasta.rglob("*"))
        if caminho.suffix in EXTENSOES and "node_modules" not in caminho.parts and "__tests__" not in caminho.parts
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app", default=str(RAIZ.parent / "GS-Mobile"), help="pasta do app SENTINELA de Mobile")
    parser.add_argument("--ai", action="store_true", help="usa a IA local (Ollama) nos achados")
    parser.add_argument("--model", default="llama3.2")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    args = parser.parse_args()

    assistente = None
    if args.ai:
        assistente = OllamaAssistant(base_url=args.ollama_url, model=args.model)
        if not assistente.health():
            print("Ollama indisponível; seguindo sem IA (alertas escritos por regras).")
            assistente = None

    exemplos = RAIZ / "exemplos"
    com_falhas = arquivos(exemplos / "prototipo-com-falhas", "src/servicos/")
    linha_do_tempo = [
        ("prototipo-com-falhas", 0, "prototipo-com-falhas", com_falhas),
        (PROJETO, 6, "prototipo-com-falhas", com_falhas),
        (PROJETO, 3, "prototipo-corrigido", arquivos(exemplos / "prototipo-corrigido", "src/servicos/")),
    ]
    app = Path(args.app) / "src"
    if app.exists():
        linha_do_tempo.append((PROJETO, 0, "app-mobile", arquivos(app, "src/")))

    create_all()
    agora = datetime.now(UTC)
    for indice, (projeto, dias, rotulo, lista) in enumerate(linha_do_tempo):
        with session_scope() as session:
            scan = services.create_scan(
                session,
                project=projeto,
                files=lista,
                trigger="ci",
                commit_sha=f"{indice + 1:x}" * 7 + "gs",
                branch="main",
            )
            scan_id = scan.id
        services.process_inline(scan_id, assistant=assistente)
        with session_scope() as session:
            session.get(Scan, scan_id).created_at = agora - timedelta(days=dias)
        print(f"{projeto} / {rotulo}: {len(lista)} arquivo(s), scan {scan_id[:8]}")
    print("Pronto. Rode 'sentinela serve' e abra http://localhost:8000.")


if __name__ == "__main__":
    main()
