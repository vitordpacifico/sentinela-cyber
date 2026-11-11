from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sentinela import services
from sentinela.storage.db import create_all, session_scope
from sentinela.storage.models import Scan

CORPUS = Path(__file__).resolve().parents[1] / "benchmark" / "corpus"
PROJECT = "loja-demo"

TIMELINE = [
    (35, ["python/loja_vulneravel.py", "javascript/api_vulneravel.js", "java/PedidoController.java"]),
    (
        28,
        [
            "python/loja_vulneravel.py",
            "javascript/api_vulneravel.js",
            "java/PedidoController.java",
            "python/falsos_positivos_semanticos.py",
        ],
    ),
    (
        21,
        [
            "python/loja_vulneravel.py",
            "javascript/api_segura.js",
            "java/PedidoController.java",
            "python/falsos_positivos_semanticos.py",
        ],
    ),
    (
        14,
        [
            "python/loja_vulneravel.py",
            "javascript/api_segura.js",
            "java/PedidoSeguro.java",
            "javascript/falsos_positivos_semanticos.js",
        ],
    ),
    (
        7,
        [
            "python/loja_segura.py",
            "javascript/api_segura.js",
            "java/PedidoSeguro.java",
            "java/FalsosPositivosSemanticos.java",
        ],
    ),
    (1, ["python/loja_segura.py", "javascript/api_segura.js", "java/PedidoSeguro.java"]),
]


def main() -> None:
    create_all()
    now = datetime.now(UTC)
    for index, (days_ago, names) in enumerate(TIMELINE):
        files = [(name, (CORPUS / name).read_text(encoding="utf-8")) for name in names]
        with session_scope() as session:
            scan = services.create_scan(
                session,
                project=PROJECT,
                files=files,
                trigger="ci",
                commit_sha=f"{index:x}" * 7 + "demo",
                branch="main",
            )
            scan_id = scan.id
        services.process_inline(scan_id, assistant=None)
        with session_scope() as session:
            session.get(Scan, scan_id).created_at = now - timedelta(days=days_ago)
        print(f"scan {scan_id[:8]}: {len(files)} arquivo(s), {days_ago} dias atrás")
    print(f"Pronto. Abra o dashboard e selecione o projeto '{PROJECT}'.")


if __name__ == "__main__":
    main()
