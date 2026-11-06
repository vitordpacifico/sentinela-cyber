"""Monta o ZIP de entrega da Global Solution (Cybersecurity) para enviar no Teams.

O ZIP leva o código atualizado do Sentinela com o módulo de dados pessoais,
as evidências da auditoria (relatórios e prints do painel) e a documentação.
Ficam de fora o ambiente virtual, caches e bancos locais.

    python scripts/gerar_zip_entrega.py
    python scripts/gerar_zip_entrega.py --video caminho/do/video.mp4
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
IGNORAR_PASTAS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "entrega", "node_modules"}
IGNORAR_SUFIXOS = {".pyc", ".db", ".egg-info"}


def arquivos_do_projeto() -> list[Path]:
    return [
        caminho
        for caminho in sorted(RAIZ.rglob("*"))
        if caminho.is_file()
        and not (set(caminho.relative_to(RAIZ).parts) & IGNORAR_PASTAS)
        and not any(parte.endswith(".egg-info") for parte in caminho.relative_to(RAIZ).parts)
        and caminho.suffix not in IGNORAR_SUFIXOS
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--video", help="vídeo da demonstração, incluído na pasta video/ do ZIP")
    parser.add_argument("--saida", default=str(RAIZ / "entrega" / "GS-Cybersecurity-SENTINELA.zip"))
    args = parser.parse_args()

    destino = Path(args.saida)
    destino.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destino, "w", compression=zipfile.ZIP_DEFLATED) as pacote:
        for caminho in arquivos_do_projeto():
            pacote.write(caminho, f"sentinela-cyber/{caminho.relative_to(RAIZ).as_posix()}")
        if args.video:
            video = Path(args.video)
            pacote.write(video, f"video/{video.name}")
    tamanho = destino.stat().st_size / 1_000_000
    print(f"ZIP gerado: {destino} ({tamanho:.1f} MB)")


if __name__ == "__main__":
    main()
