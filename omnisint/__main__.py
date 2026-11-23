"""Module entrypoint allowing `python3 -m omnisint` execution without runpy warnings."""

from __future__ import annotations

from omnisint.cli.main import app

if __name__ == "__main__":
    app()
