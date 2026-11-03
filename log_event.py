#!/usr/bin/env python3
"""Ponto de entrada do hook (use o caminho absoluto deste arquivo no settings.json)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentwatch.hook import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
