"""Plesk / Phusion Passenger entry point.

Passenger's Python support is WSGI-only, so we bridge FastAPI (ASGI) to WSGI
via ``a2wsgi``. Passenger auto-detects this file when it sits in the document
root (``httpdocs/``) and looks for a WSGI callable named ``application``.

If a ``venv/`` directory exists next to this file, we re-exec under that
interpreter so Passenger picks up the venv's installed packages (recommended on
Plesk, which otherwise runs the system Python).
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Prefer a local virtualenv (Linux/macOS path; Plesk is Linux).
_venv_py = os.path.join(BASE_DIR, "venv", "bin", "python")
if os.name == "nt":
    _venv_py = os.path.join(BASE_DIR, "venv", "Scripts", "python.exe")

if os.path.exists(_venv_py) and sys.executable != _venv_py:
    os.execl(_venv_py, _venv_py, *sys.argv)

sys.path.insert(0, BASE_DIR)

from a2wsgi import ASGIMiddleware  # noqa: E402
from app.main import app  # noqa: E402

application = ASGIMiddleware(app)
