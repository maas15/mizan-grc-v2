#!/usr/bin/env bash
# Mizan GRC — Cloud Agent dependency bootstrap.
# Idempotent: safe to re-run against a cached/partially-prepared environment.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[install] Python: $(python3 --version)"

# Project + test dependencies (installed into the user site so they persist
# in the environment snapshot without needing a virtualenv). The base image's
# Python is PEP 668 "externally managed", so --break-system-packages is needed
# to install into the user site on this ephemeral dev VM.
PIP_FLAGS=(--user --break-system-packages)
python3 -m pip install "${PIP_FLAGS[@]}" --upgrade pip
python3 -m pip install "${PIP_FLAGS[@]}" -r requirements.txt
python3 -m pip install "${PIP_FLAGS[@]}" pytest

# Ensure a bundled Arabic font is present for bilingual PDF export. The base
# image already ships Noto Arabic faces; this adds the Amiri fallback the
# renderer expects. The script is a no-op when the font already exists.
python3 scripts/ensure_render_fonts.py

echo "[install] done"
