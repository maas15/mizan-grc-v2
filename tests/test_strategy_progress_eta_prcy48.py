"""PR-CY48 — strategy task progress %, ETA, and user-facing stage labels."""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import compute_strategy_task_progress  # noqa: E402


def test_ai_provider_call_maps_to_friendly_label_and_eta():
    prog = compute_strategy_task_progress(
        'ai_provider_call',
        substage='anthropic_strategy',
        in_ai_call=True,
        elapsed_s=320,
        idle_s=45,
    )
    assert prog['progress_percent'] is not None
    assert 15 <= prog['progress_percent'] <= 85
    assert prog['eta_seconds'] is not None
    assert prog['eta_seconds'] >= 0
    assert prog['stage_label_en']
    assert prog['stage_label_ar']
    assert 'repair' in prog['stage_label_en'].lower() or 'ai' in prog['stage_label_en'].lower()


def test_late_convergence_stage_has_high_progress():
    prog = compute_strategy_task_progress(
        'ai_provider_call',
        in_ai_call=True,
        elapsed_s=902,
        idle_s=120,
    )
    assert prog['progress_percent'] >= 70
    assert prog['eta_seconds'] is not None
    assert prog['eta_seconds'] < 600


def test_status_api_attaches_progress_fields():
    src_path = os.path.join(ROOT, 'app.py')
    with open(src_path, 'r', encoding='utf-8') as fh:
        src = fh.read()
    assert 'def compute_strategy_task_progress(' in src
    assert '_attach_strategy_progress_fields(' in src
    m = re.search(
        r"def api_strategy_status\(.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert '_attach_strategy_progress_fields(' in body


def test_frontend_poll_updates_progress_from_backend():
  html_path = os.path.join(ROOT, 'templates', 'domain.html')
  with open(html_path, 'r', encoding='utf-8') as fh:
    html = fh.read()
  assert 'function updateStrategyProgressFromPoll(' in html
  assert 'function formatStrategyEta(' in html
  assert 'updateStrategyProgressFromPoll(s)' in html
  assert 'progress_percent' in html
  assert 'eta_seconds' in html
  assert 'stage_label_en' in html or 'stage_label_ar' in html
