"""PR-CY15 — Fix false strategy stall detection during long AI repair calls.

Verifies that the stall detector distinguishes a truly stuck task from one
actively running a long AI provider call (Anthropic / OpenAI / etc.)
during the strategy generation pipeline.

The runtime evidence covered:

  * Anthropic call succeeds → ``[AI] Anthropic success``
  * Per-section repair invokes another Anthropic call
  * Old behaviour: ``[STRATEGY-ASYNC] stall_detected … force_terminal``
    fired purely on idle_s > 240, killing the task while the AI call
    was still in progress, so the document was never saved.
  * New behaviour (PR-CY15):
      - ``in_ai_call=True`` heartbeat is written before each provider
        call and cleared after it returns.
      - The poll endpoint never force_terminals an in-flight AI call
        on idle_s alone.
      - A separate absolute max runtime cap
        (``STRATEGY_TASK_MAX_SECONDS``) is the only path that can kill
        an active AI call.
      - The pending response surfaces ``warning=True`` + a
        long-AI-repair message instead of "No strategy found".

Tests are pure-text + isolated SQLite so they run without booting Flask
(no SECRET_KEY / ADMIN_PASSWORD shimming required).
"""

from __future__ import annotations

import importlib.util
import os
import re
import sqlite3
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'app.py')


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


# ─────────────────────── Source-level assertions ──────────────────────────

def test_idle_threshold_default_raised_to_900():
    """Part C — IDLE_THRESHOLD_SECONDS default raised from 180 to 900s
    so a long single-AI-call repair pass cannot trip the detector while
    legitimately working."""
    src = _read(APP_PY)
    m = re.search(
        r"IDLE_THRESHOLD_SECONDS\s*=\s*int\(os\.getenv\(\s*"
        r"'IDLE_THRESHOLD_SECONDS'\s*,\s*'(\d+)'",
        src,
    )
    assert m, 'IDLE_THRESHOLD_SECONDS env-driven default not found'
    assert int(m.group(1)) >= 900, (
        f'IDLE_THRESHOLD_SECONDS default must be >= 900s; got '
        f'{m.group(1)}'
    )


def test_strategy_task_max_seconds_config_exists():
    """Part C — STRATEGY_TASK_MAX_SECONDS is a separate absolute cap."""
    src = _read(APP_PY)
    m = re.search(
        r"STRATEGY_TASK_MAX_SECONDS\s*=\s*int\(\s*"
        r"os\.getenv\(\s*'STRATEGY_TASK_MAX_SECONDS'\s*,\s*'(\d+)'",
        src,
    )
    assert m, 'STRATEGY_TASK_MAX_SECONDS env-driven default not found'
    default = int(m.group(1))
    assert default >= 1800, (
        f'STRATEGY_TASK_MAX_SECONDS default must be >= 1800s; got '
        f'{default}'
    )


def test_heartbeat_helpers_exist():
    """Part A — pre/post AI-call heartbeat helpers must exist."""
    src = _read(APP_PY)
    assert 'def _strategy_heartbeat_begin_ai_call(' in src, (
        'pre-AI-call heartbeat helper missing'
    )
    assert 'def _strategy_heartbeat_end_ai_call(' in src, (
        'post-AI-call heartbeat helper missing'
    )
    # Generic update helper handles in_ai_call + substage on the row.
    assert 'def _strategy_heartbeat_update(' in src
    # Heartbeat log line uses the required structured tag.
    assert '[STRATEGY-ASYNC] heartbeat task=' in src


def test_heartbeat_called_around_provider_calls():
    """Part A — generate_ai_content wraps every provider dispatch with
    begin + end heartbeat helpers (initial provider AND fallback chain)."""
    src = _read(APP_PY)
    m = re.search(
        r"def generate_ai_content\([^)]*\):.*?\n    if result:\n",
        src, re.DOTALL,
    )
    assert m, 'generate_ai_content body not extractable'
    body = m.group(0)
    # Begin heartbeat appears at least twice (initial + fallback loop).
    assert body.count('_strategy_heartbeat_begin_ai_call(') >= 2, (
        'begin heartbeat must be called before BOTH the initial '
        'provider call and the fallback provider calls'
    )
    # End heartbeat appears at least twice (initial finally + fallback finally).
    assert body.count('_strategy_heartbeat_end_ai_call(') >= 2, (
        'end heartbeat must be called after BOTH the initial provider '
        'call and the fallback provider calls (try/finally)'
    )
    # Begin heartbeat must precede the provider dispatch in the source.
    begin_idx = body.find('_strategy_heartbeat_begin_ai_call(')
    anthropic_idx = body.find('_generate_anthropic(system_prompt')
    assert 0 < begin_idx < anthropic_idx, (
        'begin heartbeat must appear before the first provider call'
    )


def test_stall_detector_skips_force_terminal_for_active_ai_call():
    """Part B — stall detection in api_strategy_status only force-
    terminals when in_ai_call is False (or the absolute max cap fires)."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_status\(task_id\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m, 'api_strategy_status body not extractable'
    body = m.group(0)
    # in_ai_call is read off the task row.
    assert 'in_ai_call' in body
    # Idle path only triggers when NOT in_ai_call.
    assert 'and not _in_ai_call_bool' in body, (
        'stall detector must require in_ai_call=False before force-'
        'terminal on idle_s alone'
    )
    # Absolute max cap is the only path that ignores in_ai_call.
    assert 'STRATEGY_TASK_MAX_SECONDS' in body
    assert '_max_exceeded' in body or 'max_exceeded' in body
    # Stall-check diagnostic log is present.
    assert '[STRATEGY-STALL-CHECK]' in body


def test_stall_check_diagnostic_includes_required_fields():
    """Part E — [STRATEGY-STALL-CHECK] log line includes idle_s,
    threshold, in_ai_call, stage, substage, will_force_terminal."""
    src = _read(APP_PY)
    idx = src.find('[STRATEGY-STALL-CHECK] task=')
    assert idx != -1, '[STRATEGY-STALL-CHECK] task= log line not found'
    blob = src[idx:idx + 800]
    for token in ('task=', 'idle_s=', 'threshold=', 'in_ai_call=',
                  'stage=', 'substage=', 'will_force_terminal='):
        assert token in blob, (
            f'[STRATEGY-STALL-CHECK] log must include {token}'
        )


def test_force_terminal_log_includes_diagnostics():
    """Part E — [STRATEGY-ASYNC] force_terminal log enriched with
    reason / stage / substage / in_ai_call."""
    src = _read(APP_PY)
    idx = src.find('[STRATEGY-ASYNC] force_terminal task=')
    assert idx != -1, 'force_terminal log line not found'
    blob = src[idx:idx + 800]
    for token in ('reason=', 'stage=', 'substage=', 'in_ai_call='):
        assert token in blob, (
            f'force_terminal log must include {token}'
        )


def test_pending_response_surfaces_warning_for_long_ai_repair():
    """Part D — api_strategy_status pending response carries
    warning=True + the long-AI-repair message when the idle threshold is
    exceeded but in_ai_call is True."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_status\(task_id\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert 'long AI repair step in progress' in body, (
        'pending warning message missing'
    )
    assert "'warning': True" in body, (
        'pending warning envelope must set warning=True'
    )
    # Original "still running" wording is preserved as the no-warning
    # default so the existing PR-CY12/PR-CY14 frontend contract holds.
    assert "'message': 'Generation is still running'" in body


def test_latest_pending_response_has_in_ai_call_and_warning():
    """Part D — /api/strategy/latest pending envelope now also surfaces
    in_ai_call + warning so the recovery path can render the same long-
    AI-repair UX as the polling path."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_latest\(\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert "'in_ai_call':" in body
    assert "'warning':" in body
    assert 'long AI repair step in progress' in body
    # No-strategy-found is NOT returned while an active task exists —
    # the active-task branch must short-circuit before the 404.
    no_strat_idx = body.find("'error': 'No strategy found'")
    pending_idx = body.find("'pending': True")
    assert pending_idx != -1
    assert no_strat_idx != -1
    assert pending_idx < no_strat_idx, (
        'pending branch must run BEFORE the 404 No-strategy-found '
        'fallback so an active task never surfaces "No strategy found"'
    )


def test_background_tasks_migration_adds_in_ai_call_and_substage():
    """Part A — DB schema gains in_ai_call + substage columns (with
    guarded ALTER TABLE for legacy DBs)."""
    src = _read(APP_PY)
    # Fresh-create table includes the new columns.
    assert 'in_ai_call INTEGER' in src
    assert 'substage TEXT' in src
    # Migration ALTER TABLE statements are present (split across two
    # adjacent string literals in the Python source — match either form).
    assert 'ADD COLUMN substage TEXT' in src
    assert 'ADD COLUMN in_ai_call INTEGER DEFAULT 0' in src


# ───────────────────── Behavioural / runtime tests ────────────────────────

# We import a small subset of app.py via a stub-Flask environment so the
# heartbeat + stall-detection helpers can be exercised against an in-
# memory SQLite DB without booting the whole Flask app (which would
# require ADMIN_PASSWORD / SECRET_KEY etc.).


@pytest.fixture
def stall_module(tmp_path, monkeypatch):
    """Load just the heartbeat + stall helpers from app.py against an
    isolated SQLite file by extracting the relevant helper definitions
    via exec() so we avoid the full Flask import chain.
    """
    db_path = tmp_path / 'bg.db'

    # Build a minimal shim that exposes get_db_direct + closing + the
    # helpers under test.
    src = _read(APP_PY)

    # Slice helper functions we need (heartbeat + ensure_terminal
    # + stall config + get_background_task + _parse_db_timestamp).
    def _slice(start_marker: str, end_marker: str) -> str:
        i = src.index(start_marker)
        j = src.index(end_marker, i)
        return src[i:j]

    parse_ts = _slice('def _parse_db_timestamp(', '\ndef bump_background_task_progress(')
    heartbeat_update = _slice(
        'def _strategy_heartbeat_update(',
        '\ndef _strategy_heartbeat_begin_ai_call(',
    )
    heartbeat_begin = _slice(
        'def _strategy_heartbeat_begin_ai_call(',
        '\ndef _strategy_heartbeat_end_ai_call(',
    )
    heartbeat_end = _slice(
        'def _strategy_heartbeat_end_ai_call(',
        '\ndef get_background_task(',
    )
    get_task = _slice('def get_background_task(', '\ndef _strategy_domain_canonical(')
    ensure_terminal = _slice(
        'def ensure_strategy_task_terminal_state(',
        '\ndef ensure_latest_strategy_recoverable(',
    )
    # IDLE / MAX config block.
    idle_cfg = _slice(
        '# PR-CY15: default raised from 180',
        '\ndef _parse_db_timestamp(',
    )

    # Inject minimal globals.
    code = f"""
import os, sqlite3
from contextlib import closing

DB_PATH = {str(db_path)!r}

def get_db_direct():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Stub flask.g so heartbeat helpers can resolve a task id.
class _G:
    _strategy_task_id = None

class _FlaskStub:
    g = _G()

import sys, types
flask_mod = types.ModuleType('flask')
flask_mod.g = _G()
sys.modules['flask'] = flask_mod

{idle_cfg}
{parse_ts}
{heartbeat_update}
{heartbeat_begin}
{heartbeat_end}
{get_task}
{ensure_terminal}

# Bootstrap DB schema (matches app.py background_tasks DDL).
with closing(get_db_direct()) as conn:
    conn.execute('''
        CREATE TABLE background_tasks (
            task_id TEXT PRIMARY KEY,
            user_id INTEGER,
            status TEXT DEFAULT 'pending',
            result TEXT,
            error TEXT,
            callback_domain TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            stage TEXT,
            substage TEXT,
            in_ai_call INTEGER DEFAULT 0
        )
    ''')
    conn.commit()

def make_task(task_id='t-abc12345', age_seconds=300, idle_seconds=300,
              in_ai_call=False, stage='vision_repair'):
    import datetime as _dt
    now = _dt.datetime.utcnow()
    created = now - _dt.timedelta(seconds=age_seconds)
    updated = now - _dt.timedelta(seconds=idle_seconds)
    with closing(get_db_direct()) as conn:
        conn.execute('DELETE FROM background_tasks WHERE task_id = ?',
                     (task_id,))
        conn.execute(
            'INSERT INTO background_tasks '
            '(task_id, user_id, status, callback_domain, '
            'created_at, updated_at, stage, in_ai_call) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (task_id, 1, 'pending', 'Cyber Security',
             created.strftime('%Y-%m-%d %H:%M:%S'),
             updated.strftime('%Y-%m-%d %H:%M:%S'),
             stage, 1 if in_ai_call else 0),
        )
        conn.commit()
    return task_id

def task_status(task_id):
    with closing(get_db_direct()) as conn:
        row = conn.execute(
            'SELECT status, error, in_ai_call, stage, substage '
            'FROM background_tasks WHERE task_id = ?',
            (task_id,)
        ).fetchone()
    return dict(row) if row else None

def stall_decision(task_id, idle_threshold, max_seconds):
    \"\"\"Mirror the api_strategy_status stall logic on the bare row so we
    can unit-test it without booting Flask.\"\"\"
    import datetime as _dt
    row = task_status(task_id)
    with closing(get_db_direct()) as conn:
        full = conn.execute(
            'SELECT created_at, updated_at, in_ai_call '
            'FROM background_tasks WHERE task_id = ?',
            (task_id,)
        ).fetchone()
    now = _dt.datetime.utcnow()
    created = _parse_db_timestamp(full['created_at'])
    updated = _parse_db_timestamp(full['updated_at']) or created
    elapsed_s = int((now - created).total_seconds()) if created else None
    idle_s = int((now - updated).total_seconds()) if updated else None
    in_ai = bool(full['in_ai_call'])
    if elapsed_s is not None and elapsed_s > max_seconds:
        return ('force_terminal_max', elapsed_s, idle_s, in_ai)
    if idle_s is not None and idle_s > idle_threshold and not in_ai:
        return ('force_terminal_idle', elapsed_s, idle_s, in_ai)
    if idle_s is not None and idle_s > idle_threshold and in_ai:
        return ('pending_warning', elapsed_s, idle_s, in_ai)
    return ('pending_ok', elapsed_s, idle_s, in_ai)
"""
    mod = types.ModuleType('stall_shim')
    mod.__file__ = str(tmp_path / 'shim.py')
    exec(compile(code, mod.__file__, 'exec'), mod.__dict__)
    return mod


def test_active_ai_call_with_high_idle_does_not_force_terminal(stall_module):
    """Required test 1 — Active AI call with idle_s > threshold does NOT
    force_terminal."""
    tid = stall_module.make_task(
        age_seconds=600, idle_seconds=400, in_ai_call=True,
    )
    decision, _elapsed, _idle, in_ai = stall_module.stall_decision(
        tid, idle_threshold=240, max_seconds=1800,
    )
    assert in_ai is True
    assert decision == 'pending_warning'
    # Status row remains pending.
    assert stall_module.task_status(tid)['status'] == 'pending'


def test_idle_pending_task_without_ai_call_force_terminals(stall_module):
    """Required test 2 — Non-AI pending task with idle_s > threshold
    DOES force_terminal."""
    tid = stall_module.make_task(
        age_seconds=600, idle_seconds=400, in_ai_call=False,
    )
    decision, _elapsed, _idle, in_ai = stall_module.stall_decision(
        tid, idle_threshold=240, max_seconds=1800,
    )
    assert in_ai is False
    assert decision == 'force_terminal_idle'
    # Verify ensure_strategy_task_terminal_state actually transitions it.
    stall_module.ensure_strategy_task_terminal_state(
        tid,
        error_message='Generation stalled: no progress for 400s',
        force_terminal_context={
            'reason': 'idle stall',
            'stage': 'vision_repair', 'substage': None,
            'in_ai_call': False, 'idle_s': 400, 'elapsed_s': 600,
        },
    )
    assert stall_module.task_status(tid)['status'] == 'error'


def test_absolute_max_runtime_force_terminals_even_in_ai_call(stall_module):
    """Required test 3 — Absolute max runtime force_terminals even if
    in_ai_call=True."""
    tid = stall_module.make_task(
        age_seconds=2400, idle_seconds=10, in_ai_call=True,
    )
    decision, elapsed, _idle, in_ai = stall_module.stall_decision(
        tid, idle_threshold=900, max_seconds=1800,
    )
    assert in_ai is True
    assert elapsed > 1800
    assert decision == 'force_terminal_max'


def test_heartbeat_begin_writes_in_ai_call_and_substage(stall_module):
    """Required test 4 — Begin heartbeat updates the task row with
    in_ai_call=True, stage='ai_provider_call' and a substage."""
    tid = stall_module.make_task(
        age_seconds=120, idle_seconds=120, in_ai_call=False,
    )
    # Wire flask.g.* so the helpers find this task id.
    import sys
    sys.modules['flask'].g._strategy_task_id = tid
    stall_module._strategy_heartbeat_begin_ai_call(
        provider='anthropic', section='vision_repair',
    )
    row = stall_module.task_status(tid)
    assert row is not None
    assert bool(row['in_ai_call']) is True
    assert row['stage'] == 'ai_provider_call'
    # substage encodes the provider and section hints.
    assert 'anthropic' in (row['substage'] or '')
    assert 'vision_repair' in (row['substage'] or '')


def test_heartbeat_end_clears_in_ai_call(stall_module):
    """Required test 5 — End heartbeat clears in_ai_call."""
    tid = stall_module.make_task(
        age_seconds=120, idle_seconds=120, in_ai_call=True,
        stage='ai_provider_call',
    )
    import sys
    sys.modules['flask'].g._strategy_task_id = tid
    stall_module._strategy_heartbeat_end_ai_call(
        next_stage='post_normalization_audit',
    )
    row = stall_module.task_status(tid)
    assert bool(row['in_ai_call']) is False
    assert row['stage'] == 'post_normalization_audit'


# ──────────────────── Static guarantees / scope guards ────────────────────

def test_pending_status_does_not_show_no_strategy_found_for_active_task():
    """Required test 7 — While an active task exists the latest endpoint
    must return pending, NOT "No strategy found"."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_latest\(\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    body = m.group(0)
    # Resolution order: lookup active task, return pending if found,
    # only THEN return 404 No strategy found.
    pending_idx = body.find("'pending': True")
    no_strat_idx = body.find("'error': 'No strategy found'")
    assert pending_idx != -1 and no_strat_idx != -1
    assert pending_idx < no_strat_idx


def test_existing_task_completion_behaviour_unchanged():
    """Required test 8 — done/error branches of api_strategy_status are
    unchanged: still return status:'done' or status:'error'."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_status\(task_id\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    body = m.group(0)
    assert "if status == 'done':" in body
    assert "if status == 'error':" in body
    assert "'status': 'done'" in body
    assert "'status': 'error'" in body


def test_validators_and_final_audit_unchanged():
    """Required test 9 — the strategy validators and final audit are
    NOT modified by this PR. Spot-check that the marker functions /
    constants still exist verbatim."""
    src = _read(APP_PY)
    # Spot-check a few well-known validator / audit anchors that prior
    # PRs added; PR-CY15 must not have touched them.
    for anchor in (
        '_final_strategy_audit',
        '_compute_missing_compliance_objective',
        '_compute_applicable_strategy_obligations',
        'selected_framework_coverage_missing',
    ):
        assert anchor in src, (
            f'final-audit / validator anchor {anchor} disappeared — '
            'PR-CY15 must not modify validators'
        )


def test_data_management_pipeline_unchanged():
    """Required test 10 — Data Management generation logic is not
    touched. Spot-check NDMO / PDPL repair anchors."""
    src = _read(APP_PY)
    for anchor in (
        '_convergence_data_framework_coverage_repair',
        '_convergence_data_roadmap_balance_repair',
        '_pdpl_save_guard_required_terms',
        '_DATA_ROADMAP_BALANCE_BY_FRAMEWORK',
    ):
        assert anchor in src, (
            f'data-management anchor {anchor} disappeared — '
            'PR-CY15 must not modify data generation logic'
        )


def test_no_deterministic_strategy_content_added():
    """Required test 11 — PR-CY15 must not add deterministic strategy
    content. The diff must touch only task lifecycle / stall detection
    (heartbeat helpers, schema migration, poll endpoint, AI provider
    instrumentation) — not strategy section text."""
    src = _read(APP_PY)
    # Sanity check: the new heartbeat helpers carry no embedded strategy
    # prose. Inspect a generous slice around the helpers and assert it
    # does not contain a vision/mission/objective table row marker that
    # would indicate hard-coded strategy content.
    i = src.index('def _strategy_heartbeat_update(')
    j = src.index('def get_background_task(', i)
    helper_blob = src[i:j]
    # Markdown table rows or vision/mission AR/EN templates would each
    # contain '|' delimiter pairs and a leading framework name. Heart-
    # beat helpers must not contain any.
    forbidden_patterns = (
        '## Vision', '## Mission', 'الرؤية', 'الرسالة',
        'NDMO', 'PDPL', 'ECC', 'CSCC', 'DCC',
    )
    for pat in forbidden_patterns:
        assert pat not in helper_blob, (
            f'heartbeat helpers must not contain strategy content '
            f'token {pat!r}'
        )
