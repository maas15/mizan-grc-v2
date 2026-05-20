"""PR-CY12 — Stabilize strategy task polling + Cyber vision persistence.

Pure-text assertions on ``app.py`` and ``templates/domain.html`` so the
suite stays fast and does not require app import (no ADMIN_PASSWORD /
SECRET_KEY / DATABASE_URL shimming).

Covers (mapping to problem-statement requirements):

* **Part A — task status / frontend polling**
  1. Status endpoint returns ``pending=true`` + ``stage`` + ``elapsed_seconds``
     + ``message="Generation is still running"`` while a task is active.
  2. Status endpoint does NOT return ``"No strategy found"`` for an active
     task (``/api/strategy/latest`` reroutes to a pending envelope).
  3. Duplicate generation request reuses the active ``task_id``
     (``[STRATEGY-ASYNC] active_task_reused`` log + reused payload).
  4. Frontend timeout message says "Generation is still running. Please
     wait or check My Documents." (and Arabic equivalent) when the
     backend recovery response carries ``pending=true`` — NOT the legacy
     "انتهت مهلة الإنشاء" generic-timeout toast.

* **Part B — Cyber vision persistence**
  5. ``[CYBER-VISION-PERSISTENCE] phase=after_accept`` fires immediately
     after acceptance.
  6. ``[CYBER-VISION-PERSISTENCE] phase=after_normalization`` and
     ``phase=before_final_audit`` fire around the post-normalization
     audit.
  7. The PR-CY11 post-normalization guard still rewires the targeted
     top-up before the final unified 422 emission.

* **Part C — Reduce excessive AI calls**
  8. Cyber roadmap balance repair stops early when ``missing_after=[]``.
  9. Cyber vision specialized-objective top-up early-exits (no AI call)
     when the specialized-function detector already passes.

* **Strict scope safeguards**
  10. Data Management roadmap / coverage code is not touched.
  11. Validators / final audit / save guards are not weakened (no
      deterministic objective row is appended in the new helper).
"""

from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'app.py')
DOMAIN_HTML = os.path.join(ROOT, 'templates', 'domain.html')


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


# ────────────────────────── Part A ────────────────────────────────────────

def test_status_pending_response_contract():
    """Test 1 — pending envelope exposes pending/stage/elapsed_seconds/
    message keys."""
    src = _read(APP_PY)
    # The pending jsonify(...) block lives inside ``api_strategy_status``.
    # Slice the function body so we don't accidentally match other
    # ``status: 'pending'`` strings elsewhere (e.g. create_background_task).
    m = re.search(
        r"def api_strategy_status\(task_id\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m, 'api_strategy_status function not found'
    body = m.group(0)
    assert "'pending': True" in body, (
        "pending response must expose pending=true"
    )
    assert "'elapsed_seconds':" in body, (
        "pending response must expose elapsed_seconds"
    )
    assert "'message': 'Generation is still running'" in body, (
        "pending response must carry the standard 'Generation is still "
        "running' message"
    )
    # stage is attached via _with_progress.setdefault('stage', ...)
    assert "setdefault('stage'" in body


def test_status_latest_does_not_return_no_strategy_found_for_active_task():
    """Test 2 — /api/strategy/latest reroutes to pending envelope when an
    active task exists for the same user+domain."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_latest\(\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m, 'api_strategy_latest function not found'
    body = m.group(0)
    # Helper is consulted before the 404 branch.
    assert 'find_active_strategy_task(' in body, (
        'api_strategy_latest must check for an active task'
    )
    # When active, returns pending envelope (no 404, no "No strategy found").
    assert "'pending': True" in body
    assert "'message': 'Generation is still running'" in body
    # The "No strategy found" 404 must still exist but be guarded by the
    # active-task check. We assert source-order: the active-task branch
    # appears BEFORE the 404 return inside the if-not-row block.
    not_found_idx = body.find("'error': 'No strategy found'")
    pending_idx = body.find("'message': 'Generation is still running'")
    assert pending_idx != -1 and not_found_idx != -1
    assert pending_idx < not_found_idx, (
        'active-task pending branch must precede the "No strategy found" '
        '404 return so an active task never receives a 404'
    )


def test_duplicate_strategy_request_reuses_active_task():
    """Test 3 — api_generate_strategy_async returns the existing task_id
    when one is active."""
    src = _read(APP_PY)
    # Helper definition exists.
    assert 'def find_active_strategy_task(user_id, domain):' in src
    # Generation endpoint uses it.
    m = re.search(
        r"def api_generate_strategy_async\(\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m, 'api_generate_strategy_async function not found'
    body = m.group(0)
    assert 'find_active_strategy_task(user_id, domain)' in body
    assert "[STRATEGY-ASYNC] active_task_reused" in body
    assert "'reused': True" in body


def test_frontend_timeout_message_when_backend_still_running():
    """Test 4 — frontend recovery surfaces the new "still running" toast
    when the backend response carries pending=true."""
    html = _read(DOMAIN_HTML)
    assert 'd.pending === true' in html, (
        'recovery flow must detect the pending envelope'
    )
    # New EN message.
    assert (
        'Generation is still running. Please wait or check My Documents.'
        in html
    )
    # New AR message.
    assert (
        'لا يزال الإنشاء قيد التشغيل. يُرجى الانتظار أو مراجعة وثائقي.'
        in html
    )
    # The legacy "انتهت مهلة الإنشاء" message must still exist as the
    # genuine-timeout branch — we don't want to fully delete it.
    assert 'انتهت مهلة الإنشاء' in html


# ────────────────────────── Part B ────────────────────────────────────────

def test_cyber_vision_persistence_helper_defined():
    """Test 5/6 prerequisite — the shared persistence helper exists."""
    src = _read(APP_PY)
    assert 'def _emit_cyber_vision_persistence_diagnostic(' in src
    assert '[CYBER-VISION-PERSISTENCE]' in src
    # Helper is Cyber-scoped (no-op for other domains).
    helper = re.search(
        r"def _emit_cyber_vision_persistence_diagnostic\(.*?\)\:.*?"
        r"\ndef ",
        src, re.DOTALL,
    )
    assert helper, 'helper function body not extractable'
    hbody = helper.group(0)
    assert "if dcode != 'cyber':" in hbody, (
        'persistence helper must be strictly Cyber-scoped'
    )
    # Helper must NOT mutate sections (only reads vision text + emits log).
    assert "sections['vision'] =" not in hbody
    assert 'has_specialized_objective=' in hbody
    assert 'row_preview=' in hbody


def test_cyber_vision_persistence_after_accept_emission():
    """Test 5 — persistence diagnostic fires after acceptance."""
    src = _read(APP_PY)
    # Locate the topup repair function.
    m = re.search(
        r"def _convergence_cyber_specialized_objective_topup_repair\("
        r".*?\n\n\ndef ",
        src, re.DOTALL,
    )
    assert m, 'topup repair function not found'
    body = m.group(0)
    assert "phase='after_accept'" in body, (
        'after_accept persistence diagnostic must be emitted on '
        'acceptance'
    )


def test_cyber_vision_persistence_after_normalization_and_before_audit():
    """Test 6 — both `after_normalization` and `before_final_audit`
    phases fire around the post-normalization re-audit."""
    src = _read(APP_PY)
    assert "phase='after_normalization'" in src
    assert "phase='before_final_audit'" in src
    # Both emissions must precede the `_post_norm_defects =
    # _final_strategy_audit(...)` call so we know the row state when
    # the audit reads `sections`.
    after_norm_idx = src.find("phase='after_normalization'")
    before_audit_idx = src.find("phase='before_final_audit'")
    audit_call = src.find(
        '_post_norm_defects = _final_strategy_audit(',
    )
    assert -1 not in (after_norm_idx, before_audit_idx, audit_call)
    assert after_norm_idx < audit_call
    assert before_audit_idx < audit_call


def test_post_normalization_guard_still_reinvokes_topup():
    """Test 7 — the PR-CY11 post-normalization guard remains: when the
    accepted row is lost after normalization, the targeted top-up is
    re-run before the unified 422."""
    src = _read(APP_PY)
    # The guard log tag is split across two adjacent f-string literals in
    # source ('post_normalization_' + 'guard_fired'). Just assert both
    # halves and the topup re-invocation appear in order.
    a = src.find('post_normalization_')
    b = src.find('guard_fired', a)
    c = src.find(
        '_convergence_cyber_specialized_objective_topup_repair(', b,
    )
    assert -1 not in (a, b, c) and a < b < c, (
        'PR-CY11 post-normalization guard must still re-invoke the '
        'targeted top-up'
    )


# ────────────────────────── Part C ────────────────────────────────────────

def test_cyber_roadmap_balance_repair_stops_early():
    """Test 8 — roadmap repair logs `missing_after=[]` and returns when
    nothing is missing."""
    src = _read(APP_PY)
    m = re.search(
        r"def _convergence_cyber_roadmap_balance_repair\(.*?"
        r"def _convergence_cyber_specialized_objective_topup_repair\(",
        src, re.DOTALL,
    )
    assert m, 'cyber roadmap balance repair function not found'
    body = m.group(0)
    assert 'missing_after=[] ' in body and 'stopping_early' in body
    # And the return 0 short-circuit precedes the AI prompt assembly.
    early_exit_idx = body.find('stopping_early')
    ai_call_idx = body.find('ai_repair_strategy_section(')
    assert early_exit_idx != -1
    if ai_call_idx != -1:
        assert early_exit_idx < ai_call_idx


def test_cyber_specialized_objective_topup_skips_when_passing():
    """Test 9 — specialized-objective top-up logs
    ``phase=skip_already_passing`` and short-circuits without an AI
    call."""
    src = _read(APP_PY)
    m = re.search(
        r"def _convergence_cyber_specialized_objective_topup_repair\("
        r".*?\n\n\ndef ",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert 'phase=skip_already_passing' in body
    skip_idx = body.find('phase=skip_already_passing')
    ai_call_idx = body.find('ai_repair_strategy_section(')
    assert skip_idx != -1 and ai_call_idx != -1
    assert skip_idx < ai_call_idx, (
        'skip_already_passing log must precede any AI call site so the '
        'early-exit short-circuits the bounded retry loop'
    )


# ────────────────────── Strict-scope safeguards ───────────────────────────

def test_data_management_paths_untouched():
    """Test 10 — the Data Management convergence functions (referenced
    by memories PR-5B.9AF / PR-5B.9V / PR-5B.9Z) still exist and their
    PDPL exact-term guards are intact (no weakening / no removal)."""
    src = _read(APP_PY)
    assert 'def _convergence_data_roadmap_balance_repair(' in src
    assert 'def _convergence_data_framework_coverage_repair(' in src
    assert 'data_subject_rights' in src
    assert 'breach_notification' in src
    # The unified PDPL save guard is still wired before the generic 422.
    assert 'PR-5B.9Y' in src
    assert '_pdpl_save_guard_required_terms(' in src


def test_no_deterministic_row_inserted_by_new_helper():
    """Test 11 — the new persistence helper is diagnostic-only: it does
    NOT mutate the vision section and does NOT splice a deterministic
    objective row. (Validators / save guards are unchanged.)"""
    src = _read(APP_PY)
    m = re.search(
        r"def _emit_cyber_vision_persistence_diagnostic\(.*?"
        r"\ndef _convergence_cyber_specialized_objective_topup_repair\(",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    # Must not write to sections at all — no ``sections[...] = ...``
    # assignments anywhere in the helper body. (Reads via
    # ``sections.get('vision', '')`` are allowed.)
    assignment_re = re.compile(r"sections\[[^\]]+\]\s*=")
    assert not assignment_re.search(body), (
        'persistence helper must not assign into sections[...]'
    )
    # Must not call any AI / repair helper.
    forbidden = (
        'ai_repair_strategy_section', 'synthesize_', '_splice_',
        '_extract_cyber_vision_objective_topup_row',
        'repair_vision_objectives_if_insufficient',
    )
    for tok in forbidden:
        assert tok not in body, (
            f'persistence helper must remain diagnostic-only (found {tok})'
        )
