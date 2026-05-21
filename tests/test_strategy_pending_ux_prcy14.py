"""PR-CY14 — Frontend pending UX + long-running task lifecycle visibility.

Pure-text assertions on ``app.py`` and ``templates/domain.html`` so the
suite stays fast and does not require app import (no ADMIN_PASSWORD /
SECRET_KEY / DATABASE_URL shimming).

Covers:

1. ``/api/strategy/latest`` pending envelope exposes ``stage`` and
   ``elapsed_seconds`` (resolved from the active background task row),
   in addition to the existing ``task_id`` + ``message`` fields.

2. Backend log line ``[STRATEGY-ASYNC] latest_recoverable_pending`` now
   includes ``stage=`` and ``elapsed_seconds=`` so operators can see
   what the frontend is being told.

3. Frontend ``_doRecoveryFetch`` pending branch no longer surfaces only
   a transient "check My Documents" toast — it renders a persistent
   banner via ``renderStrategyPendingBanner(task_id, stage,
   elapsed_seconds)``.

4. The banner exposes the new Arabic message
   "لا يزال التوليد جارياً. المرحلة الحالية: ... الوقت المنقضي: ... ثانية."
   and the corresponding English message, AND a visible
   "تحديث الحالة" / "Refresh status" button.

5. Clicking the refresh button re-polls ``/api/strategy-status/<task_id>``
   using the same ``task_id`` and routes done/error/pending responses
   appropriately (calls ``_onStrategyResult`` on done, surfaces error
   verbatim, refreshes telemetry if still pending).

6. The banner does NOT instruct the user to "check My Documents" while
   the task is still running.
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


# ────────────────────────── Backend ───────────────────────────────────────

def test_latest_pending_envelope_exposes_stage_and_elapsed_seconds():
    """Test 1 — /api/strategy/latest pending response exposes stage and
    elapsed_seconds (in addition to task_id + message)."""
    src = _read(APP_PY)
    m = re.search(
        r"def api_strategy_latest\(\):.*?\n@app\.route",
        src, re.DOTALL,
    )
    assert m, 'api_strategy_latest function not found'
    body = m.group(0)
    # The pending branch must build the response from the active task
    # row — i.e. resolve the row via get_background_task before returning.
    assert 'get_background_task(_active_tid)' in body, (
        'pending branch must resolve the background task row to get stage'
    )
    assert "'stage':" in body, (
        'pending response must expose a stage field'
    )
    assert "'elapsed_seconds':" in body, (
        'pending response must expose an elapsed_seconds field'
    )
    # Existing pending contract is preserved.
    assert "'pending': True" in body
    assert "'task_id': _active_tid" in body
    assert "'message': 'Generation is still running'" in body


def test_latest_recoverable_pending_log_includes_stage_and_elapsed():
    """Test 2 — operator log line carries the same telemetry the
    frontend is being given."""
    src = _read(APP_PY)
    idx = src.find('[STRATEGY-ASYNC] latest_recoverable_pending')
    assert idx != -1, 'latest_recoverable_pending log line not found'
    blob = src[idx:idx + 600]
    assert 'stage=' in blob
    assert 'elapsed_seconds=' in blob


# ────────────────────────── Frontend ──────────────────────────────────────

def test_recovery_pending_branch_renders_persistent_banner():
    """Test 3 — recovery pending branch calls
    renderStrategyPendingBanner(task_id, stage, elapsed_seconds)
    instead of relying solely on a transient toast."""
    html = _read(DOMAIN_HTML)
    # The pending branch detection survives.
    assert 'd.pending === true' in html
    # New helper invocation in the pending branch.
    assert 'renderStrategyPendingBanner(' in html, (
        'pending branch must call the persistent banner helper'
    )
    # Helper definition exists.
    assert 'function renderStrategyPendingBanner(taskId, stage, elapsedSeconds)' in html


def test_pending_banner_renders_new_message_and_refresh_button():
    """Test 4 — banner exposes the new Arabic + English wording and a
    visible 'تحديث الحالة' / 'Refresh status' button."""
    html = _read(DOMAIN_HTML)
    # New Arabic message.
    assert 'لا يزال التوليد جارياً. المرحلة الحالية:' in html
    assert 'الوقت المنقضي:' in html
    assert 'ثانية.' in html
    # New English equivalent.
    assert 'Generation is still running. Current stage:' in html
    assert 'Elapsed:' in html
    assert 'seconds.' in html
    # Refresh button text in both languages.
    assert 'تحديث الحالة' in html
    assert 'Refresh status' in html
    # Button has a stable id so the banner can re-find it.
    assert 'strategy-pending-banner-refresh' in html


def test_refresh_button_repolls_strategy_status_with_same_task_id():
    """Test 5 — refresh button issues a GET to
    /api/strategy-status/<task_id> using the stored task_id and
    branches on done/error/pending."""
    html = _read(DOMAIN_HTML)
    # Extract the renderStrategyPendingBanner body.
    m = re.search(
        r"function renderStrategyPendingBanner\([^)]*\)\{.*?\n\}\n\n"
        r"function hideStrategyPendingBanner",
        html, re.DOTALL,
    )
    assert m, 'renderStrategyPendingBanner body not extractable'
    body = m.group(0)
    # Same-task_id re-poll.
    assert "fetch('/api/strategy-status/'+tid)" in body
    # Done branch hands off to _onStrategyResult.
    assert '_onStrategyResult(_r)' in body
    # Error branch surfaces the backend error.
    assert "s.status === 'error'" in body
    # Still-pending refresh path updates the banner with new telemetry.
    assert 'renderStrategyPendingBanner(tid,' in body


def test_pending_banner_does_not_tell_user_to_check_my_documents():
    """Test 6 — the new banner message must NOT direct the user to
    My Documents while the task is still running. The legacy phrase
    may still appear in unrelated timeout / policy / audit paths, but
    the new banner copy itself must not contain it."""
    html = _read(DOMAIN_HTML)
    m = re.search(
        r"function renderStrategyPendingBanner\([^)]*\)\{.*?\n\}\n\n"
        r"function hideStrategyPendingBanner",
        html, re.DOTALL,
    )
    assert m, 'renderStrategyPendingBanner body not extractable'
    banner_body = m.group(0)
    assert 'My Documents' not in banner_body, (
        'pending banner must not tell the user to check My Documents '
        'while the background task is still running'
    )
    assert 'وثائقي' not in banner_body and 'مستنداتي' not in banner_body, (
        'pending banner must not tell the Arabic user to check '
        'وثائقي/مستنداتي while the background task is still running'
    )


def test_recovery_pending_branch_does_not_emit_my_documents_toast():
    """Test 6b — the recovery pending branch (the call site for the
    banner) no longer relies on the legacy "check My Documents" toast
    as its only feedback. That message used to mislead users into
    thinking the document was already saved."""
    html = _read(DOMAIN_HTML)
    # Slice the _doRecoveryFetch body.
    m = re.search(
        r"function _doRecoveryFetch\(reason\)\{.*?\n  \}\n",
        html, re.DOTALL,
    )
    assert m, '_doRecoveryFetch body not extractable'
    body = m.group(0)
    # Pending branch is wired to the banner.
    assert 'renderStrategyPendingBanner(' in body
    # Legacy "check My Documents" wording is no longer the pending
    # branch's only signal — it must not be the toast emitted right
    # after detecting d.pending === true.
    pending_idx = body.find('d.pending === true')
    success_idx = body.find('d.success')
    assert pending_idx != -1
    assert success_idx > pending_idx, (
        'sanity check — success branch comes after pending branch'
    )
    pending_block = body[pending_idx:success_idx]
    assert 'check My Documents' not in pending_block
    assert 'مراجعة وثائقي' not in pending_block
    assert 'مستنداتي' not in pending_block
