"""PR-5B.8B — strategy task progress / heartbeat / stall-aware polling.

Pure-text assertions on app.py and templates/domain.html. No app import
required (so these tests don't need ADMIN_PASSWORD/SECRET_KEY/DATABASE_URL
shimmed at module load), and they run fast in CI.

Covers:
  * Backend Section C: IDLE_THRESHOLD_SECONDS = 180 and the stall error
    string template are present in app.py.
  * Backend Section E: every coarse stage-bump tag is emitted from the
    strategy generation pipeline.
  * Frontend Section D: domain.html declares IDLE_CEILING_S = 180 and
    WALL_CEILING_S = 900, and no longer relies solely on the legacy
    ``maxTries=120`` counter for strategy generation timeout.
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


# ── Backend: Section C constants & stall message ──────────────────────────────

def test_backend_idle_threshold_constant():
    src = _read(APP_PY)
    # PR-CY15: default raised to 900s; still env-driven and clamped.
    assert "os.getenv('IDLE_THRESHOLD_SECONDS', '900')" in src, (
        'app.py must read IDLE_THRESHOLD_SECONDS from env with default 900'
    )


def test_backend_stall_error_message_template():
    src = _read(APP_PY)
    # Exact template required by the spec; the {idle_s}s suffix is filled
    # in by the api_strategy_status f-string.
    assert 'Generation stalled: no progress for ' in src, (
        'app.py must contain the exact stall error message prefix '
        '"Generation stalled: no progress for "'
    )


# ── Backend: Section E coarse stage bumps ─────────────────────────────────────

REQUIRED_STAGE_BUMPS = (
    'task_started',
    'request_context_ready',
    'generation_pipeline',
    'prompt_build',
    'ai_generation_started',
    'final_synthesis',
    'convergence',
    'final_audit',
    'save_gate',
)


def test_backend_emits_all_coarse_stage_bumps():
    src = _read(APP_PY)
    missing = []
    for tag in REQUIRED_STAGE_BUMPS:
        # Accept either bump_background_task_progress(task_id, '<tag>') or
        # the in-pipeline _bump_stage('<tag>') wrapper. Both write the
        # stage column verbatim.
        pat_bump = re.compile(
            r"bump_background_task_progress\([^,]+,\s*['\"]" + re.escape(tag) + r"['\"]"
        )
        pat_wrap = re.compile(r"_bump_stage\(\s*['\"]" + re.escape(tag) + r"['\"]\s*\)")
        if not (pat_bump.search(src) or pat_wrap.search(src)):
            missing.append(tag)
    assert not missing, (
        f"app.py is missing stage bump call(s) for: {missing}. "
        f"Each must appear as either bump_background_task_progress(..., '<tag>') "
        f"or _bump_stage('<tag>')."
    )


# ── Frontend: Section D ceilings & maxTries de-emphasis ───────────────────────

def test_frontend_idle_ceiling_constant():
    html = _read(DOMAIN_HTML)
    assert re.search(r'\bIDLE_CEILING_S\s*=\s*180\b', html), (
        'templates/domain.html must declare IDLE_CEILING_S = 180 in the '
        'strategy polling loop'
    )


def test_frontend_wall_ceiling_constant():
    html = _read(DOMAIN_HTML)
    assert re.search(r'\bWALL_CEILING_S\s*=\s*900\b', html), (
        'templates/domain.html must declare WALL_CEILING_S = 900 in the '
        'strategy polling loop'
    )


def test_frontend_strategy_polling_no_longer_relies_only_on_maxTries_120():
    """The strategy polling loop must no longer depend SOLELY on a
    ``maxTries=120`` counter for its generation timeout. It must use
    backend-published telemetry (elapsed_s / idle_s) gated by
    IDLE_CEILING_S / WALL_CEILING_S.
    """
    html = _read(DOMAIN_HTML)
    # Locate the strategy polling loop region. We anchor on the actual
    # `var IDLE_CEILING_S=...` JS declaration (not a docstring mention)
    # so the region starts at live code, not inside a /* ... */ block —
    # otherwise the surrounding block-comment stripping can't see its
    # `/*` opener and would leave commented-out legacy literals in the
    # haystack.
    m_start = re.search(r'\bvar\s+IDLE_CEILING_S\s*=', html)
    assert m_start is not None, 'strategy polling loop region not found'
    start = m_start.start()
    end = html.find("Policy Form", start)
    if end == -1:
        end = len(html)
    region = html[start:end]
    # Strategy polling must consume telemetry from the backend.
    assert 'elapsed_s' in region, (
        'strategy polling loop must consult backend elapsed_s telemetry'
    )
    assert 'idle_s' in region, (
        'strategy polling loop must consult backend idle_s telemetry'
    )
    # And its real ceilings must be the wall/idle constants, not 120.
    assert 'WALL_CEILING_S' in region
    assert 'IDLE_CEILING_S' in region
    # The exact legacy literal "maxTries=120" (no spaces, as it appeared
    # in the strategy poll loop's `var ... maxTries=120;` declaration)
    # must no longer appear as live code in the strategy polling region.
    # A docstring/comment that REFERENCES the old literal for context is
    # fine, so we strip JS block + line comments before checking. Other
    # unrelated polls (export etc.) are outside this region.
    region_no_block = re.sub(r'/\*.*?\*/', '', region, flags=re.DOTALL)
    region_no_comments = re.sub(r'//[^\n]*', '', region_no_block)
    assert 'maxTries=120' not in region_no_comments, (
        'strategy polling loop must not retain the legacy '
        'maxTries=120 ceiling as its generation timeout'
    )
