"""PR-5B.8D — additive operational fixes for AI provider plumbing.

Two narrow, additive changes (no strategy/content/prompt logic touched):

  1. ``IDLE_THRESHOLD_SECONDS`` is env-driven (default 180), clamped to a
     safe range [60, 1800], and any invalid env value falls back to 180.
     This lets operators raise ``AI_CALL_TIMEOUT_SECONDS`` above 180 in the
     future without a code change while preserving the invariant
     ``AI_CALL_TIMEOUT_SECONDS < IDLE_THRESHOLD_SECONDS``.

  2. ``generate_ai_content``'s fallback loop logs a clear
     ``[AI] Skipping fallback provider=...`` line whenever a fallback
     provider is skipped because its API key is missing. No keys or secrets
     are emitted — only the provider name.

Following the PR-5B.8B / 5B.8C test pattern, these tests run as pure-text
assertions on ``app.py`` so they don't require database / API-key shims and
stay fast in CI. They DO additionally exercise the env-driven clamp by
re-evaluating the exact code block under controlled environment values.
"""

from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'app.py')


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


# ── Section 1: IDLE_THRESHOLD_SECONDS env-driven ─────────────────────────────

def test_idle_threshold_seconds_reads_env_with_default_180():
    src = _read(APP_PY)
    assert "os.getenv('IDLE_THRESHOLD_SECONDS', '180')" in src, (
        "app.py must read IDLE_THRESHOLD_SECONDS from env with default '180'"
    )


def test_idle_threshold_seconds_invalid_env_falls_back_to_180():
    """An invalid env value (TypeError/ValueError) must fall back to 180."""
    src = _read(APP_PY)
    # The except branch must reset the variable to the literal 180.
    pattern = re.compile(
        r'except\s*\(\s*TypeError\s*,\s*ValueError\s*\)\s*:\s*\n'
        r'\s*IDLE_THRESHOLD_SECONDS\s*=\s*180',
        re.MULTILINE,
    )
    assert pattern.search(src), (
        "app.py must fall back to IDLE_THRESHOLD_SECONDS = 180 on invalid env "
        "values (TypeError/ValueError)"
    )


def test_idle_threshold_seconds_clamped_to_safe_range():
    """Lower bound 60, upper bound 1800."""
    src = _read(APP_PY)
    assert re.search(r'IDLE_THRESHOLD_SECONDS\s*<\s*60', src), (
        "app.py must clamp IDLE_THRESHOLD_SECONDS to a lower bound of 60"
    )
    assert re.search(r'IDLE_THRESHOLD_SECONDS\s*>\s*1800', src), (
        "app.py must clamp IDLE_THRESHOLD_SECONDS to an upper bound of 1800"
    )


def test_idle_threshold_seconds_clamp_evaluation():
    """Behavioural check: extract & exec the env-driven block under
    controlled environment values to confirm clamp + fallback semantics
    without importing the full app module.
    """
    src = _read(APP_PY)
    # Locate the exact env-driven block introduced in PR-5B.8D.
    m = re.search(
        r'try:\s*\n\s*IDLE_THRESHOLD_SECONDS\s*=\s*int\(os\.getenv\('
        r"'IDLE_THRESHOLD_SECONDS',\s*'180'\)\s*or\s*'180'\)\s*\n"
        r'except\s*\(TypeError,\s*ValueError\)\s*:\s*\n'
        r'\s*IDLE_THRESHOLD_SECONDS\s*=\s*180\s*\n'
        r'if\s+IDLE_THRESHOLD_SECONDS\s*<\s*60\s*:\s*\n'
        r'\s*IDLE_THRESHOLD_SECONDS\s*=\s*60\s*\n'
        r'elif\s+IDLE_THRESHOLD_SECONDS\s*>\s*1800\s*:\s*\n'
        r'\s*IDLE_THRESHOLD_SECONDS\s*=\s*1800',
        src,
    )
    assert m, "Could not locate PR-5B.8D env-driven IDLE_THRESHOLD_SECONDS block"

    block = m.group(0)

    def _eval_with(env_value):
        env = {} if env_value is None else {'IDLE_THRESHOLD_SECONDS': env_value}
        # Provide a minimal os shim with our controlled getenv.
        import types
        os_shim = types.SimpleNamespace(getenv=lambda k, d=None: env.get(k, d))
        ns = {'os': os_shim}
        exec(block, ns)  # noqa: S102 — controlled, internal-only block
        return ns['IDLE_THRESHOLD_SECONDS']

    # Default (env unset) → 180
    assert _eval_with(None) == 180
    # Valid mid-range value
    assert _eval_with('300') == 300
    # Below lower bound clamps to 60
    assert _eval_with('5') == 60
    # Above upper bound clamps to 1800
    assert _eval_with('99999') == 1800
    # Invalid (non-numeric) → fallback 180
    assert _eval_with('not-a-number') == 180
    # Invalid (empty string) → "or '180'" path → 180
    assert _eval_with('') == 180


def test_idle_threshold_old_literal_assignment_removed():
    """The pre-PR-5B.8D bare ``IDLE_THRESHOLD_SECONDS = 180`` literal at
    module scope must be replaced; its presence anywhere outside the
    fallback ``except`` branch would re-introduce the hard-coding.
    """
    src = _read(APP_PY)
    # Count bare literal assignments at the start of a line. The only legal
    # remaining ones are inside the fallback ``except`` branch (preceded by
    # whitespace) — those are NOT at start-of-line in the source.
    bare_literals = re.findall(
        r'^IDLE_THRESHOLD_SECONDS\s*=\s*180\s*$', src, flags=re.MULTILINE
    )
    assert not bare_literals, (
        "Hard-coded module-level `IDLE_THRESHOLD_SECONDS = 180` must be "
        "replaced by the env-driven block in PR-5B.8D"
    )


# ── Section 2: skipped-fallback logging ──────────────────────────────────────

def test_generate_ai_content_logs_skipped_fallback_provider():
    src = _read(APP_PY)
    # Must emit a clear, machine-greppable line.  No API key value is logged.
    assert "[AI] Skipping fallback provider=" in src, (
        "generate_ai_content must log skipped fallback providers with the "
        "'[AI] Skipping fallback provider=' prefix"
    )


def test_skipped_fallback_log_does_not_include_api_key():
    """Sanity: the skipped-fallback log line must not include any of the
    config.*_API_KEY references — only the provider name is emitted.
    """
    src = _read(APP_PY)
    # Find the line(s) matching the skipped-fallback log emission.
    lines = [ln for ln in src.splitlines() if "Skipping fallback provider" in ln]
    assert lines, "Expected at least one Skipping fallback provider log line"
    # Forbid any of the known key references / generic key-shaped tokens
    # (whole-word match so harmless prose like "no API key" doesn't trip).
    forbidden = re.compile(
        r'\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|GROQ_API_KEY|'
        r'DEEPSEEK_API_KEY|key_map\.get|config\.[A-Z_]+_KEY)\b'
    )
    for ln in lines:
        assert not forbidden.search(ln), (
            f"Skipped-fallback log must not reference any API key value or "
            f"config.*_KEY attribute: {ln!r}"
        )


def test_skipped_fallback_log_inside_fallback_loop():
    """The skip-log emission must live inside the fallback iteration block,
    in the ``else`` branch of ``if key_map.get(fallback):``, so that it
    fires once per skipped provider (not once for the whole call).
    """
    src = _read(APP_PY)
    skip_idx = src.find('[AI] Skipping fallback provider=')
    assert skip_idx != -1, "Expected '[AI] Skipping fallback provider=' marker"
    # Look back a bounded window for the paired `if key_map.get(fallback):`
    # and `else:` that this log emission belongs to.
    window = src[max(0, skip_idx - 2000):skip_idx]
    assert 'if key_map.get(fallback):' in window, (
        "Skipped-fallback log must follow `if key_map.get(fallback):` in the "
        "fallback iteration"
    )
    # An `else:` must appear between the `if key_map.get(fallback):` and the
    # skip-log emission, confirming the log lives in that else branch.
    if_pos = window.rfind('if key_map.get(fallback):')
    tail = window[if_pos:]
    assert re.search(r'\n\s+else\s*:\s*\n', tail), (
        "Skipped-fallback log must live inside the `else:` branch of the "
        "key_map.get(fallback) check"
    )


if __name__ == '__main__':
    # Allow running directly: ``python tests/test_provider_ops_pr5b8d.py``
    import sys
    import traceback

    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except Exception:
            failures += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
    sys.exit(1 if failures else 0)
