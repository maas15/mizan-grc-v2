"""PR-5B.8D / PR-CY15 — operational idle threshold for AI provider plumbing.

``IDLE_THRESHOLD_SECONDS`` is env-driven. PR-CY15 raised the default from
180 → 900 so long Anthropic repair passes are not force-terminated mid-call.
Values are clamped to [60, 3600].
"""

from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'app.py')

_IDLE_DEFAULT = '900'
_IDLE_FALLBACK = 900
_IDLE_CLAMP_MAX = 3600


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


def test_idle_threshold_seconds_reads_env_with_default_900():
    src = _read(APP_PY)
    assert f"os.getenv('IDLE_THRESHOLD_SECONDS', '{_IDLE_DEFAULT}')" in src, (
        f"app.py must read IDLE_THRESHOLD_SECONDS from env with default "
        f"'{_IDLE_DEFAULT}'"
    )


def test_idle_threshold_seconds_invalid_env_falls_back_to_900():
    """An invalid env value (TypeError/ValueError) must fall back to 900."""
    src = _read(APP_PY)
    pattern = re.compile(
        r'except\s*\(\s*TypeError\s*,\s*ValueError\s*\)\s*:\s*\n'
        rf'\s*IDLE_THRESHOLD_SECONDS\s*=\s*{_IDLE_FALLBACK}',
        re.MULTILINE,
    )
    assert pattern.search(src), (
        f"app.py must fall back to IDLE_THRESHOLD_SECONDS = {_IDLE_FALLBACK} "
        "on invalid env values (TypeError/ValueError)"
    )


def test_idle_threshold_seconds_clamped_to_safe_range():
    """Lower bound 60, upper bound 3600 (PR-CY15)."""
    src = _read(APP_PY)
    assert re.search(r'IDLE_THRESHOLD_SECONDS\s*<\s*60', src), (
        "app.py must clamp IDLE_THRESHOLD_SECONDS to a lower bound of 60"
    )
    assert re.search(
        rf'IDLE_THRESHOLD_SECONDS\s*>\s*{_IDLE_CLAMP_MAX}', src), (
        f"app.py must clamp IDLE_THRESHOLD_SECONDS to an upper bound of "
        f"{_IDLE_CLAMP_MAX}"
    )


def test_idle_threshold_seconds_clamp_evaluation():
    """Behavioural check on the env-driven block without importing app."""
    src = _read(APP_PY)
    m = re.search(
        r'try:\s*\n\s*IDLE_THRESHOLD_SECONDS\s*=\s*int\(os\.getenv\('
        rf"'IDLE_THRESHOLD_SECONDS',\s*'{_IDLE_DEFAULT}'\)\s*or\s*'{_IDLE_DEFAULT}'\)\s*\n"
        r'except\s*\(TypeError,\s*ValueError\)\s*:\s*\n'
        rf'\s*IDLE_THRESHOLD_SECONDS\s*=\s*{_IDLE_FALLBACK}\s*\n'
        r'if\s+IDLE_THRESHOLD_SECONDS\s*<\s*60\s*:\s*\n'
        r'\s*IDLE_THRESHOLD_SECONDS\s*=\s*60\s*\n'
        rf'elif\s+IDLE_THRESHOLD_SECONDS\s*>\s*{_IDLE_CLAMP_MAX}\s*:\s*\n'
        rf'\s*IDLE_THRESHOLD_SECONDS\s*=\s*{_IDLE_CLAMP_MAX}',
        src,
    )
    assert m, "Could not locate PR-CY15 env-driven IDLE_THRESHOLD_SECONDS block"

    block = m.group(0)

    def _eval_with(env_value):
        env = {} if env_value is None else {'IDLE_THRESHOLD_SECONDS': env_value}
        import types
        os_shim = types.SimpleNamespace(getenv=lambda k, d=None: env.get(k, d))
        ns = {'os': os_shim}
        exec(block, ns)  # noqa: S102
        return ns['IDLE_THRESHOLD_SECONDS']

    assert _eval_with(None) == _IDLE_FALLBACK
    assert _eval_with('300') == 300
    assert _eval_with('5') == 60
    assert _eval_with('99999') == _IDLE_CLAMP_MAX
    assert _eval_with('not-a-number') == _IDLE_FALLBACK
    assert _eval_with('') == _IDLE_FALLBACK


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
    window = src[max(0, skip_idx - 4000):skip_idx]
    assert 'key_map.get(fallback)' in window, (
        "Skipped-fallback log must follow `if key_map.get(fallback):` in the "
        "fallback iteration"
    )
    # An `else:` must appear between the `if key_map.get(fallback):` and the
    # skip-log emission, confirming the log lives in that else branch.
    if_pos = window.rfind('key_map.get(fallback)')
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
