"""PR-5B.8C — bounded AI provider timeout handling.

Pure-text assertions on app.py to verify the structural pieces that PR-5B.8C
adds.  Following the PR-5B.8B test pattern, these tests do NOT import app.py
(so they don't need ADMIN_PASSWORD/SECRET_KEY/DATABASE_URL shimmed) and run
fast in CI.

Covers:
  * Section A: ``AI_CALL_TIMEOUT_SECONDS`` is read from env, defaults to 120,
    and is clamped to the safe range 10–600.
  * Section B: ``ProviderTimeoutError`` exists, extends ``RuntimeError``, and
    is defined near (above) ``RepairError``.
  * Section C: every provider wrapper passes ``timeout=…`` and raises
    ``ProviderTimeoutError`` on a provider-timeout exception.  The OpenAI-
    compatible wrappers (openai/groq/deepseek) also pass ``max_retries=0``.
    Anthropic passes ``max_retries=0``.  Google passes ``request_options``
    with a ``timeout`` key.
  * Section D: ``generate_ai_content`` records timeouts in a dedicated dict
    and raises ``ProviderTimeoutError`` (not silent ``None``) when every
    attempted provider has timed out.  Fallback chain is preserved.
  * Section E: ``ai_repair_strategy_section`` catches ``ProviderTimeoutError``
    explicitly, converts it to ``RepairError`` with ``setattr(err, 'section',
    section_key)``, and re-raises.  The catch is BEFORE the existing
    ``RuntimeError`` branch (since ``ProviderTimeoutError`` extends
    ``RuntimeError``).
"""

from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_PY = os.path.join(ROOT, 'app.py')


def _read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as fh:
        return fh.read()


# ── Section A: AI_CALL_TIMEOUT_SECONDS ────────────────────────────────────────

def test_ai_call_timeout_seconds_env_with_default_120():
    src = _read(APP_PY)
    assert "os.getenv('AI_CALL_TIMEOUT_SECONDS', '120')" in src, (
        "app.py must read AI_CALL_TIMEOUT_SECONDS from env with default '120'"
    )


def test_ai_call_timeout_seconds_clamped_to_safe_range():
    src = _read(APP_PY)
    # Must clamp below 10 → 10 and above 600 → 600.
    assert re.search(r'AI_CALL_TIMEOUT_SECONDS\s*<\s*10', src), (
        "app.py must clamp AI_CALL_TIMEOUT_SECONDS to a lower bound of 10"
    )
    assert re.search(r'AI_CALL_TIMEOUT_SECONDS\s*>\s*600', src), (
        "app.py must clamp AI_CALL_TIMEOUT_SECONDS to an upper bound of 600"
    )


def test_ai_call_timeout_seconds_attribute_on_config():
    src = _read(APP_PY)
    # Sits inside class Config.
    cls_pos = src.find('class Config:')
    attr_pos = src.find('AI_CALL_TIMEOUT_SECONDS')
    assert cls_pos > 0 and attr_pos > cls_pos, (
        "AI_CALL_TIMEOUT_SECONDS must be defined inside class Config"
    )


# ── Section B: ProviderTimeoutError ──────────────────────────────────────────

def test_provider_timeout_error_class_defined():
    src = _read(APP_PY)
    assert re.search(
        r'class\s+ProviderTimeoutError\s*\(\s*RuntimeError\s*\)\s*:',
        src,
    ), "ProviderTimeoutError(RuntimeError) must be defined in app.py"


def test_provider_timeout_error_message_is_sanitized():
    src = _read(APP_PY)
    # The class must mention 'sanitized' or otherwise document that no API
    # keys / raw provider payloads are emitted.  Loose check: docstring or
    # nearby comment must include 'sanitized' or 'no API keys'.
    cls_idx = src.find('class ProviderTimeoutError(')
    assert cls_idx > 0
    block = src[cls_idx:cls_idx + 2000]
    assert ('sanitized' in block.lower()
            or 'no api keys' in block.lower()), (
        "ProviderTimeoutError docstring/comment must document the "
        "sanitized message contract (no API keys, no raw payloads)"
    )


def test_provider_timeout_error_carries_provider_and_timeout():
    src = _read(APP_PY)
    cls_idx = src.find('class ProviderTimeoutError(')
    block = src[cls_idx:cls_idx + 2500]
    assert 'self.provider' in block, (
        "ProviderTimeoutError must store provider on the exception"
    )
    assert 'self.timeout_seconds' in block, (
        "ProviderTimeoutError must store timeout_seconds on the exception"
    )


# ── Section C: provider wrappers patched ─────────────────────────────────────

def _slice_function(src: str, defn: str) -> str:
    start = src.index(defn)
    # Stop at next top-level def/class or end of file.
    rest = src[start + len(defn):]
    m = re.search(r'\n(?=def\s|class\s)', rest)
    end = start + len(defn) + (m.start() if m else len(rest))
    return src[start:end]


def test_openai_wrapper_uses_timeout_and_no_retries():
    src = _read(APP_PY)
    body = _slice_function(src, 'def _generate_openai(')
    assert 'config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'timeout=_to' in body or 'timeout=config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'max_retries=0' in body
    assert "raise ProviderTimeoutError('openai'" in body


def test_anthropic_wrapper_uses_timeout_and_no_retries():
    src = _read(APP_PY)
    body = _slice_function(src, 'def _generate_anthropic(')
    assert 'config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'timeout=_to' in body or 'timeout=config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'max_retries=0' in body
    assert "raise ProviderTimeoutError('anthropic'" in body


def test_google_wrapper_uses_request_options_timeout():
    src = _read(APP_PY)
    body = _slice_function(src, 'def _generate_google(')
    assert 'request_options' in body, (
        "_generate_google must forward a request_options dict containing 'timeout'"
    )
    assert '"timeout"' in body or "'timeout'" in body
    assert "raise ProviderTimeoutError('google'" in body


def test_groq_wrapper_uses_timeout_and_no_retries():
    src = _read(APP_PY)
    body = _slice_function(src, 'def _generate_groq(')
    assert 'config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'timeout=_to' in body
    assert 'max_retries=0' in body
    assert "raise ProviderTimeoutError('groq'" in body


def test_deepseek_wrapper_uses_timeout_and_no_retries():
    src = _read(APP_PY)
    body = _slice_function(src, 'def _generate_deepseek(')
    assert 'config.AI_CALL_TIMEOUT_SECONDS' in body
    assert 'timeout=_to' in body
    assert 'max_retries=0' in body
    assert "raise ProviderTimeoutError('deepseek'" in body


# ── Section D: generate_ai_content ───────────────────────────────────────────

def test_generate_ai_content_tracks_provider_timeouts():
    src = _read(APP_PY)
    body = _slice_function(src, 'def generate_ai_content(')
    assert '_provider_timeouts' in body, (
        "generate_ai_content must track timeouts in a dedicated dict so the "
        "all-providers-failed branch can distinguish timeouts from other failures"
    )
    # The primary-attempt try/except and the fallback try/except must both
    # have an `except ProviderTimeoutError` branch.
    assert body.count('except ProviderTimeoutError') >= 2, (
        "generate_ai_content must catch ProviderTimeoutError on both the "
        "primary attempt and the fallback chain attempts"
    )


def test_generate_ai_content_raises_provider_timeout_when_all_timeout():
    src = _read(APP_PY)
    body = _slice_function(src, 'def generate_ai_content(')
    # When _provider_timeouts is non-empty after the chain, a
    # ProviderTimeoutError must be raised (no silent None return, no
    # silent simulation fallback for the all-timeout case).
    assert re.search(
        r'if\s+_provider_timeouts\s*:\s*\n.*?raise\s+ProviderTimeoutError\(',
        body,
        flags=re.DOTALL,
    ), (
        "generate_ai_content must raise ProviderTimeoutError when at least "
        "one provider in the exhausted chain timed out"
    )


def test_generate_ai_content_no_silent_none_for_timeouts():
    """Sanity: the simulation-fallback return must be guarded behind the
    timeout check, so an all-timeout failure cannot fall through to
    generate_simulation_content silently."""
    src = _read(APP_PY)
    body = _slice_function(src, 'def generate_ai_content(')
    raise_idx = -1
    m = re.search(r"raise\s+ProviderTimeoutError\(\s*['\"]all['\"]", body)
    if m:
        raise_idx = m.start()
    # The relevant simulation_content fallback is the LAST one in the
    # function (the early no-provider-configured branch returns simulation
    # content before any provider call is made and is intentionally
    # unaffected by timeouts).
    sim_idx = body.rfind('return generate_simulation_content(')
    assert raise_idx > 0 and sim_idx > raise_idx, (
        "All-timeout ProviderTimeoutError must be raised BEFORE the "
        "tail simulation-content fallback so timeouts never silently simulate"
    )


# ── Section E: ai_repair_strategy_section conversion ─────────────────────────

def test_ai_repair_section_converts_provider_timeout_to_repair_error():
    src = _read(APP_PY)
    body = _slice_function(src, 'def ai_repair_strategy_section(')
    # Must catch ProviderTimeoutError BEFORE the broad RuntimeError branch
    # (because ProviderTimeoutError IS a RuntimeError subclass).
    pte_idx = body.find('except ProviderTimeoutError')
    rte_idx = body.find('except RuntimeError')
    assert pte_idx > 0, (
        "ai_repair_strategy_section must catch ProviderTimeoutError"
    )
    assert rte_idx > pte_idx, (
        "ai_repair_strategy_section must catch ProviderTimeoutError BEFORE "
        "RuntimeError, otherwise the ProviderTimeoutError branch is dead code"
    )
    # Must re-raise as RepairError tagged with section_key.
    block = body[pte_idx:rte_idx]
    assert 'RepairError(' in block, "must re-raise as RepairError"
    assert re.search(
        r"setattr\(\s*\w+\s*,\s*['\"]section['\"]\s*,\s*section_key\s*\)",
        block,
    ), (
        "must setattr(err, 'section', section_key) so _mark_synth_failed routes correctly"
    )
