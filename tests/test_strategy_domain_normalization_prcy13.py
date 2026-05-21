"""PR-CY13 — Strategy task lifecycle must normalize domain names.

Covers the runtime race documented in the PR-CY13 problem statement:

* Backend stores ``callback_domain='Cyber Security'`` via
  ``create_background_task`` (English-normalized in
  ``api_generate_strategy_async`` after ``normalize_domain_strict``).
* Frontend recovery hits ``/api/strategy/latest?domain=الأمن السيبراني``
  (Arabic display name).
* Old behaviour: exact-equality lookup → 404 even though a task is still
  pending → frontend showed the misleading "انتهت مهلة الإنشاء" toast.
* New behaviour (PR-CY13): both ``find_active_strategy_task`` and
  ``ensure_latest_strategy_recoverable`` normalize via
  ``_strategy_domain_canonical`` so any equivalent variant matches.

Equivalence classes (all six strategy domains):

  Cyber Security == الأمن السيبراني == cyber == cybersecurity == cyber_security
  Data Management == إدارة البيانات == data == data_management
  Artificial Intelligence == الذكاء الاصطناعي == ai == artificial_intelligence
  Digital Transformation == التحول الرقمي == dt == digital_transformation
  Enterprise Risk Management == إدارة المخاطر المؤسسية == erm == enterprise_risk_management
  Global Standards == المعايير العالمية == global == global_standards

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


# ────────────────────── Source-level assertions ───────────────────────────


def test_helper_defined_and_does_not_default_to_cyber():
    src = _read(APP_PY)
    assert 'def _strategy_domain_canonical(' in src, (
        'PR-CY13 helper _strategy_domain_canonical must be defined'
    )
    m = re.search(
        r"def _strategy_domain_canonical\(raw\):.*?\n\n\ndef ",
        src, re.DOTALL,
    )
    assert m, 'helper body not extractable'
    body = m.group(0)
    # Must NOT default to 'cyber' for unknown input — that would cause
    # find_active_strategy_task to coerce unrelated rows into a match.
    assert 'return None' in body
    assert "return 'cyber'" not in body
    assert 'return "cyber"' not in body


def test_find_active_strategy_task_uses_canonical_normalization():
    src = _read(APP_PY)
    m = re.search(
        r"def find_active_strategy_task\(user_id, domain\):.*?"
        r"\ndef delete_background_task\(",
        src, re.DOTALL,
    )
    assert m, 'find_active_strategy_task not found'
    body = m.group(0)
    assert '_strategy_domain_canonical(domain)' in body, (
        'find_active_strategy_task must normalize the lookup domain'
    )
    assert '_strategy_domain_canonical(cb)' in body, (
        'find_active_strategy_task must normalize each candidate row'
    )


def test_ensure_latest_strategy_recoverable_uses_canonical_normalization():
    src = _read(APP_PY)
    m = re.search(
        r"def ensure_latest_strategy_recoverable\(.*?"
        r"\ndef run_ai_task\(",
        src, re.DOTALL,
    )
    assert m, 'ensure_latest_strategy_recoverable not found'
    body = m.group(0)
    assert '_strategy_domain_canonical(domain)' in body
    assert '_strategy_domain_canonical(cd)' in body


def test_cybersecurity_alias_added_to_domain_code_map():
    src = _read(APP_PY)
    # Restrict the assertion to the registry block to avoid matching
    # log strings or comments elsewhere.
    m = re.search(
        r"_DOMAIN_CODE_MAP: dict = \{(.*?)\n\}",
        src, re.DOTALL,
    )
    assert m, '_DOMAIN_CODE_MAP not found'
    block = m.group(1)
    assert '"cybersecurity": "cyber"' in block
    assert '"Cybersecurity": "cyber"' in block


# ────────────────────── Behavioural assertions ────────────────────────────
# Load only the bits we need from app.py without importing the whole Flask
# app (which requires env-vars and DB bootstrap).


def _load_helpers():
    """Extract _DOMAIN_CODE_MAP + _strategy_domain_canonical into a
    sandbox module so we can call the helper without booting Flask.

    Approach: read app.py as text, slice out the definitions of the
    canonical registry and the helper, exec them into a fresh namespace.
    """
    src = _read(APP_PY)
    map_match = re.search(
        r"^_DOMAIN_CODE_MAP: dict = \{.*?^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    helper_match = re.search(
        r"^def _strategy_domain_canonical\(raw\):.*?(?=\n\ndef )",
        src, re.DOTALL | re.MULTILINE,
    )
    assert map_match and helper_match
    ns = {}
    exec(map_match.group(0), ns)
    exec(helper_match.group(0), ns)
    return ns


def test_canonical_helper_collapses_all_strategy_domain_variants():
    ns = _load_helpers()
    canonical = ns['_strategy_domain_canonical']
    cases = {
        'cyber': [
            'Cyber Security', 'cyber security', 'الأمن السيبراني',
            'cyber', 'cybersecurity', 'Cybersecurity', 'CyberSecurity',
            'cyber_security', 'CYBER',
        ],
        'data': [
            'Data Management', 'data management', 'إدارة البيانات',
            'data', 'data_management', 'DATA',
        ],
        'ai': [
            'Artificial Intelligence', 'artificial intelligence',
            'الذكاء الاصطناعي', 'ai', 'AI', 'artificial_intelligence',
        ],
        'dt': [
            'Digital Transformation', 'digital transformation',
            'التحول الرقمي', 'dt', 'DT', 'digital_transformation',
        ],
        'erm': [
            'Enterprise Risk Management', 'enterprise risk management',
            'إدارة المخاطر المؤسسية', 'erm', 'ERM',
            'enterprise_risk_management',
        ],
        'global': [
            'Global Standards', 'global standards',
            'المعايير العالمية', 'global', 'global_standards',
        ],
    }
    for code, variants in cases.items():
        for v in variants:
            assert canonical(v) == code, (
                f'{v!r} should normalize to {code!r}, got {canonical(v)!r}'
            )


def test_canonical_helper_returns_none_for_unknown_or_empty():
    ns = _load_helpers()
    canonical = ns['_strategy_domain_canonical']
    for bad in (None, '', '   ', 123, 'NotADomain', 'random text'):
        assert canonical(bad) is None, f'{bad!r} should not match any domain'


# ────────────────────── DB-level integration ──────────────────────────────


def _load_lookup_helpers_with_db(monkeypatch_db_path):
    """Build a mini-namespace containing find_active_strategy_task and
    ensure_latest_strategy_recoverable wired against an isolated SQLite
    DB file. We patch ``get_db_direct`` to point at a freshly-created
    schema so the helpers can run without Flask config.
    """
    src = _read(APP_PY)
    map_match = re.search(
        r"^_DOMAIN_CODE_MAP: dict = \{.*?^\}",
        src, re.DOTALL | re.MULTILINE,
    )
    helper_match = re.search(
        r"^def _strategy_domain_canonical\(raw\):.*?(?=\n\ndef )",
        src, re.DOTALL | re.MULTILINE,
    )
    find_match = re.search(
        r"^def find_active_strategy_task\(user_id, domain\):.*?"
        r"(?=\n\ndef delete_background_task\()",
        src, re.DOTALL | re.MULTILINE,
    )
    ensure_match = re.search(
        r"^def ensure_latest_strategy_recoverable\(.*?"
        r"(?=\n\ndef run_ai_task\()",
        src, re.DOTALL | re.MULTILINE,
    )
    assert all((map_match, helper_match, find_match, ensure_match))

    db_path = monkeypatch_db_path

    # Mini schema covering only the columns the helpers SELECT.
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            'CREATE TABLE background_tasks ('
            'task_id TEXT PRIMARY KEY, user_id INTEGER, status TEXT, '
            'result TEXT, error TEXT, callback_domain TEXT, '
            "stage TEXT, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute(
            'CREATE TABLE strategies ('
            'id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, '
            'domain TEXT, sections_json TEXT, content_json TEXT, '
            'content TEXT, language TEXT, document_title TEXT, '
            'created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)'
        )
        conn.commit()

    # Build the sandbox namespace.
    from contextlib import closing as _closing

    def _get_db():
        c = sqlite3.connect(db_path)
        c.row_factory = sqlite3.Row
        return c

    ns = {
        'closing': _closing,
        'get_db_direct': _get_db,
        'sqlite3': sqlite3,
        'print': lambda *a, **kw: None,  # silence helper logs in tests
    }
    exec(map_match.group(0), ns)
    exec(helper_match.group(0), ns)
    exec(find_match.group(0), ns)
    exec(ensure_match.group(0), ns)
    return ns


def test_find_active_strategy_task_matches_arabic_when_stored_english(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    # Simulate what create_background_task writes:
    # api_generate_strategy_async always normalizes to canonical EN.
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            'INSERT INTO background_tasks (task_id, user_id, status, '
            'callback_domain) VALUES (?, ?, ?, ?)',
            ('task-cyber-01', 2, 'pending', 'Cyber Security'),
        )
        conn.commit()
    # Frontend recovery sends Arabic domain — must still match.
    assert ns['find_active_strategy_task'](2, 'الأمن السيبراني') == 'task-cyber-01'
    # And short codes / slugs / cybersecurity alias.
    assert ns['find_active_strategy_task'](2, 'cyber') == 'task-cyber-01'
    assert ns['find_active_strategy_task'](2, 'cybersecurity') == 'task-cyber-01'
    assert ns['find_active_strategy_task'](2, 'cyber_security') == 'task-cyber-01'


def test_find_active_strategy_task_does_not_match_other_domains(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            'INSERT INTO background_tasks (task_id, user_id, status, '
            'callback_domain) VALUES (?, ?, ?, ?)',
            ('task-data-01', 2, 'pending', 'Data Management'),
        )
        conn.commit()
    # Cyber lookup must not collide with a data task.
    assert ns['find_active_strategy_task'](2, 'الأمن السيبراني') is None
    # But Arabic data lookup must match the data task.
    assert ns['find_active_strategy_task'](2, 'إدارة البيانات') == 'task-data-01'


def test_find_active_strategy_task_skips_terminal_tasks(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            'INSERT INTO background_tasks (task_id, user_id, status, '
            'callback_domain) VALUES (?, ?, ?, ?)',
            ('task-done', 2, 'done', 'Cyber Security'),
        )
        conn.execute(
            'INSERT INTO background_tasks (task_id, user_id, status, '
            'callback_domain) VALUES (?, ?, ?, ?)',
            ('task-error', 2, 'error', 'Cyber Security'),
        )
        conn.commit()
    assert ns['find_active_strategy_task'](2, 'الأمن السيبراني') is None


def test_ensure_latest_strategy_recoverable_cross_language(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    with sqlite3.connect(str(db)) as conn:
        # Strategy stored with the Arabic display name.
        conn.execute(
            'INSERT INTO strategies (user_id, domain, content, language) '
            'VALUES (?, ?, ?, ?)',
            (2, 'الأمن السيبراني', 'cyber-content', 'ar'),
        )
        conn.commit()
    # Recovery using English form must still find it.
    row, _ = ns['ensure_latest_strategy_recoverable'](
        2, 'Cyber Security', max_retries=1, retry_delay_seconds=0
    )
    assert row is not None
    assert row['content'] == 'cyber-content'
    # And via short code / cybersecurity alias.
    row, _ = ns['ensure_latest_strategy_recoverable'](
        2, 'cybersecurity', max_retries=1, retry_delay_seconds=0
    )
    assert row is not None and row['content'] == 'cyber-content'


def test_ensure_latest_strategy_recoverable_picks_most_recent_matching(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    with sqlite3.connect(str(db)) as conn:
        # Older cyber strategy.
        conn.execute(
            'INSERT INTO strategies (user_id, domain, content, language, '
            'created_at) VALUES (?, ?, ?, ?, ?)',
            (2, 'Cyber Security', 'old-cyber', 'en', '2024-01-01 00:00:00'),
        )
        # Unrelated newer data strategy — must be skipped.
        conn.execute(
            'INSERT INTO strategies (user_id, domain, content, language, '
            'created_at) VALUES (?, ?, ?, ?, ?)',
            (2, 'إدارة البيانات', 'new-data', 'ar', '2025-06-01 00:00:00'),
        )
        # Newer cyber strategy stored under Arabic — should be picked.
        conn.execute(
            'INSERT INTO strategies (user_id, domain, content, language, '
            'created_at) VALUES (?, ?, ?, ?, ?)',
            (2, 'الأمن السيبراني', 'new-cyber', 'ar', '2025-12-01 00:00:00'),
        )
        conn.commit()
    row, _ = ns['ensure_latest_strategy_recoverable'](
        2, 'Cyber Security', max_retries=1, retry_delay_seconds=0
    )
    assert row is not None
    assert row['content'] == 'new-cyber', (
        'must skip newer non-cyber row and prefer most recent cyber row '
        'regardless of stored language'
    )


def test_ensure_latest_strategy_recoverable_returns_none_when_no_match(tmp_path):
    db = tmp_path / 'mini.db'
    ns = _load_lookup_helpers_with_db(str(db))
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            'INSERT INTO strategies (user_id, domain, content, language) '
            'VALUES (?, ?, ?, ?)',
            (2, 'Data Management', 'd', 'en'),
        )
        conn.commit()
    row, attempts = ns['ensure_latest_strategy_recoverable'](
        2, 'الأمن السيبراني', max_retries=2, retry_delay_seconds=0
    )
    assert row is None
    assert attempts == 2
