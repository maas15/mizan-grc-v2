"""Official-shaped vs UI-shaped export of the same saved REL37 model.

New implementation evidence. Historical d2f2d5/99af805 logs do not apply.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_ENV_KEYS = (
    'ADMIN_PASSWORD', 'SECRET_KEY', 'DATABASE_PATH', 'DATABASE_URL',
    'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
    'REL2_SKIP_EXPORT_EVIDENCE', 'REL37_DATA_AI_DT_COMPILER',
)
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}

_TMP = tempfile.mkdtemp(prefix='test_rel37_official_diff_')


def _ensure_test_env():
    os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
    os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
    os.environ['SECRET_KEY'] = 'test-secret-key'
    os.environ.setdefault('DATABASE_PATH', os.path.join(_TMP, 'official_diff.db'))
    os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'official_diff.db'))
    os.environ['OPENAI_API_KEY'] = ''
    os.environ['ANTHROPIC_API_KEY'] = ''
    os.environ['GOOGLE_API_KEY'] = ''
    os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'


_ensure_test_env()

import app as app_mod  # noqa: E402

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_APPLIED_KEY,
    REL37_CANONICAL_FW_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_ORIGINAL_FW_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    apply_rel37_to_sections,
    load_model,
    rel37_bind_export_sections,
    serialize_model,
)
from release_engine_v3.rel37_export_content_parity import (  # noqa: E402
    compare_model_to_docx,
)
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections  # noqa: E402

class ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args or ()
        self.kwargs = kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)

    def join(self, timeout=None):
        return None


def tearDownModule():
    for key in ('REL2_SKIP_EXPORT_EVIDENCE', 'OPENAI_API_KEY',
                'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY'):
        previous = _ENV_BEFORE.get(key)
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def _compile_data_en():
    out, _repairs = apply_rel37_to_sections(
        {'vision': 'placeholder'},
        domain='data',
        lang='en',
        document_type='strategy',
        selected_frameworks=['ndmo', 'pdpl'],
        org_name='REL33 P1 Data Management Org',
    )
    model = load_model(out)
    if model is None:
        raise AssertionError('compile failed')
    return model


def _persist(model):
    with app_mod.app.app_context():
        db = app_mod.get_db()
        db.execute(
            'INSERT OR IGNORE INTO users '
            '(id, username, password_hash, role, is_active) '
            'VALUES (701, ?, ?, ?, 1)',
            ('rel37off701', 'x', 'user'),
        )
        sections = model_to_sections(model)
        sections[REL37_APPLIED_KEY] = '1'
        sections[REL37_MODEL_KEY] = serialize_model(model)
        sections[REL37_HASH_KEY] = model.model_hash
        sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
        sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
        sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
        sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
        content = model_to_markdown(model)
        cur = db.execute(
            'INSERT INTO strategies '
            '(user_id, domain, org_name, sector, content, language, '
            ' document_title, sections_json, content_json) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                701, 'Data Management', model.org_name, 'Government',
                content, 'en', 'Data EN official differential',
                json.dumps(sections, ensure_ascii=False),
                json.dumps({'sections': sections}, ensure_ascii=False),
            ),
        )
        sid = cur.lastrowid
        db.commit()
    client = app_mod.app.test_client()
    csrf = 'rel37-official-diff-csrf'
    with client.session_transaction() as sess:
        sess['user_id'] = 701
        sess['username'] = 'rel37off701'
        sess['role'] = 'user'
        sess['csrf_token'] = csrf
    return {
        'client': client,
        'headers': {'X-CSRFToken': csrf, 'Content-Type': 'application/json'},
        'strategy_id': sid,
        'model': model,
        'content': content,
        'sections': sections,
    }


def _export(saved, *, org_name, include_content=True, fmt='docx'):
    body = {
        'filename': f'rel37_official_{fmt}',
        'language': 'en',
        'domain': 'Data Management',
        'doc_type': 'Strategy Document',
        'document_type': 'strategy',
        'artifact_type': 'strategy',
        'generation_mode': 'drafting',
        'strategy_id': saved['strategy_id'],
        'artifact_id': saved['strategy_id'],
        'selected_frameworks': list(saved['model'].selected_frameworks),
        'org_name': org_name,
    }
    if include_content:
        body['content'] = saved['content']
    with patch('threading.Thread', ImmediateThread):
        resp = saved['client'].post(
            f'/api/generate-{fmt}-async', json=body, headers=saved['headers'])
    submit = resp.get_json(silent=True) or {}
    tid = submit.get('task_id')
    status = {}
    if tid:
        status = saved['client'].get(
            f'/api/export-status/{tid}', headers=saved['headers']
        ).get_json(silent=True) or {}
    raw = b''
    if tid and status.get('status') == 'done':
        raw = saved['client'].get(
            f'/api/export-download/{tid}', headers=saved['headers']
        ).data or b''
    return resp.status_code, submit, raw


class SavedIdentityDifferentialTests(unittest.TestCase):
    def setUp(self):
        _ensure_test_env()

    def test_official_org_suffix_mismatch_uses_saved_identity(self):
        saved = _persist(_compile_data_en())
        official_http, official_body, official_bytes = _export(
            saved, org_name='REL33 P1 Data Management')
        ui_http, ui_body, ui_bytes = _export(
            saved, org_name=saved['model'].org_name)
        self.assertEqual(official_http, 200, official_body)
        self.assertEqual(ui_http, 200, ui_body)
        self.assertTrue(official_bytes.startswith(b'PK'), official_body)
        self.assertTrue(ui_bytes.startswith(b'PK'), ui_body)
        official_blockers = compare_model_to_docx(saved['model'], official_bytes)
        ui_blockers = compare_model_to_docx(saved['model'], ui_bytes)
        self.assertEqual(official_blockers, [], official_blockers)
        self.assertEqual(ui_blockers, [], ui_blockers)

    def test_saved_id_only_does_not_need_client_canonical(self):
        saved = _persist(_compile_data_en())
        http, body, raw = _export(
            saved, org_name='client-other-org', include_content=False)
        self.assertEqual(http, 200, body)
        self.assertTrue(raw.startswith(b'PK'), body)
        self.assertEqual(compare_model_to_docx(saved['model'], raw), [])

    def test_client_org_does_not_block_saved_bind(self):
        saved = _persist(_compile_data_en())
        bound = rel37_bind_export_sections(
            saved['sections'],
            {'roadmap': 'legacy'},
            domain='data',
            lang='en',
            document_type='strategy',
            org_name='REL33 P1 Data Management',
            selected_frameworks=list(saved['model'].selected_frameworks),
        )
        # Request org may mismatch; saved-source overlay uses model identity.
        from release_engine_v3.rel37_apply import overlay_rel37_authority
        overlaid = overlay_rel37_authority(
            bound, saved['sections'], org_name='REL33 P1 Data Management')
        self.assertFalse(overlaid.get('rel37_authority_blocked'), overlaid)
        self.assertTrue(overlaid.get(REL37_MODEL_KEY))

    def test_server_hash_tamper_still_blocks(self):
        saved = _persist(_compile_data_en())
        tampered = dict(saved['sections'])
        tampered[REL37_HASH_KEY] = '0' * 64
        bound = rel37_bind_export_sections(
            tampered,
            {'roadmap': 'legacy fallback'},
            domain='data',
            lang='en',
            document_type='strategy',
            org_name=saved['model'].org_name,
            selected_frameworks=list(saved['model'].selected_frameworks),
        )
        self.assertTrue(bound.get('_rel37_render_blocked'), bound)
        self.assertNotEqual(bound.get('roadmap'), 'legacy fallback')

    def test_conflicting_ids_rejected_redundant_org_is_not(self):
        self.assertTrue(app_mod._public_pdf_identifier_conflict({
            'strategy_id': '1', 'artifact_id': '2',
        }))
        self.assertFalse(app_mod._public_pdf_identifier_conflict({
            'strategy_id': '1', 'artifact_id': '1',
            'org_name': 'other',
        }))


if __name__ == '__main__':
    unittest.main()
