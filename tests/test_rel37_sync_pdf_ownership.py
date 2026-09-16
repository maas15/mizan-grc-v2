"""Local read-only tracing of public /api/generate-pdf ownership.

Does not change authentication or ownership policy. Uses isolated users
and a tracked REL37 fixture. No provider calls.
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_ENV_KEYS = (
    'ADMIN_PASSWORD', 'SECRET_KEY', 'DATABASE_PATH', 'DATABASE_URL',
    'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
    'REL2_SKIP_EXPORT_EVIDENCE', 'REL37_DATA_AI_DT_COMPILER',
)
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}

_TMP = tempfile.mkdtemp(prefix='test_rel37_sync_pdf_')
os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'rel37_sync_pdf.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'rel37_sync_pdf.db')
os.environ['OPENAI_API_KEY'] = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)

import app as app_mod  # noqa: E402

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_APPLIED_KEY,
    REL37_CANONICAL_FW_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_ORIGINAL_FW_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    serialize_model,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_export_content_parity import extract_pdf_text  # noqa: E402
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections  # noqa: E402

FIXTURE = ROOT / 'tests' / 'fixtures' / 'rel37' / 'data_en_saved_canonical_model.json'
DELIVERABLE = 'Approved NDMO policy'


def tearDownModule():
    for key, previous in _ENV_BEFORE.items():
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def _load_model() -> CanonicalDocument:
    model = CanonicalDocument.from_dict(
        json.loads(FIXTURE.read_text(encoding='utf-8')))
    if not model.model_hash:
        model.compute_hashes()
    return model


def _sections(model: CanonicalDocument) -> dict:
    sections = model_to_sections(model)
    sections[REL37_APPLIED_KEY] = '1'
    sections[REL37_MODEL_KEY] = serialize_model(model)
    sections[REL37_HASH_KEY] = model.model_hash
    sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
    sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
    sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
    return sections


def _make_user(uid: int, username: str):
    with app_mod.app.app_context():
        db = app_mod.get_db()
        db.execute(
            'INSERT OR IGNORE INTO users '
            '(id, username, password_hash, role, is_active) '
            'VALUES (?, ?, ?, ?, 1)',
            (uid, username, 'x', 'user'),
        )
        db.commit()
    client = app_mod.app.test_client()
    csrf = f'sync-pdf-csrf-{uid}'
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = username
        sess['role'] = 'user'
        sess['csrf_token'] = csrf
    headers = {'X-CSRFToken': csrf, 'Content-Type': 'application/json'}
    return client, headers


def _persist_for(uid: int, username: str, model: CanonicalDocument) -> dict:
    client, headers = _make_user(uid, username)
    sections = _sections(model)
    content = model_to_markdown(model)
    with app_mod.app.app_context():
        db = app_mod.get_db()
        cur = db.execute(
            'INSERT INTO strategies '
            '(user_id, domain, org_name, sector, content, language, '
            ' document_title, sections_json, content_json) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                uid, 'Data Management', model.org_name, 'Government',
                content, 'en', 'Data EN ownership fixture',
                json.dumps(sections, ensure_ascii=False),
                json.dumps({'sections': sections}, ensure_ascii=False),
            ),
        )
        sid = cur.lastrowid
        db.commit()
    return {
        'uid': uid,
        'username': username,
        'client': client,
        'headers': headers,
        'strategy_id': sid,
        'sections': sections,
        'content': content,
        'model': model,
    }


def _pdf_body(saved, *, extra=None, strategy_id=None, artifact_id=None):
    body = {
        'content': saved['content'],
        'filename': 'sync_pdf_ownership',
        'language': 'en',
        'domain': 'Data Management',
        'doc_type': 'Strategy Document',
        'document_type': 'strategy',
        'artifact_type': 'strategy',
        'generation_mode': 'drafting',
        'strategy_id': saved['strategy_id'] if strategy_id is None else strategy_id,
        'artifact_id': saved['strategy_id'] if artifact_id is None else artifact_id,
        'selected_frameworks': list(saved['model'].selected_frameworks),
        'frameworks': list(saved['model'].selected_frameworks),
        'org_name': saved['model'].org_name,
        'sections': saved['sections'],
        '_rel37_source_sections': saved['sections'],
    }
    if extra:
        body.update(extra)
    return body


def _looks_like_pdf(raw: bytes) -> bool:
    return bool(raw) and raw.startswith(b'%PDF')


def _response_payload(resp):
    raw = resp.data or b''
    json_body = {}
    if not _looks_like_pdf(raw):
        json_body = resp.get_json(silent=True) or {}
    return raw, json_body


class SyncPdfOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = _load_model()
        cls.owner = _persist_for(3101, 'rel37ownerA', cls.model)
        cls.other_client, cls.other_headers = _make_user(3102, 'rel37userB')

    def test_owner_can_export_own_artifact(self):
        resp = self.owner['client'].post(
            '/api/generate-pdf',
            json=_pdf_body(self.owner),
            headers=self.owner['headers'],
        )
        raw, payload = _response_payload(resp)
        self.assertEqual(resp.status_code, 200, payload)
        self.assertTrue(_looks_like_pdf(raw), raw[:40])
        text, meta = extract_pdf_text(raw)
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn(DELIVERABLE, text)

    def test_unauthenticated_gets_no_file(self):
        anon = app_mod.app.test_client()
        resp = anon.post(
            '/api/generate-pdf',
            json=_pdf_body(self.owner),
            headers={'Content-Type': 'application/json', 'X-CSRFToken': 'x'},
        )
        self.assertEqual(resp.status_code, 401)
        body = resp.get_json(silent=True) or {}
        self.assertNotEqual(body.get('reason'), 'csrf_invalid')
        self.assertFalse(_looks_like_pdf(resp.data or b''))

    def test_other_user_artifact_id_only(self):
        body = _pdf_body(self.owner)
        body['content'] = 'unrelated placeholder content for user B'
        body.pop('_rel37_source_sections', None)
        body.pop('sections', None)
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw = resp.data or b''
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        leaked = DELIVERABLE in text
        self.assertFalse(
            resp.status_code == 200 and leaked,
            f'B obtained owner deliverable via artifact_id '
            f'status={resp.status_code} reason={(resp.get_json(silent=True) or {}).get("reason")}',
        )
        if resp.status_code == 403:
            reason = (resp.get_json(silent=True) or {}).get('reason')
            self.assertNotEqual(reason, 'csrf_invalid')
            self.assertFalse(_looks_like_pdf(raw))

    def test_other_user_copied_snapshot_and_hash(self):
        body = _pdf_body(self.owner)
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw = resp.data or b''
        payload = resp.get_json(silent=True) or {}
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        leaked = DELIVERABLE in text
        self.assertFalse(
            resp.status_code == 200 and leaked,
            'B obtained owner content from a copied REL37 snapshot/hash; '
            f'status={resp.status_code} reason={payload.get("reason")}',
        )
        if resp.status_code == 403:
            self.assertNotEqual(payload.get('reason'), 'csrf_invalid')
            self.assertFalse(_looks_like_pdf(raw))

    def test_other_user_internal_looking_flags(self):
        body = _pdf_body(self.owner, extra={
            '_rel26_internal': True,
            'skip_rel26_gate': True,
            '_rel2_evidence_collect': True,
            '_rel31_evidence_internal': True,
        })
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw = resp.data or b''
        payload = resp.get_json(silent=True) or {}
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        leaked = DELIVERABLE in text
        self.assertFalse(
            resp.status_code == 200 and leaked,
            'B obtained owner content using client internal-looking flags; '
            f'status={resp.status_code} reason={payload.get("reason")}',
        )
        if resp.status_code == 403:
            self.assertNotEqual(payload.get('reason'), 'csrf_invalid')
            self.assertFalse(_looks_like_pdf(raw))

    def test_other_user_snapshot_only_conflicting_id(self):
        body = _pdf_body(self.owner, strategy_id=999999, artifact_id=999999)
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw = resp.data or b''
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        self.assertFalse(
            resp.status_code == 200 and DELIVERABLE in text,
            'B obtained owner content from snapshot-only/conflicting IDs',
        )

    def test_internal_reentry_from_authorized_server_source(self):
        backend = app_mod._rel2_backend_callables()
        builder = backend.get('build_pdf_bytes')
        self.assertTrue(callable(builder))
        raw = builder(
            self.owner['content'],
            'en',
            sections=self.owner['sections'],
            metadata={
                'org_name': self.owner['model'].org_name,
                'strategy_id': self.owner['strategy_id'],
                'artifact_id': self.owner['strategy_id'],
                'document_type': 'strategy',
                'model_hash': self.owner['model'].model_hash,
                'selected_frameworks': list(self.owner['model'].selected_frameworks),
            },
            selected_frameworks=list(self.owner['model'].selected_frameworks),
            domain='data',
        )
        self.assertTrue(_looks_like_pdf(raw or b''), (raw or b'')[:40])
        text, meta = extract_pdf_text(raw)
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn(DELIVERABLE, text)


if __name__ == '__main__':
    unittest.main()
