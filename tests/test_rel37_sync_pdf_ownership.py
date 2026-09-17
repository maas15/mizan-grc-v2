"""Local security regressions for public /api/generate-pdf ownership.

Uses isolated users, a local database, valid CSRF, and the tracked REL37
fixture. No provider or live-service calls.

Two evidence questions are kept separate:
A. Copied-snapshot / authority spoofing (client content already in B's body).
B. Server-held marker disclosure (marker never sent in B's request).
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
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}

# Required evidence must be enabled before application import.
if os.environ.get('REL2_SKIP_EXPORT_EVIDENCE', '').strip() == '1':
    raise RuntimeError(
        'REL2_SKIP_EXPORT_EVIDENCE must not be set for sync PDF '
        'ownership acceptance')
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)

_TMP = tempfile.mkdtemp(prefix='test_rel37_sync_pdf_')
os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'rel37_sync_pdf.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'rel37_sync_pdf.db')
os.environ['OPENAI_API_KEY'] = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

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
SERVER_MARKER = 'REL37_SERVER_ONLY_MARKER_A_7f3c'
TAMPER_MARK = 'REL37_CLIENT_TAMPER_CELL_9e2a'
INTERNAL_FLAGS = (
    '_rel26_internal',
    'skip_rel26_gate',
    '_rel2_evidence_collect',
    '_rel31_evidence_internal',
)


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
    server_sections = dict(sections)
    server_sections['vision'] = (
        str(server_sections.get('vision') or '') + '\n' + SERVER_MARKER)
    db_content = content + '\n\n' + SERVER_MARKER
    with app_mod.app.app_context():
        db = app_mod.get_db()
        cur = db.execute(
            'INSERT INTO strategies '
            '(user_id, domain, org_name, sector, content, language, '
            ' document_title, sections_json, content_json) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                uid, 'Data Management', model.org_name, 'Government',
                db_content, 'en', 'Data EN ownership fixture',
                json.dumps(server_sections, ensure_ascii=False),
                json.dumps({'sections': server_sections}, ensure_ascii=False),
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


def _assert_ownership_denied(test, resp, *, render_before):
    raw, payload = _response_payload(resp)
    test.assertEqual(resp.status_code, 403, payload)
    test.assertEqual(payload.get('reason'), 'cross_user_export_denied', payload)
    test.assertNotEqual(payload.get('reason'), 'csrf_invalid')
    test.assertFalse(_looks_like_pdf(raw), raw[:40])
    test.assertNotIn(b'%PDF', raw[:8])
    test.assertEqual(
        app_mod._SYNC_PDF_RENDER_EVENTS[render_before:],
        [],
        app_mod._SYNC_PDF_RENDER_EVENTS[render_before:],
    )


class SyncPdfOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = _load_model()
        cls.owner = _persist_for(3101, 'rel37ownerA', cls.model)
        cls.other_client, cls.other_headers = _make_user(3102, 'rel37userB')

    def setUp(self):
        app_mod._SYNC_PDF_RENDER_EVENTS.clear()

    def test_evidence_skip_is_not_active(self):
        self.assertNotEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')
        self.assertFalse(bool(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE')))
        self.assertFalse(
            app_mod._is_internal_rel_export_request({
                '_rel26_internal': True,
                'skip_rel26_gate': True,
                '_rel2_evidence_collect': True,
                '_rel31_evidence_internal': True,
            })
        )

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
        self.assertIn(SERVER_MARKER, text)
        self.assertTrue(app_mod._SYNC_PDF_RENDER_EVENTS)

    def test_owner_async_pdf_status_download(self):
        with patch('threading.Thread', ImmediateThread):
            resp = self.owner['client'].post(
                '/api/generate-pdf-async',
                json=_pdf_body(self.owner),
                headers=self.owner['headers'],
            )
        submit = resp.get_json(silent=True) or {}
        self.assertEqual(resp.status_code, 200, submit)
        tid = submit.get('task_id')
        self.assertTrue(tid)
        status = self.owner['client'].get(
            f'/api/export-status/{tid}', headers=self.owner['headers']
        ).get_json(silent=True) or {}
        self.assertEqual(status.get('status'), 'done', status)
        dl = self.owner['client'].get(
            f'/api/export-download/{tid}', headers=self.owner['headers'])
        self.assertEqual(dl.status_code, 200)
        self.assertTrue(_looks_like_pdf(dl.data or b''), (dl.data or b'')[:40])
        text, meta = extract_pdf_text(dl.data)
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn(DELIVERABLE, text)
        self.assertIn(SERVER_MARKER, text)

    def test_unauthenticated_gets_no_file(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
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
        self.assertEqual(app_mod._SYNC_PDF_RENDER_EVENTS[before:], [])

    def test_stale_csrf_denied(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
        headers = dict(self.owner['headers'])
        headers['X-CSRFToken'] = 'stale-csrf-token'
        resp = self.owner['client'].post(
            '/api/generate-pdf',
            json=_pdf_body(self.owner),
            headers=headers,
        )
        raw, payload = _response_payload(resp)
        self.assertEqual(resp.status_code, 403, payload)
        self.assertEqual(payload.get('reason'), 'csrf_invalid', payload)
        self.assertFalse(_looks_like_pdf(raw))
        self.assertEqual(app_mod._SYNC_PDF_RENDER_EVENTS[before:], [])

    def test_other_user_artifact_id_only(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
        body = _pdf_body(self.owner)
        body['content'] = 'unrelated placeholder content for user B'
        body.pop('_rel37_source_sections', None)
        body.pop('sections', None)
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        _assert_ownership_denied(self, resp, render_before=before)
        raw = resp.data or b''
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        self.assertNotIn(SERVER_MARKER, text)
        self.assertNotIn(DELIVERABLE, text)

    def test_other_user_copied_snapshot_and_hash(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
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
        _assert_ownership_denied(self, resp, render_before=before)

    def test_other_user_cannot_retrieve_server_only_marker(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
        body = _pdf_body(self.owner)
        self.assertNotIn(SERVER_MARKER, body['content'])
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw, payload = _response_payload(resp)
        text = ''
        if _looks_like_pdf(raw):
            text, _meta = extract_pdf_text(raw)
        self.assertNotIn(SERVER_MARKER, text)
        _assert_ownership_denied(self, resp, render_before=before)
        self.assertEqual(payload.get('reason'), 'cross_user_export_denied')

    def test_other_user_internal_looking_flags(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
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
        _assert_ownership_denied(self, resp, render_before=before)

    def test_each_internal_flag_rejected_alone(self):
        for flag in INTERNAL_FLAGS:
            with self.subTest(flag=flag):
                before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
                body = _pdf_body(self.owner, extra={flag: True})
                resp = self.other_client.post(
                    '/api/generate-pdf', json=body, headers=self.other_headers)
                _assert_ownership_denied(self, resp, render_before=before)

    def test_other_user_snapshot_only_conflicting_id(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
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
        self.assertNotIn(SERVER_MARKER, text)
        _assert_ownership_denied(self, resp, render_before=before)

    def test_conflicting_identifiers_rejected(self):
        before = len(app_mod._SYNC_PDF_RENDER_EVENTS)
        body = _pdf_body(
            self.owner,
            strategy_id=self.owner['strategy_id'],
            artifact_id=999999,
        )
        resp = self.other_client.post(
            '/api/generate-pdf', json=body, headers=self.other_headers)
        raw, payload = _response_payload(resp)
        self.assertEqual(resp.status_code, 400, payload)
        self.assertEqual(payload.get('reason'), 'conflicting_export_identifiers')
        self.assertFalse(_looks_like_pdf(raw))
        self.assertEqual(app_mod._SYNC_PDF_RENDER_EVENTS[before:], [])

    def test_owner_tampered_client_source_uses_server_authority(self):
        body = _pdf_body(self.owner)
        body['content'] = TAMPER_MARK + '\n# Vision\nforged client snapshot'
        body['sections'] = {'vision': TAMPER_MARK}
        body['_rel37_source_sections'] = {'vision': TAMPER_MARK}
        resp = self.owner['client'].post(
            '/api/generate-pdf', json=body, headers=self.owner['headers'])
        raw, payload = _response_payload(resp)
        self.assertEqual(resp.status_code, 200, payload)
        self.assertTrue(_looks_like_pdf(raw), raw[:40])
        text, meta = extract_pdf_text(raw)
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn(SERVER_MARKER, text)
        self.assertIn(DELIVERABLE, text)
        self.assertNotIn(TAMPER_MARK, text)

    def test_other_user_cannot_poll_or_download_owner_export(self):
        with patch('threading.Thread', ImmediateThread):
            resp = self.owner['client'].post(
                '/api/generate-pdf-async',
                json=_pdf_body(self.owner),
                headers=self.owner['headers'],
            )
        tid = (resp.get_json(silent=True) or {}).get('task_id')
        self.assertTrue(tid)
        status = self.other_client.get(
            f'/api/export-status/{tid}', headers=self.other_headers)
        status_body = status.get_json(silent=True) or {}
        self.assertEqual(status.status_code, 403, status_body)
        self.assertEqual(status_body.get('reason'), 'cross_user_export_denied')
        self.assertNotEqual(status_body.get('status'), 'done')
        dl = self.other_client.get(
            f'/api/export-download/{tid}', headers=self.other_headers)
        raw, payload = _response_payload(dl)
        self.assertEqual(dl.status_code, 403, payload)
        self.assertEqual(payload.get('reason'), 'cross_user_export_denied')
        self.assertFalse(_looks_like_pdf(raw))

    def test_internal_reentry_from_authorized_server_source(self):
        backend = app_mod._rel2_backend_callables()
        builder = backend.get('build_pdf_bytes')
        self.assertTrue(callable(builder))
        raw = builder(
            self.owner['content'] + '\n\n' + SERVER_MARKER,
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
        self.assertFalse(app_mod._is_internal_rel_export_request({
            '_rel26_internal': True,
        }))


if __name__ == '__main__':
    unittest.main()
