"""Typed ERM ownership with colliding strategy/risk numeric IDs.

New implementation evidence. Does not weaken e9d7643 protections.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
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
if os.environ.get('REL2_SKIP_EXPORT_EVIDENCE', '').strip() == '1':
    raise RuntimeError(
        'REL2_SKIP_EXPORT_EVIDENCE must not be set for ERM ownership tests')
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}

_TMP = tempfile.mkdtemp(prefix='test_rel37_erm_own_')


def _ensure_test_env():
    os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)
    os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
    os.environ['SECRET_KEY'] = 'test-secret-key'
    os.environ.setdefault('DATABASE_PATH', os.path.join(_TMP, 'erm_own.db'))
    os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'erm_own.db'))
    os.environ['OPENAI_API_KEY'] = ''
    os.environ['ANTHROPIC_API_KEY'] = ''
    os.environ['GOOGLE_API_KEY'] = ''
    os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'


_ensure_test_env()

import json  # noqa: E402

import app as app_mod  # noqa: E402

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_APPLIED_KEY,
    REL37_CANONICAL_FW_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    REL37_ORIGINAL_FW_KEY,
    REL37_SELECTION_REASON_KEY,
    REL37_SELECTION_SUPPORTED_KEY,
    _EXPORT_SNAPSHOTS,
    is_rel37_authoritative,
    recall_rel37_export_snapshot,
    rel37_export_snapshot_keys,
    remember_rel37_export_snapshot,
    serialize_model,
)
from release_engine_v3.rel37_export_content_parity import (  # noqa: E402
    extract_pdf_text,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_render import model_to_markdown, model_to_sections  # noqa: E402

COLLISION_ID = 9001
FIXTURE = ROOT / 'tests' / 'fixtures' / 'rel37' / 'data_en_saved_canonical_model.json'
_CLEAN_RISK_MD = (
    '## 1. وصف السيناريو\n'
    'سيناريو مخاطر تشغيلية يهدد استمرارية الأعمال ويؤثر على شهية المخاطر.\n\n'
    '## 2. جدول تقييم المخاطر\n'
    '| الخطر | الاحتمالية | التأثير | الدرجة |\n'
    '|---|---|---|---|\n'
    '| توقف الخدمة | متوسطة | عالٍ | مرتفع |\n'
    '| فقدان بيانات | منخفضة | عالٍ | متوسط |\n\n'
    '## 4. جدول استراتيجية المعالجة\n'
    '| الضابط | النوع | الأولوية | الجدول الزمني | المالك |\n'
    '|---|---|---|---|---|\n'
    '| خطة استمرارية الأعمال | وقائي | عالية | 30 يوم | مالك المخاطر |\n'
    '| نسخ احتياطي دوري | تصحيحي | متوسطة | 45 يوم | مالك المخاطر |\n'
    '| مراجعة الضوابط | كاشف | متوسطة | 60 يوم | لجنة المخاطر |\n\n'
    '## 5. مقاييس KRI للمراقبة\n'
    '| المؤشر | الحد المقبول | التكرار |\n'
    '|---|---|---|\n'
    '| نسبة المخاطر المعالجة | ≥ 90% | شهري |\n'
    '| زمن التعافي | ≤ 4 ساعات | ربع سنوي |\n'
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


def _load_model():
    model = CanonicalDocument.from_dict(
        json.loads(FIXTURE.read_text(encoding='utf-8')))
    if not model.model_hash:
        model.compute_hashes()
    return model


def _persist_for(uid, username, model):
    client, headers = _user(uid, username)
    sections = model_to_sections(model)
    sections[REL37_APPLIED_KEY] = '1'
    sections[REL37_MODEL_KEY] = serialize_model(model)
    sections[REL37_HASH_KEY] = model.model_hash
    sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
    sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
    sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
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


def tearDownModule():
    # Keep ADMIN_PASSWORD/SECRET_KEY for later modules in the same process.
    for key in ('REL2_SKIP_EXPORT_EVIDENCE', 'OPENAI_API_KEY',
                'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY'):
        previous = _ENV_BEFORE.get(key)
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def _user(uid, username):
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
    csrf = f'erm-own-csrf-{uid}'
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = username
        sess['role'] = 'user'
        sess['csrf_token'] = csrf
    return client, {'X-CSRFToken': csrf, 'Content-Type': 'application/json'}


def _collision_fixture():
    model = _load_model()
    client_a, headers_a = _user(801, 'ownerA')
    client_b, headers_b = _user(802, 'ownerB')
    sections = model_to_sections(model)
    sections[REL37_APPLIED_KEY] = '1'
    sections[REL37_MODEL_KEY] = serialize_model(model)
    sections[REL37_HASH_KEY] = model.model_hash
    sections[REL37_SELECTION_SUPPORTED_KEY] = 'true'
    sections[REL37_SELECTION_REASON_KEY] = 'supported_selection'
    sections[REL37_CANONICAL_FW_KEY] = list(model.selected_frameworks)
    sections[REL37_ORIGINAL_FW_KEY] = list(model.selected_frameworks)
    content = model_to_markdown(model)
    with app_mod.app.app_context():
        db = app_mod.get_db()
        db.execute('DELETE FROM risks WHERE id = ?', (COLLISION_ID,))
        db.execute('DELETE FROM strategies WHERE id = ?', (COLLISION_ID,))
        db.execute(
            'INSERT INTO strategies '
            '(id, user_id, domain, org_name, sector, content, language, '
            ' document_title, sections_json, content_json) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                COLLISION_ID, 801, 'Data Management', model.org_name,
                'Government', content, 'en', 'Data EN collision',
                json.dumps(sections, ensure_ascii=False),
                json.dumps({'sections': sections}, ensure_ascii=False),
            ),
        )
        db.execute(
            'INSERT INTO risks '
            '(id, user_id, domain, asset_name, threat, risk_level, analysis, language) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (COLLISION_ID, 802, 'Enterprise Risk Management', 'Core service',
             'Outage', 'HIGH', _CLEAN_RISK_MD, 'ar'),
        )
        db.commit()
    return {
        'uid': 801,
        'username': 'ownerA',
        'client': client_a,
        'headers': headers_a,
        'strategy_id': COLLISION_ID,
        'sections': sections,
        'content': content,
        'model': model,
    }, {
        'uid': 802,
        'username': 'ownerB',
        'client': client_b,
        'headers': headers_b,
        'risk_id': COLLISION_ID,
        'content': _CLEAN_RISK_MD,
    }


A_ORG = 'REL37.07 Data EN UI Org'
A_NARRATIVE_MARK = 'classification completeness'
B_SCENARIO_MARK = 'سيناريو مخاطر تشغيلية'
B_TREATMENT_MARK = 'خطة استمرارية الأعمال'
B_KRI_MARK = 'نسبة المخاطر المعالجة'
_CORRUPT_RISK_MD = (
    '## 1. وصف السيناريو\n'
    'نص سيناريو بدون جداول المعالجة أو التقييم.\n'
)


def _post(client, headers, path, body):
    with patch('threading.Thread', ImmediateThread):
        resp = client.post(path, json=body, headers=headers)
    return resp.status_code, resp.get_json(silent=True) or {}


def _strategy_body(owner, extra=None):
    body = {
        'content': owner['content'],
        'filename': 'data_a',
        'language': 'en',
        'domain': 'Data Management',
        'document_type': 'strategy',
        'artifact_type': 'strategy',
        'strategy_id': owner['strategy_id'],
        'artifact_id': owner['strategy_id'],
        'generation_mode': 'drafting',
        'org_name': owner['model'].org_name,
        'selected_frameworks': list(owner['model'].selected_frameworks),
    }
    if extra:
        body.update(extra)
    return body


def _risk_body(owner, extra=None):
    body = {
        'content': owner['content'],
        'filename': 'erm_b',
        'language': 'ar',
        'domain': 'Enterprise Risk Management',
        'document_type': 'risk',
        'artifact_type': 'risk',
        'risk_id': owner['risk_id'],
        'artifact_id': owner['risk_id'],
        'generation_mode': 'drafting',
    }
    if extra:
        body.update(extra)
    return body


def _poll_export(client, headers, task_id, *, timeout=45):
    status = {}
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.get(
            f'/api/export-status/{task_id}', headers=headers
        ).get_json(silent=True) or {}
        if status.get('status') in ('done', 'error'):
            break
        time.sleep(0.2)
    raw = b''
    download_http = 0
    if status.get('status') == 'done':
        dl = client.get(f'/api/export-download/{task_id}', headers=headers)
        download_http = dl.status_code
        raw = dl.data or b''
    return status, download_http, raw


def _export_real(client, headers, path, body, *, timeout=45):
    resp = client.post(path, json=body, headers=headers)
    submit = resp.get_json(silent=True) or {}
    tid = submit.get('task_id')
    status, download_http, raw = ({}, 0, b'')
    if tid:
        status, download_http, raw = _poll_export(
            client, headers, tid, timeout=timeout)
    return {
        'submit_http': resp.status_code,
        'submit': submit,
        'task_id': tid,
        'status': status,
        'download_http': download_http,
        'bytes': raw,
    }


def _persist_risk(uid, username, analysis, *, risk_id=None):
    client, headers = _user(uid, username)
    with app_mod.app.app_context():
        db = app_mod.get_db()
        if risk_id is None:
            cur = db.execute(
                'INSERT INTO risks '
                '(user_id, domain, asset_name, threat, risk_level, '
                ' analysis, language) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (uid, 'Enterprise Risk Management', 'Core service',
                 'Outage', 'HIGH', analysis, 'ar'),
            )
            rid = cur.lastrowid
        else:
            db.execute('DELETE FROM risks WHERE id = ?', (risk_id,))
            db.execute(
                'INSERT INTO risks '
                '(id, user_id, domain, asset_name, threat, risk_level, '
                ' analysis, language) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (risk_id, uid, 'Enterprise Risk Management', 'Core service',
                 'Outage', 'HIGH', analysis, 'ar'),
            )
            rid = risk_id
        db.commit()
    return {
        'uid': uid,
        'username': username,
        'client': client,
        'headers': headers,
        'risk_id': rid,
        'content': analysis,
    }


def _looks_like_pdf(raw):
    return bool(raw) and raw.startswith(b'%PDF')


def _pdf_text(raw):
    text, meta = extract_pdf_text(raw)
    return text or '', meta or {}


class ErmTypedOwnershipTests(unittest.TestCase):
    def setUp(self):
        _ensure_test_env()

    def test_identifier_conflict_rejects_strategy_and_risk(self):
        self.assertTrue(app_mod._public_pdf_identifier_conflict({
            'strategy_id': '77', 'risk_id': '77', 'artifact_type': 'risk',
        }))
        self.assertFalse(app_mod._public_pdf_identifier_conflict({
            'risk_id': '77', 'artifact_id': '77', 'artifact_type': 'risk',
            'document_type': 'risk',
        }))
        _owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf-async', {
                               'content': owner_b['content'],
                               'filename': 'conflict',
                               'language': 'ar',
                               'domain': 'Enterprise Risk Management',
                               'document_type': 'risk',
                               'artifact_type': 'risk',
                               'risk_id': owner_b['risk_id'],
                               'strategy_id': COLLISION_ID,
                               'artifact_id': owner_b['risk_id'],
                               'generation_mode': 'drafting',
                           })
        self.assertEqual(http, 400, body)
        self.assertEqual(body.get('reason'), 'conflicting_export_identifiers')

    def test_b_own_risk_lookup_is_not_ownership_denial(self):
        """Authorization-only: B's own risk_id is not cross-user denied."""
        _owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf-async', _risk_body(owner_b))
        self.assertNotEqual(body.get('reason'), 'cross_user_export_denied', body)
        self.assertIn(http, (200, 422), body)
        if http == 200:
            self.assertTrue(body.get('task_id'), body)

    def test_b_cannot_export_a_strategy(self):
        owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf-async', {
                               'content': owner_a['content'],
                               'filename': 'steal',
                               'language': 'en',
                               'domain': 'Data Management',
                               'document_type': 'strategy',
                               'artifact_type': 'strategy',
                               'strategy_id': owner_a['strategy_id'],
                               'artifact_id': owner_a['strategy_id'],
                               'generation_mode': 'drafting',
                           })
        self.assertEqual(http, 403, body)
        self.assertEqual(body.get('reason'), 'cross_user_export_denied')

    def test_a_cannot_export_b_risk_via_strategy_id(self):
        owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_a['client'], owner_a['headers'],
                           '/api/generate-pdf-async', {
                               'content': owner_b['content'],
                               'filename': 'spoof_risk',
                               'language': 'ar',
                               'domain': 'Enterprise Risk Management',
                               'document_type': 'risk',
                               'artifact_type': 'risk',
                               'strategy_id': owner_a['strategy_id'],
                               'artifact_id': owner_a['strategy_id'],
                               'generation_mode': 'drafting',
                           })
        self.assertEqual(http, 403, body)
        self.assertEqual(body.get('reason'), 'cross_user_export_denied')

    def test_risk_lookup_uses_risks_table(self):
        _owner_a, owner_b = _collision_fixture()
        loaded = app_mod._load_authorized_saved_export_for_pdf(
            COLLISION_ID, 802, 'risk')
        self.assertIsNotNone(loaded)
        self.assertEqual(int(loaded['id']), COLLISION_ID)
        self.assertIn('جدول تقييم المخاطر', loaded['content'])
        stolen = app_mod._load_authorized_saved_export_for_pdf(
            COLLISION_ID, 801, 'risk')
        self.assertIsNone(stolen)

    def test_copied_snapshot_and_internal_flags_inert(self):
        owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf', {
                               'content': owner_a['content'],
                               'filename': 'flags',
                               'language': 'en',
                               'domain': 'Data Management',
                               'document_type': 'strategy',
                               'strategy_id': owner_a['strategy_id'],
                               '_rel26_internal': True,
                               'skip_rel26_gate': True,
                               '_rel37_source_sections': owner_a['sections'],
                           })
        self.assertEqual(http, 403, body)

    def test_stale_csrf_is_not_ownership_denial(self):
        _owner_a, owner_b = _collision_fixture()
        bad = dict(owner_b['headers'])
        bad['X-CSRFToken'] = 'stale'
        http, body = _post(owner_b['client'], bad, '/api/generate-pdf-async', {
            'content': owner_b['content'],
            'filename': 'csrf',
            'language': 'ar',
            'domain': 'Enterprise Risk Management',
            'document_type': 'risk',
            'artifact_type': 'risk',
            'risk_id': owner_b['risk_id'],
            'artifact_id': owner_b['risk_id'],
        })
        self.assertNotEqual(body.get('reason'), 'cross_user_export_denied', body)
        self.assertIn(http, (400, 403))

    def test_missing_csrf_and_unauthenticated_remain_refused(self):
        _owner_a, owner_b = _collision_fixture()
        anon = app_mod.app.test_client()
        http, body = _post(anon, {'Content-Type': 'application/json'},
                           '/api/generate-pdf-async', _risk_body(owner_b))
        self.assertIn(http, (401, 403), body)
        self.assertNotEqual(body.get('reason'), 'cross_user_export_denied', body)
        missing = dict(owner_b['headers'])
        missing.pop('X-CSRFToken', None)
        http, body = _post(owner_b['client'], missing,
                           '/api/generate-pdf-async', _risk_body(owner_b))
        self.assertIn(http, (400, 403), body)
        self.assertNotEqual(body.get('reason'), 'cross_user_export_denied', body)

    def test_a_cannot_access_b_risk_jobs_and_b_cannot_access_a_jobs(self):
        owner_a, owner_b = _collision_fixture()
        http_a, body_a = _post(owner_a['client'], owner_a['headers'],
                               '/api/generate-pdf-async', _strategy_body(owner_a))
        http_b, body_b = _post(owner_b['client'], owner_b['headers'],
                               '/api/generate-pdf-async', _risk_body(owner_b))
        if http_a == 200 and body_a.get('task_id'):
            stolen = owner_b['client'].get(
                f"/api/export-status/{body_a['task_id']}",
                headers=owner_b['headers']).get_json(silent=True) or {}
            self.assertNotEqual(stolen.get('status'), 'done', stolen)
            dl = owner_b['client'].get(
                f"/api/export-download/{body_a['task_id']}",
                headers=owner_b['headers'])
            self.assertNotEqual(dl.status_code, 200)
            self.assertFalse(_looks_like_pdf(dl.data or b''))
        if http_b == 200 and body_b.get('task_id'):
            stolen = owner_a['client'].get(
                f"/api/export-status/{body_b['task_id']}",
                headers=owner_a['headers']).get_json(silent=True) or {}
            self.assertNotEqual(stolen.get('status'), 'done', stolen)
            dl = owner_a['client'].get(
                f"/api/export-download/{body_b['task_id']}",
                headers=owner_a['headers'])
            self.assertNotEqual(dl.status_code, 200)
            self.assertFalse(_looks_like_pdf(dl.data or b''))

    def test_strategy_cannot_evade_validation_by_client_type(self):
        owner_a, _owner_b = _collision_fixture()
        http, body = _post(owner_a['client'], owner_a['headers'],
                           '/api/generate-pdf-async', _strategy_body(owner_a, {
                               'document_type': 'risk',
                               'artifact_type': 'risk',
                           }))
        self.assertIn(http, (400, 403), body)
        self.assertNotEqual(http, 200, body)

    def test_hash_identity_tamper_remains_refused(self):
        owner_a, _owner_b = _collision_fixture()
        tampered = dict(owner_a['sections'])
        tampered[REL37_HASH_KEY] = '0' * 64
        with app_mod.app.app_context():
            db = app_mod.get_db()
            db.execute(
                'UPDATE strategies SET sections_json=?, content_json=? '
                'WHERE id=?',
                (
                    json.dumps(tampered, ensure_ascii=False),
                    json.dumps({'sections': tampered}, ensure_ascii=False),
                    owner_a['strategy_id'],
                ),
            )
            db.commit()
        result = _export_real(
            owner_a['client'], owner_a['headers'],
            '/api/generate-pdf-async', _strategy_body(owner_a))
        self.assertFalse(
            result['download_http'] == 200 and _looks_like_pdf(result['bytes']),
            result,
        )
        if result['bytes']:
            self.assertFalse(_looks_like_pdf(result['bytes']), result)

    def test_invalid_risk_content_is_refused(self):
        owner_b = _persist_risk(812, 'ownerBcorrupt', _CORRUPT_RISK_MD)
        result = _export_real(
            owner_b['client'], owner_b['headers'],
            '/api/generate-pdf-async', _risk_body(owner_b))
        self.assertFalse(
            result['download_http'] == 200 and _looks_like_pdf(result['bytes']),
            result,
        )
        self.assertNotEqual(
            (result['submit'] or {}).get('reason'),
            'cross_user_export_denied',
            result,
        )


class Rel37ExportSnapshotIdentityTests(unittest.TestCase):
    def setUp(self):
        _EXPORT_SNAPSHOTS.clear()
        self.sections = {
            REL37_APPLIED_KEY: '1',
            REL37_MODEL_KEY: '{"domain":"data"}',
            REL37_HASH_KEY: 'c87b5cc6e1dee58de38657ee721b2e61c509a0e48141e8f6796414293eb99d40',
        }
        self.assertTrue(is_rel37_authoritative(self.sections))

    def tearDown(self):
        _EXPORT_SNAPSHOTS.clear()

    def test_missing_type_or_owner_refuses_store_and_recall(self):
        remember_rel37_export_snapshot('1', self.sections)
        remember_rel37_export_snapshot(
            '1', self.sections, artifact_type='strategy')
        remember_rel37_export_snapshot(
            '1', self.sections, owner='101')
        self.assertEqual(list(_EXPORT_SNAPSHOTS), [])
        self.assertEqual(recall_rel37_export_snapshot('1'), {})
        self.assertEqual(
            recall_rel37_export_snapshot(
                '1', model_hash=self.sections[REL37_HASH_KEY]),
            {},
        )

    def test_risk_type_never_stores_or_recalls_strategy(self):
        remember_rel37_export_snapshot(
            '1', self.sections, artifact_type='strategy', owner='101')
        remember_rel37_export_snapshot(
            '1', self.sections, artifact_type='risk', owner='202')
        self.assertEqual(
            rel37_export_snapshot_keys(
                '1', artifact_type='risk', owner='202'),
            [],
        )
        self.assertEqual(
            recall_rel37_export_snapshot(
                '1', artifact_type='risk', owner='202'),
            {},
        )
        self.assertEqual(
            recall_rel37_export_snapshot(
                '1',
                model_hash=self.sections[REL37_HASH_KEY],
                artifact_type='risk',
                owner='101',
            ),
            {},
        )
        self.assertNotIn('1', _EXPORT_SNAPSHOTS)
        self.assertNotIn(
            f'hash:{self.sections[REL37_HASH_KEY]}', _EXPORT_SNAPSHOTS)

    def test_same_owner_strategy_repeat_hits_typed_keys(self):
        remember_rel37_export_snapshot(
            '1', self.sections, artifact_type='strategy', owner='101')
        recalled = recall_rel37_export_snapshot(
            '1', artifact_type='strategy', owner='101')
        self.assertTrue(is_rel37_authoritative(recalled))
        self.assertEqual(
            recalled.get(REL37_HASH_KEY), self.sections[REL37_HASH_KEY])
        keys = set(_EXPORT_SNAPSHOTS)
        self.assertIn('strategy:101:1', keys)
        self.assertIn(
            'strategy:101:hash:c87b5cc6e1dee58de38657ee721b2e61c509a0e48141e8f6796414293eb99d40',
            keys,
        )
        self.assertTrue(all(':' in key for key in keys))

    def test_other_owner_or_type_cannot_use_snapshot(self):
        remember_rel37_export_snapshot(
            '1', self.sections, artifact_type='strategy', owner='101')
        self.assertEqual(
            recall_rel37_export_snapshot(
                '1', artifact_type='strategy', owner='202'),
            {},
        )
        self.assertEqual(
            recall_rel37_export_snapshot(
                '1', artifact_type='gap_assessment', owner='101'),
            {},
        )

    def test_copied_snapshot_flags_cannot_redirect_authority(self):
        owner_a, owner_b = _collision_fixture()
        remember_rel37_export_snapshot(
            owner_a['strategy_id'],
            owner_a['sections'],
            artifact_type='strategy',
            owner=str(owner_a['uid']),
        )
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf-async', _risk_body(owner_b, {
                               '_rel37_source_sections': owner_a['sections'],
                               '_rel26_internal': True,
                               'skip_rel26_gate': True,
                               'canonical_hash': owner_a['model'].model_hash,
                               'model_hash': owner_a['model'].model_hash,
                           }))
        self.assertNotEqual(body.get('reason'), 'cross_user_export_denied', body)
        recalled = recall_rel37_export_snapshot(
            owner_b['risk_id'],
            model_hash=owner_a['model'].model_hash,
            artifact_type='risk',
            owner=str(owner_b['uid']),
        )
        self.assertEqual(recalled, {})


class ErmInterleavedTypedExportTests(unittest.TestCase):
    """Same-number / interleaved owner-positive using the real worker."""

    def setUp(self):
        _ensure_test_env()
        _EXPORT_SNAPSHOTS.clear()

    def tearDown(self):
        _EXPORT_SNAPSHOTS.clear()

    def _assert_owner_risk_pdf(self, result, owner_b):
        self.assertEqual(result['submit_http'], 200, result['submit'])
        self.assertTrue(result['task_id'], result)
        self.assertEqual(result['status'].get('status'), 'done', result['status'])
        self.assertEqual(result['download_http'], 200, result['status'])
        self.assertTrue(_looks_like_pdf(result['bytes']), result['bytes'][:40])
        text, meta = _pdf_text(result['bytes'])
        self.assertTrue(text.strip(), meta)
        self.assertIn(B_SCENARIO_MARK, text)
        self.assertIn(B_TREATMENT_MARK, text)
        self.assertIn(B_KRI_MARK, text)
        self.assertIn('جدول تقييم المخاطر', text)
        self.assertNotIn(A_ORG, text)
        self.assertNotIn(A_NARRATIVE_MARK, text)
        self.assertNotIn('NDMO', text)
        self.assertNotIn(owner_b.get('strategy_marker', A_ORG), text)

    def _assert_owner_strategy_pdf(self, result):
        self.assertEqual(result['submit_http'], 200, result['submit'])
        self.assertTrue(result['task_id'], result)
        self.assertEqual(result['status'].get('status'), 'done', result['status'])
        self.assertEqual(result['download_http'], 200, result['status'])
        self.assertTrue(_looks_like_pdf(result['bytes']), result['bytes'][:40])
        text, meta = _pdf_text(result['bytes'])
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn(A_ORG, text)
        self.assertNotIn(B_SCENARIO_MARK, text)
        self.assertNotIn(B_TREATMENT_MARK, text)

    def _prime_a_then_export_b(self, owner_a, owner_b):
        first = _export_real(
            owner_a['client'], owner_a['headers'],
            '/api/generate-pdf-async', _strategy_body(owner_a))
        self._assert_owner_strategy_pdf(first)
        repeat = _export_real(
            owner_a['client'], owner_a['headers'],
            '/api/generate-pdf-async', _strategy_body(owner_a))
        self._assert_owner_strategy_pdf(repeat)
        risk = _export_real(
            owner_b['client'], owner_b['headers'],
            '/api/generate-pdf-async', _risk_body(owner_b))
        self._assert_owner_risk_pdf(risk, owner_b)
        self.assertTrue(
            any(str(key).startswith('strategy:') for key in _EXPORT_SNAPSHOTS),
            list(_EXPORT_SNAPSHOTS),
        )
        self.assertFalse(
            any(str(key).startswith('risk:') for key in _EXPORT_SNAPSHOTS),
            list(_EXPORT_SNAPSHOTS),
        )
        return first, repeat, risk

    def test_b_can_export_own_risk(self):
        owner_a, owner_b = _collision_fixture()
        _first, _repeat, risk = self._prime_a_then_export_b(owner_a, owner_b)
        self.assertGreater(len(risk['bytes']), 1000)

    def test_same_number_strategy_then_risk_isolation(self):
        owner_a, owner_b = _collision_fixture()
        self.assertEqual(int(owner_a['strategy_id']), int(owner_b['risk_id']))
        self._prime_a_then_export_b(owner_a, owner_b)

    def test_different_numeric_ids_remain_isolated(self):
        model = _load_model()
        owner_a = _persist_for(821, 'ownerAdiff', model)
        owner_b = _persist_risk(822, 'ownerBdiff', _CLEAN_RISK_MD)
        self.assertNotEqual(int(owner_a['strategy_id']), int(owner_b['risk_id']))
        self._prime_a_then_export_b(owner_a, owner_b)

    def test_interleaved_risk_strategy_risk(self):
        owner_a, owner_b = _collision_fixture()
        cold = _export_real(
            owner_b['client'], owner_b['headers'],
            '/api/generate-pdf-async', _risk_body(owner_b))
        self._assert_owner_risk_pdf(cold, owner_b)
        primed = _export_real(
            owner_a['client'], owner_a['headers'],
            '/api/generate-pdf-async', _strategy_body(owner_a))
        self._assert_owner_strategy_pdf(primed)
        warm = _export_real(
            owner_b['client'], owner_b['headers'],
            '/api/generate-pdf-async', _risk_body(owner_b))
        self._assert_owner_risk_pdf(warm, owner_b)

    def test_a_cannot_export_b_risk_or_jobs_after_prime(self):
        owner_a, owner_b = _collision_fixture()
        primed = _export_real(
            owner_a['client'], owner_a['headers'],
            '/api/generate-pdf-async', _strategy_body(owner_a))
        self._assert_owner_strategy_pdf(primed)
        http, body = _post(owner_a['client'], owner_a['headers'],
                           '/api/generate-pdf-async', _risk_body(owner_b))
        self.assertEqual(http, 403, body)
        self.assertEqual(body.get('reason'), 'cross_user_export_denied')
        stolen = owner_b['client'].get(
            f"/api/export-download/{primed['task_id']}",
            headers=owner_b['headers'])
        self.assertNotEqual(stolen.status_code, 200)
        self.assertFalse(_looks_like_pdf(stolen.data or b''))


if __name__ == '__main__':
    unittest.main()
