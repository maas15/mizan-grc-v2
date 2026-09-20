"""Typed ERM ownership with colliding strategy/risk numeric IDs.

New implementation evidence. Does not weaken e9d7643 protections.
"""
from __future__ import annotations

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
    serialize_model,
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


def _post(client, headers, path, body):
    with patch('threading.Thread', ImmediateThread):
        resp = client.post(path, json=body, headers=headers)
    return resp.status_code, resp.get_json(silent=True) or {}


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

    def test_b_can_export_own_risk(self):
        _owner_a, owner_b = _collision_fixture()
        http, body = _post(owner_b['client'], owner_b['headers'],
                           '/api/generate-pdf-async', {
                               'content': owner_b['content'],
                               'filename': 'erm_b',
                               'language': 'ar',
                               'domain': 'Enterprise Risk Management',
                               'document_type': 'risk',
                               'artifact_type': 'risk',
                               'risk_id': owner_b['risk_id'],
                               'artifact_id': owner_b['risk_id'],
                               'generation_mode': 'drafting',
                           })
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


if __name__ == '__main__':
    unittest.main()
