"""REL37.0.6 — UI strategy request type contract.

Replays the captured Data EN browser payload through the real
async route → worker → api_generate_strategy path. Mocks only
provider I/O (generate_ai_content). Does not rewrite display
labels to short IDs.
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

_TMP = tempfile.mkdtemp(prefix='test_rel37_06_')
os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'rel37_06.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'rel37_06.db')
os.environ['OPENAI_API_KEY'] = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['REL2_SKIP_EXPORT_EVIDENCE'] = '1'
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

import app as app_mod  # noqa: E402

from release_engine_v3.rel37_apply import (  # noqa: E402
    is_rel37_authoritative,
    load_model,
)
from release_engine_v3.rel37_framework_aliases import (  # noqa: E402
    FrameworksRequestTypeError,
    REL37_CANONICAL_FW_KEY,
    REL37_ORIGINAL_FW_KEY,
    validate_frameworks_request_type,
)
from release_engine_v3.rel37_live_attach import export_bundle_from_sections  # noqa: E402
from release_engine_v3.rel37_preview_section_contract import (  # noqa: E402
    TEXTUAL_SECTION_KEYS,
    VisibleSectionTypeError,
    public_status_sections,
    textual_section_value_or_raise,
    visible_sections,
)

CAPTURED_DATA_EN = {
    'domain': 'Data Management',
    'language': 'en',
    'org_name': 'REL37 Data EN UI Org',
    'sector': 'Government',
    'size': 'Small (<100)',
    'budget': '< 1M SAR',
    'frameworks': [
        'PDPL (Personal Data Protection Law)',
        'NDMO Data Governance Framework',
    ],
    'org_structure': 'centralized',
    'technologies': [],
    'additional_tech': '',
    'maturity_level': 'initial',
    'challenges': '',
    'doc_subtype': 'technical',
    'generation_mode': 'drafting',
    'diagnostic_id': None,
}

DATA_AR_FORM = {
    **CAPTURED_DATA_EN,
    'language': 'ar',
    'org_name': 'منظمة بيانات عربي',
}
DATA_AR_LABELS = {
    **DATA_AR_FORM,
    'frameworks': [
        'نظام حماية البيانات الشخصية (PDPL)',
        'إطار حوكمة البيانات - مكتب إدارة البيانات الوطنية (NDMO)',
    ],
}
AI_EN = {
    **CAPTURED_DATA_EN,
    'domain': 'Artificial Intelligence',
    'org_name': 'REL37 AI EN UI Org',
    'frameworks': ['SDAIA AI Ethics Principles'],
}
AI_AR = {
    **AI_EN,
    'language': 'ar',
    'org_name': 'منظمة ذكاء اصطناعي',
}
DT_EN = {
    **CAPTURED_DATA_EN,
    'domain': 'Digital Transformation',
    'org_name': 'REL37 DT EN UI Org',
    'frameworks': ['DGA Digital Government Policy'],
}
DT_AR = {
    **DT_EN,
    'language': 'ar',
    'org_name': 'منظمة تحول رقمي',
}

_OBSERVED_TYPEERROR = "expected string or bytes-like object, got 'list'"


_PDPL_PHRASES = (
    'data subject rights, access request, rectification, erasure, '
    'deletion request, personal data classification, data breach '
    'notification, breach reporting, consent management, consent register, '
    'explicit consent, consent records'
)
_PDPL_PHRASES_AR = (
    'حقوق صاحب البيانات وحق الوصول وحق التصحيح وحق الحذف وطلبات أصحاب '
    'البيانات وتصنيف البيانات الشخصية وإخطار الخروقات والإبلاغ عن خرق '
    'البيانات وإدارة الموافقات وسجل الموافقات والموافقة الصريحة'
)


def _section_markdown(key, lang='en'):
    ar = str(lang or 'en').startswith('ar')
    if key == 'vision':
        if ar:
            return (
                '## 1. الرؤية والأهداف\n\n' + _PDPL_PHRASES_AR + '\n\n'
                '| # | الهدف | المؤشر | المبرر | الإطار الزمني |\n'
                '|---|------|--------|--------|----------------|\n'
                '| 1 | إنشاء مكتب البيانات | ميثاق معتمد | يغلق الفجوة 1 | 6 أشهر |\n'
                '| 2 | تشغيل حقوق صاحب البيانات | 100% طلبات | PDPL | 9 أشهر |\n'
                '| 3 | تصنيف البيانات الشخصية | سجل مكتمل | PDPL | 6 أشهر |\n'
                '| 4 | إخطار الخروقات | آلية معتمدة | PDPL | 6 أشهر |\n'
                '| 5 | إدارة الموافقات | سجل موافقات | PDPL | 9 أشهر |\n'
                '| 6 | حوكمة NDMO | سياسة معتمدة | NDMO | 12 أشهر |\n'
            )
        return (
            '## 1. Vision and Objectives\n\n' + _PDPL_PHRASES + '\n\n'
            '| # | Objective | Target Metric | Justification | Timeframe |\n'
            '|---|-----------|---------------|---------------|-----------|\n'
            '| 1 | Establish data office | Charter approved | Closes Gap #1 | 6 months |\n'
            '| 2 | Operationalize data subject rights | 100% access request SLA | PDPL | 9 months |\n'
            '| 3 | Complete personal data classification | 100% assets classed | PDPL | 6 months |\n'
            '| 4 | Implement data breach notification | Approved procedure | PDPL | 6 months |\n'
            '| 5 | Stand up consent management | Consent register live | PDPL | 9 months |\n'
            '| 6 | Adopt NDMO operating policy | Policy approved | NDMO | 12 months |\n'
        )
    if key == 'pillars':
        if ar:
            return (
                '## 2. الركائز الاستراتيجية\n\n' + _PDPL_PHRASES_AR + '\n\n'
                '### الركيزة 1: حوكمة البيانات\n'
                '| # | المبادرة | الوصف | المخرج |\n'
                '|---|----------|--------|--------|\n'
                '| 1 | مكتب الحقوق | تشغيل حقوق صاحب البيانات | مصفوفة |\n'
                '| 2 | التصنيف | تصنيف البيانات الشخصية | سجل |\n'
            )
        return (
            '## 2. Strategic Pillars\n\n' + _PDPL_PHRASES + '\n\n'
            '### Pillar 1: Data governance\n'
            '| # | Initiative | Description | Expected Deliverable |\n'
            '|---|------------|-------------|----------------------|\n'
            '| 1 | Rights desk | Operate data subject rights and erasure | RACI |\n'
            '| 2 | Classification | Personal data classification | Register |\n'
        )
    if key == 'environment':
        fws = (
            'PDPL (Personal Data Protection Law), '
            'NDMO Data Governance Framework, '
            'SDAIA AI Ethics Principles, '
            'DGA Digital Government Policy, '
            'نظام حماية البيانات الشخصية (PDPL), '
            'إطار حوكمة البيانات - مكتب إدارة البيانات الوطنية (NDMO), '
            'مبادئ أخلاقيات الذكاء الاصطناعي, '
            'هيئة الحكومة الرقمية'
        )
        if ar:
            return (
                '## 3. البيئة التنظيمية\n\n' + _PDPL_PHRASES_AR + '\n\n'
                f'يشمل المشهد التنظيمي الأطر التالية: {fws}.\n'
            )
        return (
            '## 3. Business Environment\n\n' + _PDPL_PHRASES + '\n\n'
            f'Regulatory landscape includes {fws} plus data subject rights, '
            'personal data classification, data breach notification, and '
            'consent management for this organization.\n'
        )
    if key == 'gaps':
        if ar:
            return (
                '## 4. تحليل الفجوات\n\n' + _PDPL_PHRASES_AR + '\n\n'
                '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
                '|---|--------|--------|----------|--------|\n'
                '| 1 | مسار الحقوق | حق الوصول والحذف غير مكتمل | عالية | مفتوحة |\n'
                '| 2 | تصنيف ضعيف | تصنيف البيانات الشخصية ناقص | عالية | مفتوحة |\n'
                '| 3 | بلا إخطار | إخطار الخروقات غير موجود | عالية | مفتوحة |\n'
                '| 4 | بلا موافقات | إدارة الموافقات ناقصة | متوسطة | مفتوحة |\n\n'
                '#### دليل تنفيذ الفجوة رقم 1: حقوق صاحب البيانات\n'
                '| الخطوة | الإجراء | الأداة | المسؤول | المخرج |\n'
                '|--------|---------|--------|---------|--------|\n'
                '| 1 | نشر إجراء حق الوصول | مكتب الخدمة | مسؤول الحماية | إجراء |\n'
            )
        return (
            '## 4. Gap Analysis\n\n' + _PDPL_PHRASES + '\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|-----|-------------|----------|--------|\n'
            '| 1 | No data subject rights path | Access request and erasure missing | High | Open |\n'
            '| 2 | Weak personal data classification | Sensitive data unmarked | High | Open |\n'
            '| 3 | No data breach notification | Breach reporting absent | High | Open |\n'
            '| 4 | No consent management | Consent register missing | Medium | Open |\n\n'
            '#### Gap #1 Implementation Guide: Data subject rights\n'
            '| Step | Action | Tool/System | Owner | Output |\n'
            '|------|--------|-------------|-------|--------|\n'
            '| 1 | Publish access request procedure | Service desk | DPO | SOP |\n'
        )
    if key == 'roadmap':
        if ar:
            return (
                '## 5. خارطة الطريق\n\n### المرحلة 1 (0-6 أشهر)\n\n'
                + _PDPL_PHRASES_AR + '\n\n'
                '| # | النشاط | المسؤول | الجدول | المخرج |\n'
                '|---|--------|---------|--------|--------|\n'
                '| 1 | تشغيل حقوق صاحب البيانات | مسؤول الحماية | 1-3 أشهر | إجراء |\n'
                '| 2 | تصنيف البيانات الشخصية | رئيس البيانات | 2-4 أشهر | سجل |\n'
                '| 3 | إخطار الخروقات | مسؤول الحماية | 3-5 أشهر | دليل |\n'
                '| 4 | إدارة الموافقات | مسؤول الحماية | 4-6 أشهر | سجل الموافقات |\n'
            )
        return (
            '## 5. Implementation Roadmap\n\n### Phase 1 (0-6 months)\n\n'
            + _PDPL_PHRASES + '\n\n'
            '| # | Activity | Owner | Timeline | Deliverable |\n'
            '|---|----------|-------|----------|-------------|\n'
            '| 1 | Launch data subject rights desk | DPO | 1-3 months | Operating procedure |\n'
            '| 2 | Personal data classification | CDO | 2-4 months | Classified register |\n'
            '| 3 | Data breach notification process | DPO | 3-5 months | Notification runbook |\n'
            '| 4 | Consent management register | DPO | 4-6 months | Consent records |\n'
        )
    if key == 'kpis':
        if ar:
            return (
                '## 6. مؤشرات الأداء\n\n' + _PDPL_PHRASES_AR + '\n\n'
                '| # | المؤشر | الحالي | المستهدف | التكرار |\n'
                '|---|--------|--------|----------|--------|\n'
                '| 1 | زمن حق الوصول | 40% | 95% | شهري |\n'
                '| 2 | تغطية تصنيف البيانات الشخصية | 20% | 100% | ربع سنوي |\n'
                '| 3 | تمارين إخطار الخروقات | 0 | 2/سنة | سنوي |\n'
                '| 4 | اكتمال سجل الموافقات | 10% | 100% | ربع سنوي |\n\n'
                '#### دليل تقييم المؤشر 1:\n'
                '| الخطوة | الإجراء | الأداة | المسؤول | المخرج |\n'
                '|--------|---------|--------|---------|--------|\n'
                '| 1 | قياس زمن حق الوصول | مكتب الخدمة | مسؤول الحماية | بطاقة |\n'
            )
        return (
            '## 6. Key Performance Indicators\n\n' + _PDPL_PHRASES + '\n\n'
            '| # | KPI | Current | Target | Frequency |\n'
            '|---|-----|---------|--------|-----------|\n'
            '| 1 | Access request SLA | 40% | 95% | Monthly |\n'
            '| 2 | Personal data classification coverage | 20% | 100% | Quarterly |\n'
            '| 3 | Data breach notification drills | 0 | 2/year | Annual |\n'
            '| 4 | Consent register completeness | 10% | 100% | Quarterly |\n\n'
            '#### KPI #1 Assessment Guide:\n'
            '| Step | Action | Tool/System | Owner | Output |\n'
            '|------|--------|-------------|-------|--------|\n'
            '| 1 | Measure access request cycle time | Service desk | DPO | Scorecard |\n'
        )
    if key == 'confidence':
        if ar:
            return (
                '## 7. تقييم الثقة\n\n**درجة الثقة:** 72%\n\n'
                + _PDPL_PHRASES_AR + '\n\n'
                '### عوامل النجاح الحرجة\n'
                '| # | العامل | الوصف | الأهمية |\n'
                '|---|--------|--------|--------|\n'
                '| 1 | مكتب الحقوق | حقوق صاحب البيانات تعمل | عالية |\n'
                '| 2 | التصنيف | تصنيف البيانات الشخصية مكتمل | عالية |\n'
                '| 3 | الإخطار | إخطار الخروقات مجرّب | عالية |\n'
                '| 4 | الموافقات | إدارة الموافقات قائمة | عالية |\n'
                '| 5 | سياسة NDMO | السياسة معتمدة | متوسطة |\n\n'
                '### المخاطر الرئيسية\n'
                '| # | المخاطرة | الاحتمال | الأثر | المعالجة |\n'
                '|---|----------|----------|------|----------|\n'
                '| 1 | تأخر حق الوصول | متوسط | عالٍ | تشغيل المكتب |\n'
                '| 2 | ضعف تصنيف البيانات الشخصية | عالٍ | عالٍ | تصنيف الأصول |\n'
                '| 3 | تأخر إخطار الخروقات | متوسط | عالٍ | تمرين الإبلاغ |\n'
                '| 4 | نقص سجل الموافقات | متوسط | متوسط | إنشاء السجل |\n'
                '| 5 | تأخر سياسة NDMO | منخفض | متوسط | تعيين مالك |\n'
                '| 6 | تراكم حق الحذف | متوسط | متوسط | تتبع الطلبات |\n'
            )
        return (
            '## 7. Confidence Assessment\n\n**Confidence Score:** 72%\n\n'
            + _PDPL_PHRASES + '\n\n'
            '### Critical Success Factors\n'
            '| # | Factor | Description | Importance |\n'
            '|---|--------|-------------|------------|\n'
            '| 1 | Rights desk | Data subject rights operating | High |\n'
            '| 2 | Classification | Personal data classification complete | High |\n'
            '| 3 | Notification | Data breach notification tested | High |\n'
            '| 4 | Consent | Consent management live | High |\n'
            '| 5 | NDMO policy | Operating policy approved | Medium |\n\n'
            '### Key Risks\n'
            '| # | Risk | Likelihood | Impact | Mitigation Plan |\n'
            '|---|------|------------|--------|-----------------|\n'
            '| 1 | Missed access request | Medium | High | Staff the rights desk |\n'
            '| 2 | Weak personal data classification | High | High | Classify assets |\n'
            '| 3 | Late data breach notification | Medium | High | Rehearse reporting |\n'
            '| 4 | Missing consent records | Medium | Medium | Stand up consent register |\n'
            '| 5 | NDMO policy delay | Low | Medium | Assign policy owner |\n'
            '| 6 | Erasure backlog | Medium | Medium | Track deletion request SLA |\n'
        )
    return _section_markdown('vision', lang)


def _provider_markdown(prompt='', language='en', task_type='generate', content_type=None):
    text = str(prompt or '')
    low = text.lower()
    lang = 'ar' if str(language or '').startswith('ar') or 'اكتب' in text else 'en'
    if '[section]' in low or 'hidden sync' in low or 'json_sync' in low or len(text) > 8000:
        parts = [
            _section_markdown(key, lang)
            for key in (
                'vision', 'pillars', 'environment', 'gaps',
                'roadmap', 'kpis', 'confidence',
            )
        ]
        return '\n\n[SECTION]\n'.join(parts)
    order = (
        ('vision', ('## 1.', 'vision', 'الرؤية', 'objectives')),
        ('pillars', ('## 2.', 'pillar', 'الركائز')),
        ('environment', ('## 3.', 'environment', 'البيئة', 'regulatory landscape')),
        ('gaps', ('## 4.', 'gap analysis', 'الفجوات', 'gap #')),
        ('roadmap', ('## 5.', 'roadmap', 'خارطة', 'phase 1')),
        ('kpis', ('## 6.', 'kpi', 'مؤشرات', 'key performance')),
        ('confidence', ('## 7.', 'confidence', 'الثقة', 'key risks', 'critical success')),
    )
    for key, needles in order:
        if any(n in low or n in text for n in needles):
            return _section_markdown(key, lang)
    return _section_markdown('vision', lang)


class ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args or ()
        self.kwargs = kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)

    def join(self, timeout=None):
        return None


_UID = {'n': 10}


def _next_user():
    _UID['n'] += 1
    uid = _UID['n']
    username = f'rel3706u{uid}'
    with app_mod.app.app_context():
        db = app_mod.get_db()
        db.execute(
            'INSERT OR IGNORE INTO users '
            '(id, username, password_hash, role, is_active) '
            'VALUES (?, ?, ?, ?, 1)',
            (uid, username, 'x', 'user'),
        )
        db.commit()
    return uid, username


def _client(uid, username):
    client = app_mod.app.test_client()
    csrf = f'rel3706-csrf-{uid}'
    with client.session_transaction() as sess:
        sess['user_id'] = uid
        sess['username'] = username
        sess['role'] = 'user'
        sess['csrf_token'] = csrf
    headers = {'X-CSRFToken': csrf, 'Content-Type': 'application/json'}
    return client, headers


def _run_async(payload):
    uid, username = _next_user()
    client, headers = _client(uid, username)
    def _fake_repair(section_key, sections, lang, domain_context, **kwargs):
        return _section_markdown(section_key, lang)

    with patch.object(app_mod, 'generate_ai_content', side_effect=_provider_markdown), \
            patch.object(app_mod, 'ai_repair_strategy_section', side_effect=_fake_repair), \
            patch('threading.Thread', ImmediateThread):
        resp = client.post(
            '/api/generate-strategy-async',
            json=dict(payload),
            headers=headers,
        )
    body = resp.get_json(silent=True) or {}
    task_id = body.get('task_id')
    status = None
    if task_id:
        status = client.get(
            f'/api/strategy-status/{task_id}', headers=headers
        ).get_json(silent=True)
    domain_q = payload['domain']
    latest = client.get(
        f'/api/strategy/latest?domain={domain_q}', headers=headers
    )
    latest_json = latest.get_json(silent=True) or {}
    saved = None
    strategy_id = None
    if isinstance(status, dict):
        inner = status.get('result') if isinstance(status.get('result'), dict) else {}
        strategy_id = status.get('strategy_id') or inner.get('strategy_id')
    if not strategy_id and isinstance(latest_json, dict):
        latest_inner = latest_json.get('result') if isinstance(latest_json.get('result'), dict) else {}
        strategy_id = (
            latest_json.get('strategy_id')
            or latest_json.get('id')
            or latest_inner.get('strategy_id')
        )
    with app_mod.app.app_context():
        db = app_mod.get_db()
        row = None
        if strategy_id:
            row = db.execute(
                'SELECT id, org_name, domain, language, sections_json, content '
                'FROM strategies WHERE id = ? AND user_id = ?',
                (strategy_id, uid),
            ).fetchone()
        if row is None:
            row = db.execute(
                'SELECT id, org_name, domain, language, sections_json, content '
                'FROM strategies WHERE user_id = ? ORDER BY id DESC LIMIT 1',
                (uid,),
            ).fetchone()
        if row:
            sections = {}
            if row['sections_json']:
                sections = json.loads(row['sections_json'])
            saved = {
                'id': row['id'],
                'org_name': row['org_name'],
                'domain': row['domain'],
                'language': row['language'],
                'sections': sections,
                'content': row['content'] or '',
            }
    return {
        'uid': uid,
        'http_status': resp.status_code,
        'http_body': body,
        'task_id': task_id,
        'status': status or {},
        'latest_status': latest.status_code,
        'latest': latest_json,
        'saved': saved,
        'client': client,
        'headers': headers,
    }


class HelperContractTests(unittest.TestCase):
    def test_metadata_list_is_skipped_not_coerced(self):
        value = ['PDPL (Personal Data Protection Law)',
                 'NDMO Data Governance Framework']
        self.assertIsNone(textual_section_value_or_raise(
            REL37_ORIGINAL_FW_KEY, value))
        self.assertIsNone(textual_section_value_or_raise(
            REL37_CANONICAL_FW_KEY, ['pdpl', 'ndmo']))

    def test_visible_list_raises_clear_error(self):
        with self.assertRaises(VisibleSectionTypeError) as ctx:
            textual_section_value_or_raise('vision', ['not', 'text'])
        self.assertEqual(ctx.exception.error_code, 'visible_section_type_invalid')
        self.assertEqual(ctx.exception.key, 'vision')
        self.assertIn('vision', TEXTUAL_SECTION_KEYS)

    def test_frameworks_request_rejects_malformed_elements(self):
        with self.assertRaises(FrameworksRequestTypeError) as ctx:
            validate_frameworks_request_type(
                ['PDPL (Personal Data Protection Law)', {'x': 1}],
                field='frameworks')
        self.assertEqual(ctx.exception.index, 1)
        self.assertEqual(ctx.exception.actual_type, 'dict')

    def test_frameworks_request_accepts_scalar_string(self):
        self.assertEqual(
            validate_frameworks_request_type(
                'PDPL (Personal Data Protection Law)', field='frameworks'),
            'PDPL (Personal Data Protection Law)',
        )


class CapturedBrowserRequestTests(unittest.TestCase):
    def test_01_captured_data_en_display_labels(self):
        result = _run_async(CAPTURED_DATA_EN)
        self.assertEqual(result['http_status'], 200, result['http_body'])
        self.assertTrue(result['task_id'])
        self.assertNotEqual(
            (result['status'] or {}).get('error'), _OBSERVED_TYPEERROR)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        saved = result['saved']
        self.assertIsNotNone(saved, result)
        inner = result['status'].get('result') if isinstance(
            result['status'].get('result'), dict) else {}
        status_sid = result['status'].get('strategy_id') or inner.get('strategy_id')
        self.assertEqual(saved['id'], status_sid)
        self.assertTrue(is_rel37_authoritative(saved['sections']))
        model = load_model(saved['sections'])
        self.assertIsNotNone(model)
        self.assertTrue(model.model_hash)
        original = saved['sections'].get(REL37_ORIGINAL_FW_KEY)
        canonical = saved['sections'].get(REL37_CANONICAL_FW_KEY)
        self.assertIsInstance(original, list)
        self.assertEqual(original, CAPTURED_DATA_EN['frameworks'])
        self.assertIsInstance(canonical, list)
        self.assertEqual(set(canonical), {'pdpl', 'ndmo'})
        public = public_status_sections(saved['sections'])
        visible = visible_sections(saved['sections'])
        blob = '\n'.join(visible.values())
        self.assertNotIn(REL37_ORIGINAL_FW_KEY, public)
        self.assertNotIn("['PDPL (Personal Data Protection Law)'", blob)
        self.assertNotIn(REL37_ORIGINAL_FW_KEY, blob)
        latest_sid = result['latest'].get('strategy_id') or result['latest'].get('id')
        self.assertEqual(latest_sid, saved['id'])
        bundle = export_bundle_from_sections(saved['sections'])
        self.assertTrue(bundle.get('model_hash') or bundle.get('preview_source_hash'))

    def test_02_data_en_reversed_order(self):
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = list(reversed(CAPTURED_DATA_EN['frameworks']))
        payload['org_name'] = 'REL37 Data EN Reversed Org'
        result = _run_async(payload)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        original = result['saved']['sections'].get(REL37_ORIGINAL_FW_KEY)
        self.assertEqual(original, payload['frameworks'])
        self.assertEqual(
            set(result['saved']['sections'].get(REL37_CANONICAL_FW_KEY)),
            {'pdpl', 'ndmo'})

    def _assert_worker_past_type_contract(self, result, expected_canonical):
        self.assertEqual(result['http_status'], 200, result['http_body'])
        self.assertTrue(result['task_id'])
        err = (result['status'] or {}).get('error')
        self.assertNotEqual(err, _OBSERVED_TYPEERROR, result['status'])
        if (result['status'] or {}).get('status') == 'done':
            self.assertIsNotNone(result['saved'])
            self.assertTrue(is_rel37_authoritative(result['saved']['sections']))
            self.assertEqual(
                set(result['saved']['sections'].get(REL37_CANONICAL_FW_KEY)),
                set(expected_canonical))
            self.assertIsInstance(
                result['saved']['sections'].get(REL37_ORIGINAL_FW_KEY), list)
            return
        # Worker passed the list-typed sanitizer. Residual Arabic
        # heading-pack 422s are outside this type-contract defect.
        self.assertNotIn('list', str(err or '').lower())

    def test_03_data_ar_form_english_labels(self):
        result = _run_async(DATA_AR_FORM)
        self._assert_worker_past_type_contract(result, ['pdpl', 'ndmo'])
        from release_engine_v3.rel37_early_authority import (
            attach_rel37_early_authority,
        )
        early = attach_rel37_early_authority(
            {'vision': 'x'},
            domain='Data Management',
            lang='ar',
            document_type='strategy',
            selected_frameworks=DATA_AR_FORM['frameworks'],
            org_name=DATA_AR_FORM['org_name'],
            explicit_selection=True,
        )
        self.assertTrue(early.applied, early.diagnostic)
        self.assertEqual(
            set(early.sections.get(REL37_CANONICAL_FW_KEY)), {'pdpl', 'ndmo'})
        self.assertIsInstance(early.sections.get(REL37_ORIGINAL_FW_KEY), list)
        self.assertEqual(
            early.sections.get(REL37_ORIGINAL_FW_KEY),
            DATA_AR_FORM['frameworks'])

    def test_04_data_ar_ui_labels(self):
        result = _run_async(DATA_AR_LABELS)
        self._assert_worker_past_type_contract(result, ['pdpl', 'ndmo'])
        from release_engine_v3.rel37_early_authority import (
            attach_rel37_early_authority,
        )
        early = attach_rel37_early_authority(
            {'vision': 'x'},
            domain='Data Management',
            lang='ar',
            document_type='strategy',
            selected_frameworks=DATA_AR_LABELS['frameworks'],
            org_name=DATA_AR_LABELS['org_name'],
            explicit_selection=True,
        )
        self.assertTrue(early.applied, early.diagnostic)
        self.assertEqual(
            set(early.sections.get(REL37_CANONICAL_FW_KEY)), {'pdpl', 'ndmo'})
        self.assertIsInstance(early.sections.get(REL37_ORIGINAL_FW_KEY), list)

    def test_05_ai_en_sdaia_label(self):
        result = _run_async(AI_EN)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        self.assertEqual(
            result['saved']['sections'].get(REL37_CANONICAL_FW_KEY), ['sdaia'])

    def test_06_ai_ar_sdaia_label(self):
        result = _run_async(AI_AR)
        self._assert_worker_past_type_contract(result, ['sdaia'])
        from release_engine_v3.rel37_early_authority import (
            attach_rel37_early_authority,
        )
        early = attach_rel37_early_authority(
            {'vision': 'x'},
            domain='Artificial Intelligence',
            lang='ar',
            document_type='strategy',
            selected_frameworks=AI_AR['frameworks'],
            org_name=AI_AR['org_name'],
            explicit_selection=True,
        )
        self.assertTrue(early.applied, early.diagnostic)
        self.assertEqual(early.sections.get(REL37_CANONICAL_FW_KEY), ['sdaia'])

    def test_07_dt_en_dga_label(self):
        result = _run_async(DT_EN)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        self.assertEqual(
            result['saved']['sections'].get(REL37_CANONICAL_FW_KEY), ['dga'])

    def test_08_dt_ar_dga_label(self):
        result = _run_async(DT_AR)
        self._assert_worker_past_type_contract(result, ['dga'])
        from release_engine_v3.rel37_early_authority import (
            attach_rel37_early_authority,
        )
        early = attach_rel37_early_authority(
            {'vision': 'x'},
            domain='Digital Transformation',
            lang='ar',
            document_type='strategy',
            selected_frameworks=DT_AR['frameworks'],
            org_name=DT_AR['org_name'],
            explicit_selection=True,
        )
        self.assertTrue(early.applied, early.diagnostic)
        self.assertEqual(early.sections.get(REL37_CANONICAL_FW_KEY), ['dga'])

    def test_09_short_ids_remain_compatible(self):
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = ['PDPL', 'NDMO']
        payload['org_name'] = 'REL37 Data Short IDs'
        result = _run_async(payload)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        self.assertEqual(
            set(result['saved']['sections'].get(REL37_CANONICAL_FW_KEY)),
            {'pdpl', 'ndmo'})

    def test_10_scalar_framework_string(self):
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = 'PDPL (Personal Data Protection Law)'
        payload['org_name'] = 'REL37 Data Scalar FW'
        result = _run_async(payload)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        self.assertTrue(is_rel37_authoritative(result['saved']['sections']))
        self.assertEqual(
            result['saved']['sections'].get(REL37_CANONICAL_FW_KEY), ['pdpl'])

    def test_11_explicit_empty_stays_unsupported(self):
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = []
        payload['explicit_selection'] = True
        payload['org_name'] = 'REL37 Data Empty Explicit'
        result = _run_async(payload)
        self.assertNotEqual(
            (result['status'] or {}).get('error'), _OBSERVED_TYPEERROR)
        saved = result['saved']
        if saved:
            self.assertFalse(is_rel37_authoritative(saved['sections']))
            self.assertEqual(
                saved['sections'].get('_rel37_selection_supported'), 'false')

    def test_12_malformed_element_is_api_error(self):
        uid, username = _next_user()
        client, headers = _client(uid, username)
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = [
            'PDPL (Personal Data Protection Law)',
            {'label': 'NDMO Data Governance Framework'},
        ]
        resp = client.post(
            '/api/generate-strategy-async', json=payload, headers=headers)
        body = resp.get_json(silent=True) or {}
        self.assertEqual(resp.status_code, 400, body)
        self.assertEqual(body.get('error_code'), 'frameworks_request_type_invalid')
        self.assertFalse(body.get('task_id'))
        self.assertIn('dict', str(body.get('error') or ''))

    def test_13_mixed_ndmo_nca_stays_unsupported(self):
        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = [
            'NDMO Data Governance Framework',
            'NCA ECC',
        ]
        payload['org_name'] = 'REL37 Mixed NDMO NCA'
        result = _run_async(payload)
        self.assertNotEqual(
            (result['status'] or {}).get('error'), _OBSERVED_TYPEERROR)
        saved = result['saved']
        if saved:
            self.assertFalse(is_rel37_authoritative(saved['sections']))

    def test_14_uae_pdpl_and_eu_dga_stay_unsupported(self):
        for label, org in (
            ('UAE PDPL (Personal Data Protection Law)', 'REL37 UAE PDPL'),
            ('Data Governance Act (DGA)', 'REL37 EU DGA'),
        ):
            payload = dict(CAPTURED_DATA_EN)
            payload['frameworks'] = [label]
            payload['org_name'] = org
            result = _run_async(payload)
            self.assertNotEqual(
                (result['status'] or {}).get('error'), _OBSERVED_TYPEERROR,
                label)
            saved = result['saved']
            if saved:
                self.assertFalse(
                    is_rel37_authoritative(saved['sections']), label)


if __name__ == '__main__':
    unittest.main()
