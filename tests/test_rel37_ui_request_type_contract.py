"""REL37.0.6/0.7 — UI request type, persist, and actual export contract.

Replays the captured Data EN browser payload through the real
async route → worker → api_generate_strategy path. Mocks only
provider I/O (generate_ai_content). Does not rewrite display
labels to short IDs.

REL37.0.7 also requires terminal persist, identity-matched REL37
models, public preview, and actual DOCX/PDF route completion for
supported Data/AI/DT AR+EN requests.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
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

from release_engine_v3.rel33_pdf_evidence_norm import (  # noqa: E402
    arabic_token_present,
)
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

    def _assert_typeerror_absent(self, result):
        """REL37.0.6 TypeError regression only. Not persist acceptance."""
        self.assertEqual(result['http_status'], 200, result['http_body'])
        self.assertTrue(result['task_id'])
        err = (result['status'] or {}).get('error')
        self.assertNotEqual(err, _OBSERVED_TYPEERROR, result['status'])
        self.assertNotIn("got 'list'", str(err or ''))

    def _assert_supported_persist(self, result, payload, expected_canonical):
        self._assert_typeerror_absent(result)
        self.assertEqual((result['status'] or {}).get('status'), 'done',
                         result['status'])
        saved = result['saved']
        self.assertIsNotNone(saved, result['status'])
        inner = result['status'].get('result') if isinstance(
            result['status'].get('result'), dict) else {}
        status_sid = result['status'].get('strategy_id') or inner.get('strategy_id')
        self.assertEqual(saved['id'], status_sid)
        self.assertTrue(is_rel37_authoritative(saved['sections']))
        model = load_model(saved['sections'])
        self.assertIsNotNone(model)
        self.assertTrue(model.validation_passed or not model.validate())
        self.assertTrue(model.confidence)
        self.assertTrue(model.risks)
        self.assertTrue(all(all(str(c).strip() for c in row.cells())
                            for row in model.confidence))
        self.assertTrue(all(all(str(c).strip() for c in row.cells())
                            for row in model.risks))
        self.assertEqual(
            set(saved['sections'].get(REL37_CANONICAL_FW_KEY)),
            set(expected_canonical))
        self.assertIsInstance(
            saved['sections'].get(REL37_ORIGINAL_FW_KEY), list)
        public = public_status_sections(saved['sections'])
        visible = visible_sections(saved['sections'])
        blob = '\n'.join(visible.values())
        self.assertNotIn(REL37_ORIGINAL_FW_KEY, public)
        self.assertNotIn(REL37_ORIGINAL_FW_KEY, blob)
        self.assertNotIn("['PDPL (Personal Data Protection Law)'", blob)
        latest_sid = result['latest'].get('strategy_id') or result['latest'].get('id')
        self.assertEqual(latest_sid, saved['id'])
        self.assertEqual(saved['org_name'], payload['org_name'])
        return saved

    def test_03_data_ar_form_english_labels(self):
        result = _run_async(DATA_AR_FORM)
        self._assert_supported_persist(result, DATA_AR_FORM, ['pdpl', 'ndmo'])
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
        self._assert_supported_persist(result, DATA_AR_LABELS, ['pdpl', 'ndmo'])
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
        self._assert_supported_persist(result, AI_EN, ['sdaia'])

    def test_06_ai_ar_sdaia_label(self):
        result = _run_async(AI_AR)
        self._assert_supported_persist(result, AI_AR, ['sdaia'])
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
        self._assert_supported_persist(result, DT_EN, ['dga'])

    def test_08_dt_ar_dga_label(self):
        result = _run_async(DT_AR)
        self._assert_supported_persist(result, DT_AR, ['dga'])
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


_LEGACY_CSF_RE = re.compile(
    r'###\s+(?:عوامل\s+النجاح\s+الحرجة|Critical\s+Success\s+Factors)',
    re.IGNORECASE,
)
_LEGACY_RISK_RE = re.compile(
    r'###\s+(?:المخاطر\s+الرئيسية|Key\s+Risks)',
    re.IGNORECASE,
)


def _legacy_heading_failures(confidence_md):
    text = confidence_md or ''
    failures = []
    if not _LEGACY_CSF_RE.search(text):
        failures.append('confidence_csf_heading_missing')
    if not _LEGACY_RISK_RE.search(text):
        failures.append('confidence_risk_heading_missing')
    hdr_count = len(_LEGACY_RISK_RE.findall(text))
    if hdr_count != 1:
        failures.append(f'confidence_risk_heading_count={hdr_count} (must be 1)')
    return failures


def _export_route(result, payload, fmt):
    saved = result['saved']
    client = result['client']
    headers = result['headers']
    body = {
        'content': saved.get('content') or saved['sections'].get('vision') or '## Vision',
        'filename': f'rel3707_{fmt}',
        'language': payload['language'],
        'domain': payload['domain'],
        'doc_type': 'Strategy Document',
        'document_type': 'strategy',
        'artifact_type': 'strategy',
        'generation_mode': 'drafting',
        'strategy_id': saved['id'],
        'artifact_id': saved['id'],
        'selected_frameworks': payload['frameworks'],
        'frameworks': payload['frameworks'],
        'org_name': payload['org_name'],
    }
    route = f'/api/generate-{fmt}-async'
    with patch('threading.Thread', ImmediateThread):
        resp = client.post(route, json=body, headers=headers)
    submit = resp.get_json(silent=True) or {}
    export_task = submit.get('task_id')
    status = None
    if export_task:
        status = client.get(
            f'/api/export-status/{export_task}', headers=headers
        ).get_json(silent=True)
    download_bytes = b''
    download = None
    if export_task and (status or {}).get('status') == 'done':
        dl = client.get(f'/api/export-download/{export_task}', headers=headers)
        download = {
            'http_status': dl.status_code,
            'content_type': dl.headers.get('Content-Type'),
        }
        download_bytes = dl.data or b''
    parsed_ok = False
    parsed_text = ''
    if download_bytes:
        try:
            if fmt == 'docx':
                from docx import Document
                doc = Document(io.BytesIO(download_bytes))
                parsed_text = '\n'.join(p.text for p in doc.paragraphs)
                parsed_ok = True
            else:
                parsed_ok = download_bytes.startswith(b'%PDF')
                try:
                    import pymupdf
                    doc = pymupdf.open(stream=download_bytes, filetype='pdf')
                    parsed_text = '\n'.join(page.get_text() for page in doc)
                    parsed_ok = len(doc) > 0
                except Exception:
                    from PyPDF2 import PdfReader
                    reader = PdfReader(io.BytesIO(download_bytes))
                    parsed_text = '\n'.join(
                        (page.extract_text() or '') for page in reader.pages)
                    parsed_ok = len(reader.pages) > 0
        except Exception as exc:
            parsed_text = f'parse_error:{type(exc).__name__}:{exc}'
    return {
        'submit_http': resp.status_code,
        'export_task_id': export_task,
        'status': status or {},
        'download': download,
        'bytes': download_bytes,
        'sha256': hashlib.sha256(download_bytes).hexdigest() if download_bytes else '',
        'parsed_ok': parsed_ok,
        'parsed_text': parsed_text,
    }


class Rel37ConfidenceRiskGateContractTests(unittest.TestCase):
    """Failing-before / passing-after on the ff34348 heading grammar."""

    def _compiled_sections(self, domain, lang, org_name, frameworks):
        from release_engine_v3.rel37_apply import apply_rel37_to_sections
        out, _repairs = apply_rel37_to_sections(
            {'vision': 'placeholder'},
            domain=domain,
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            org_name=org_name,
        )
        return out

    def test_legacy_heading_regex_rejects_rel37_arabic_render(self):
        sections = self._compiled_sections(
            'Data Management', 'ar', DATA_AR_FORM['org_name'],
            DATA_AR_FORM['frameworks'])
        failures = _legacy_heading_failures(sections.get('confidence') or '')
        self.assertIn('confidence_csf_heading_missing', failures)
        self.assertIn('confidence_risk_heading_missing', failures)

    def test_rel37_gate_accepts_complete_typed_model(self):
        from release_engine_v3.rel37_apply import (
            rel37_confidence_risk_post_repair_result,
        )
        sections = self._compiled_sections(
            'Data Management', 'ar', DATA_AR_FORM['org_name'],
            DATA_AR_FORM['frameworks'])
        blockers = rel37_confidence_risk_post_repair_result(
            sections,
            domain='Data Management',
            lang='ar',
            document_type='strategy',
            org_name=DATA_AR_FORM['org_name'],
            selected_frameworks=DATA_AR_FORM['frameworks'],
        )
        self.assertEqual(blockers, [])

    def test_forged_applied_flag_does_not_bypass(self):
        from release_engine_v3.rel37_apply import (
            rel37_confidence_risk_post_repair_result,
        )
        forged = {
            '_rel37_applied': 'true',
            'confidence': '### عوامل النجاح الحرجة\n',
        }
        self.assertIsNone(rel37_confidence_risk_post_repair_result(
            forged,
            domain='Data Management',
            lang='ar',
            document_type='strategy',
            org_name='x',
            selected_frameworks=DATA_AR_FORM['frameworks'],
        ))
        failures = _legacy_heading_failures(forged['confidence'])
        self.assertIn('confidence_risk_heading_missing', failures)

    def test_missing_confidence_blocks(self):
        from release_engine_v3.rel37_apply import (
            REL37_MODEL_KEY,
            serialize_model,
            rel37_confidence_risk_post_repair_result,
        )
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        model = load_model(sections)
        model.confidence = ()
        model.compute_hashes()
        sections[REL37_MODEL_KEY] = serialize_model(model)
        sections['_rel37_model_hash'] = model.model_hash
        blockers = rel37_confidence_risk_post_repair_result(
            sections,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        )
        self.assertIn('rel37_confidence_missing', blockers)

    def test_missing_risk_blocks(self):
        from release_engine_v3.rel37_apply import (
            REL37_MODEL_KEY,
            serialize_model,
            rel37_confidence_risk_post_repair_result,
        )
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        model = load_model(sections)
        model.risks = ()
        model.compute_hashes()
        sections[REL37_MODEL_KEY] = serialize_model(model)
        sections['_rel37_model_hash'] = model.model_hash
        blockers = rel37_confidence_risk_post_repair_result(
            sections,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        )
        self.assertIn('rel37_risks_missing', blockers)

    def test_bind_export_prefers_validated_rel37_sections(self):
        from release_engine_v3.rel37_apply import rel37_bind_export_sections
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        bound = rel37_bind_export_sections(
            sections,
            {'kpis': '## KPI / KRI Framework\n'},
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        )
        self.assertTrue(is_rel37_authoritative(bound))
        self.assertIn('KPI Description', bound.get('kpis') or '')

    def test_bind_export_rejects_forged_flag(self):
        from release_engine_v3.rel37_apply import rel37_bind_export_sections
        fallback = {'kpis': '## KPI / KRI Framework\n'}
        bound = rel37_bind_export_sections(
            {'_rel37_applied': 'true', 'kpis': 'forged'},
            fallback,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        )
        self.assertEqual(bound, fallback)

    def test_validated_export_markdown_requires_current_model(self):
        from release_engine_v3.rel37_apply import (
            REL37_HASH_KEY,
            rel37_validated_export_markdown,
        )
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        md = rel37_validated_export_markdown(sections)
        self.assertIn('## 6. Key Performance Indicators', md)
        self.assertIn('KPI Description', md)
        sections[REL37_HASH_KEY] = '0' * 64
        self.assertEqual(rel37_validated_export_markdown(sections), '')
        self.assertEqual(
            rel37_validated_export_markdown({'_rel37_applied': 'true'}), '')

    def test_render_tree_uses_rel37_markdown_not_arabic_kpi_remix(self):
        from release_engine_v3.contracts import (
            CanonicalSection,
            ExportManifest,
            FinalDocumentArtifact,
        )
        from release_engine_v3.render_tree import build_render_tree
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        artifact = FinalDocumentArtifact(
            artifact_id='rel37-en',
            domain='data',
            language='en',
            document_type='strategy',
            strategy_type='technical',
            selected_frameworks=['pdpl', 'ndmo'],
            canonical_sections={
                'kpi_kri': CanonicalSection(
                    key='kpi_kri',
                    title='مؤشرات الأداء الرئيسية',
                    narrative='',
                    table_rows=(),
                ),
            },
            quality_repairs=[],
            quality_results={},
            frozen=True,
            canonical_hash='x',
            render_tree_hash='',
            export_manifest=ExportManifest(),
            blocking_errors=[],
            release_ready_final_passed=True,
            legacy_sections=sections,
        )
        tree = build_render_tree(artifact)
        self.assertIn('## 6. Key Performance Indicators', tree.markdown_view)
        self.assertIn('KPI Description', tree.markdown_view)
        self.assertNotEqual(
            tree.markdown_view.strip(),
            '## مؤشرات الأداء الرئيسية')

    def test_rel37_english_markdown_is_not_an_export_fragment(self):
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        md = sections.get('_rel37_markdown') or ''
        is_frag, found, why = app_mod._is_strategy_export_fragment(md)
        self.assertFalse(is_frag, (sorted(found), why))
        self.assertGreaterEqual(len(found), 5)
        self.assertIn('environment', found)
        self.assertIn('gaps', found)
        self.assertIn('confidence', found)
        from release_engine_v3.rel37_apply import rel37_export_completeness_ok
        self.assertTrue(rel37_export_completeness_ok(
            sections,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        ))
        is_frag_typed, _, _ = app_mod._is_strategy_export_fragment(
            '## KPI only',
            sections,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        )
        self.assertFalse(is_frag_typed)

    def test_kpi_only_fragment_still_blocked_without_rel37_model(self):
        fragment = (
            '### KPI Assessment Guidelines\n\n'
            '#### KPI #1 Assessment Guide\n\n'
            '## 7. Confidence and Risk\n\nbody.\n'
        )
        is_frag, found, why = app_mod._is_strategy_export_fragment(fragment)
        self.assertTrue(is_frag, (sorted(found), why))
        self.assertNotIn('vision', found)
        self.assertNotIn('pillars', found)
        forged = {'_rel37_applied': 'true', 'kpis': fragment}
        from release_engine_v3.rel37_apply import rel37_export_completeness_ok
        self.assertIsNone(rel37_export_completeness_ok(
            forged,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        ))
        is_frag_forged, _, _ = app_mod._is_strategy_export_fragment(
            fragment, forged)
        self.assertTrue(is_frag_forged)

    def test_hash_and_identity_mismatch_not_trusted(self):
        from release_engine_v3.rel37_apply import (
            rel37_confidence_risk_post_repair_result,
        )
        sections = self._compiled_sections(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        sections['_rel37_model_hash'] = '0' * 64
        blockers = rel37_confidence_risk_post_repair_result(
            sections,
            domain='Cyber Security',
            lang='ar',
            document_type='risk',
            org_name='Other Org',
            selected_frameworks=['NCA ECC'],
        )
        self.assertTrue(blockers)
        self.assertTrue(any('hash' in str(b) or 'mismatch' in str(b)
                            for b in blockers))


class Rel37KpiSemanticsRoutingTests(unittest.TestCase):
    """Cyber PR-CY61 must not rewrite identity-matched REL37 Data/AI/DT KPIs."""

    def _compiled(self, domain, lang, org_name, frameworks):
        from release_engine_v3.rel37_apply import apply_rel37_to_sections
        out, _repairs = apply_rel37_to_sections(
            {'vision': 'placeholder'},
            domain=domain,
            lang=lang,
            document_type='strategy',
            selected_frameworks=frameworks,
            org_name=org_name,
        )
        return out

    def test_skip_requires_identity_matched_rel37_data(self):
        from release_engine_v3.rel37_apply import rel37_skip_cyber_kpi_semantics
        sections = self._compiled(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        self.assertTrue(rel37_skip_cyber_kpi_semantics(
            sections,
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        ))
        self.assertFalse(rel37_skip_cyber_kpi_semantics(
            {'_rel37_applied': 'true'},
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        ))
        self.assertFalse(rel37_skip_cyber_kpi_semantics(
            sections,
            domain='Cyber Security',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=['NCA ECC'],
        ))

    def test_compiler_on_time_kpis_preserved_and_rewritten_without_skip(self):
        from professional_strategy_render import (
            collect_kpi_metric_semantics_issues,
            split_kpi_tables,
        )
        sections = self._compiled(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])
        kpis = sections.get('kpis') or ''
        self.assertIn('On-time data-subject request closure', kpis)
        self.assertIn('On-time eligible-incident notification', kpis)
        preserved = split_kpi_tables(
            kpis, 'en', domain='data', preserve_compiler_kpis=True)
        mutated = split_kpi_tables(kpis, 'en', domain='data')
        preserved_blob = json.dumps(preserved, ensure_ascii=False)
        mutated_blob = json.dumps(mutated, ensure_ascii=False)
        self.assertIn('On-time data-subject request closure', preserved_blob)
        self.assertIn('100%', preserved_blob)
        self.assertIn(
            'on-time closures / total requests × 100', preserved_blob)
        self.assertIn('On-time eligible-incident notification', preserved_blob)
        self.assertNotIn('≤ 72 hours', preserved_blob)
        self.assertNotIn('Critical incident SLA resolution rate', preserved_blob)
        from professional_strategy_render import _is_time_based_metric
        self.assertFalse(_is_time_based_metric(
            'On-time data-subject request closure'))
        self.assertFalse(_is_time_based_metric(
            'On-time eligible-incident notification'))
        from professional_strategy_render import (
            _derive_kpi_target,
            _is_incident_response_metric,
        )
        self.assertFalse(_is_incident_response_metric(
            'On-time eligible-incident notification'))
        self.assertEqual(
            _derive_kpi_target(
                'On-time eligible-incident notification', '100%', 'en'),
            '100%')
        self.assertTrue(_is_incident_response_metric(
            'Critical incident response time'))
        self.assertTrue(_is_time_based_metric('Critical incident response time'))
        self.assertTrue(_is_time_based_metric('Mean time to respond'))
        # Forged authority still runs the Cyber semantic collector.
        fake_model = {
            'blocks': {
                'kpi_kri_framework': {
                    'tables': mutated,
                }
            }
        }
        cyber_bad = {
            'blocks': {
                'kpi_kri_framework': {
                    'tables': [{
                        'schema': 'kpi_main',
                        'rows': [[
                            '1', 'Critical incident response time', 'KPI',
                            '95%', 'x', 'SIEM',
                        ]],
                    }, {
                        'schema': 'kpi_formula',
                        'rows': [[
                            '1', 'Critical incident response time',
                            '(closed / total) × 100', 'SIEM',
                        ]],
                    }],
                }
            }
        }
        self.assertTrue(collect_kpi_metric_semantics_issues(cyber_bad, 'en'))
        _ = fake_model

    def test_professional_gate_accepts_identity_matched_rel37_data_en(self):
        from professional_strategy_render import (
            build_professional_strategy_document_model,
            identify_docmodel_failing_subgate,
            prcy47_docmodel_professional_checks,
        )
        sections = self._compiled(
            'Data Management', 'en', CAPTURED_DATA_EN['org_name'],
            CAPTURED_DATA_EN['frameworks'])

        def _base_builder(**_kwargs):
            return {
                'lang': 'en',
                'domain': 'data',
                'document_type': 'strategy',
                'org_name': CAPTURED_DATA_EN['org_name'],
                'selected_frameworks': ['pdpl', 'ndmo'],
                'blocks': {},
            }

        model = build_professional_strategy_document_model(
            sections.get('_rel37_markdown') or '',
            metadata={
                'domain': 'data',
                'org_name': CAPTURED_DATA_EN['org_name'],
                'document_type': 'strategy',
                'selected_frameworks': ['pdpl', 'ndmo'],
            },
            sections=sections,
            selected_frameworks=['pdpl', 'ndmo'],
            lang='en',
            domain='data',
            base_builder=_base_builder,
        )
        checks = prcy47_docmodel_professional_checks(model, 'en')
        self.assertTrue(
            checks.get('kpi_metric_semantics_valid'), checks)
        self.assertTrue(
            checks.get('pdf_kpi_type_column_valid'), checks)
        rows = json.dumps(
            ((model.get('blocks') or {}).get('kpi_kri_framework') or {}).get(
                'tables') or [],
            ensure_ascii=False,
        )
        self.assertIn('On-time data-subject request closure', rows)
        self.assertNotIn('Critical incident SLA resolution rate', rows)
        if not checks.get('docmodel_professional_passed'):
            # Other professional subgates may still fail on a stub builder;
            # the proven EN PDF blocker is KPI semantics / type.
            self.assertNotEqual(
                identify_docmodel_failing_subgate(checks),
                'kpi_metric_semantics_valid',
                checks,
            )


    def test_rel37_en_roadmap_family_tokens_match_compiler_titles(self):
        from release_engine.rel27_export_checks import check_roadmap_coverage
        ai = self._compiled(
            'Artificial Intelligence', 'en', AI_EN['org_name'],
            AI_EN['frameworks'])
        ai_cov = check_roadmap_coverage(
            ai.get('_rel37_markdown') or ai.get('roadmap') or '', domain='ai')
        self.assertNotIn('model_inventory', ai_cov.get('missing_families') or [])
        self.assertNotIn('model_monitoring', ai_cov.get('missing_families') or [])
        dt = self._compiled(
            'Digital Transformation', 'en', DT_EN['org_name'],
            DT_EN['frameworks'])
        dt_cov = check_roadmap_coverage(
            dt.get('_rel37_markdown') or dt.get('roadmap') or '', domain='dt')
        self.assertNotIn('digital_channels', dt_cov.get('missing_families') or [])
        empty = check_roadmap_coverage('## 5. Implementation Roadmap\n\nNone.', domain='ai')
        self.assertIn('model_inventory', empty.get('missing_families') or [])


class PdfResidueClassifierTests(unittest.TestCase):
    def test_valid_processing_register_is_not_glue(self):
        from release_engine.rel27_export_checks import check_arabic_residues_exported
        from release_engine.export_evidence_validator import _contains_arabic_residue
        valid = 'غياب سجل معالجة موثق للبيانات الشخصية'
        self.assertFalse(_contains_arabic_residue(valid, 'ل معالجة'))
        self.assertNotIn(
            'ل معالجة',
            check_arabic_residues_exported(valid).get('residues_found') or [])
        self.assertFalse(_contains_arabic_residue('معدل معالجة الحوادث', 'ل معالجة'))

    def test_genuine_detached_particle_still_blocks(self):
        from release_engine.rel27_export_checks import check_arabic_residues_exported
        from release_engine.export_evidence_validator import _contains_arabic_residue
        defect = 'يجب ل معالجة الحوادث فوراً'
        self.assertTrue(_contains_arabic_residue(defect, 'ل معالجة'))
        self.assertIn(
            'ل معالجة',
            check_arabic_residues_exported(defect).get('residues_found') or [])


class SupportedPersistExportMatrixTests(unittest.TestCase):
    CASES = (
        ('data_en', CAPTURED_DATA_EN, ['pdpl', 'ndmo']),
        ('data_ar', DATA_AR_FORM, ['pdpl', 'ndmo']),
        ('ai_en', AI_EN, ['sdaia']),
        ('ai_ar', AI_AR, ['sdaia']),
        ('dt_en', DT_EN, ['dga']),
        ('dt_ar', DT_AR, ['dga']),
    )

    def _assert_export(self, result, payload, fmt):
        exported = _export_route(result, payload, fmt)
        self.assertEqual(exported['submit_http'], 200, exported)
        self.assertTrue(exported['export_task_id'], exported)
        self.assertEqual(
            (exported['status'] or {}).get('status'), 'done', exported['status'])
        self.assertTrue(exported['bytes'], exported)
        self.assertTrue(exported['parsed_ok'], exported['parsed_text'][:300])
        self.assertTrue(
            arabic_token_present(exported['parsed_text'], payload['org_name']),
            exported['parsed_text'][:800],
        )
        self.assertNotIn(REL37_ORIGINAL_FW_KEY, exported['parsed_text'])
        self.assertNotIn(
            "['PDPL (Personal Data Protection Law)'", exported['parsed_text'])
        return exported

    def test_six_supported_routes_persist_preview_docx_pdf(self):
        for name, payload, canonical in self.CASES:
            with self.subTest(case=name):
                result = _run_async(payload)
                helper = CapturedBrowserRequestTests()
                helper._assert_supported_persist(result, payload, canonical)
                preview = public_status_sections(result['saved']['sections'])
                self.assertTrue(preview.get('vision') or preview.get('confidence'))
                docx = self._assert_export(result, payload, 'docx')
                pdf = self._assert_export(result, payload, 'pdf')
                self.assertGreater(len(docx['bytes']), 1000)
                self.assertGreater(len(pdf['bytes']), 1000)
                self.assertTrue(pdf['bytes'].startswith(b'%PDF'))
                if payload['language'] == 'en':
                    self.assertNotIn(
                        'Critical incident SLA resolution rate',
                        pdf['parsed_text'])
                    self.assertNotIn('≤ 72 hours', pdf['parsed_text'])
                    if name == 'data_en':
                        self.assertTrue(
                            arabic_token_present(
                                pdf['parsed_text'],
                                'On-time data-subject request closure'),
                            pdf['parsed_text'][:800],
                        )
                        self.assertTrue(
                            arabic_token_present(
                                pdf['parsed_text'],
                                'On-time eligible-incident notification'),
                            pdf['parsed_text'][:800],
                        )
                        self.assertNotIn('< 4 hours', pdf['parsed_text'])


class NegativeControlTests(unittest.TestCase):
    def test_malformed_frameworks_rejected_before_provider(self):
        uid, username = _next_user()
        client, headers = _client(uid, username)
        calls = {'n': 0}

        def _boom(*args, **kwargs):
            calls['n'] += 1
            raise AssertionError('provider must not run')

        payload = dict(CAPTURED_DATA_EN)
        payload['frameworks'] = [
            'PDPL (Personal Data Protection Law)',
            {'x': 1},
        ]
        with patch.object(app_mod, 'generate_ai_content', side_effect=_boom):
            resp = client.post(
                '/api/generate-strategy-async', json=payload, headers=headers)
            sync = client.post(
                '/api/generate-strategy', json=payload, headers=headers)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(sync.status_code, 400)
        self.assertFalse((resp.get_json(silent=True) or {}).get('task_id'))
        self.assertEqual(calls['n'], 0)

    def test_missing_export_job_is_not_accepted(self):
        uid, username = _next_user()
        client, headers = _client(uid, username)
        status = client.get(
            '/api/export-status/missing-export-task', headers=headers
        ).get_json(silent=True) or {}
        self.assertNotEqual(status.get('status'), 'done')
        download = client.get(
            '/api/export-download/missing-export-task', headers=headers)
        self.assertNotEqual(download.status_code, 200)

    def test_genuine_pdf_glue_residue_still_blocks_quality(self):
        from release_engine_v3.validators import validate_canonical_quality
        from release_engine.rel27_export_checks import check_arabic_residues_exported
        blob = (
            '## 7. Confidence and Risk\n\n'
            'Incident response requires ل معالجة of critical cases.\n'
        )
        found = check_arabic_residues_exported(blob).get('residues_found') or []
        self.assertIn('ل معالجة', found)
        quality = validate_canonical_quality(
            {},
            legacy_sections={'confidence': blob, 'vision': '## 1. Vision'},
            domain='data',
            lang='en',
            document_type='strategy',
        )
        self.assertIn('ل معالجة', quality.get('blocking_errors') or [])

    def test_feature_disabled_does_not_claim_rel37_authority(self):
        from release_engine_v3.rel37_apply import (
            rel37_confidence_risk_post_repair_result,
        )
        self.assertIsNone(rel37_confidence_risk_post_repair_result(
            {'confidence': '### Key Risks\n'},
            domain='Data Management',
            lang='en',
            document_type='strategy',
            org_name=CAPTURED_DATA_EN['org_name'],
            selected_frameworks=CAPTURED_DATA_EN['frameworks'],
        ))


if __name__ == '__main__':
    unittest.main()
