"""REL37 Data EN guide-completeness persist — real worker path.

Reproduces the staging e9d7643 first-gate / typed-model boundary
without ImmediateThread, without patching ai_repair_strategy_section,
and without legacy guide headings in the provider stub.

CI blind spot in tests/test_rel37_ui_request_type_contract.py:
it injects Gap/KPI guide headings, patches ai_repair_strategy_section,
and substitutes ImmediateThread. That combination never reaches the
legacy richness gate against heading-less provider text.
"""
from __future__ import annotations

import json
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
    'REL2_SKIP_EXPORT_EVIDENCE', 'REL37_DATA_AI_DT_COMPILER', 'TESTING',
)
_ENV_BEFORE = {key: os.environ.get(key) for key in _ENV_KEYS}

_TMP = tempfile.mkdtemp(prefix='test_rel37_guide_persist_')
os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'rel37_guide.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'rel37_guide.db')
os.environ['OPENAI_API_KEY'] = 'sk-test-rel37-guide-persist'
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'
os.environ['TESTING'] = '1'
os.environ.pop('REL2_SKIP_EXPORT_EVIDENCE', None)

import openai  # noqa: E402
import app as app_mod  # noqa: E402

app_mod.config.OPENAI_API_KEY = os.environ['OPENAI_API_KEY']
app_mod.config.ANTHROPIC_API_KEY = ''
app_mod.config.GOOGLE_API_KEY = ''
app_mod.config.AI_PROVIDER = 'openai'

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_APPLIED_KEY,
    REL37_HASH_KEY,
    REL37_MODEL_KEY,
    is_rel37_authoritative,
    load_model,
    rel37_guide_completeness_persist_result,
    rel37_request_model_consistent,
)
from release_engine_v3.rel37_early_authority import attach_rel37_early_authority  # noqa: E402
from release_engine_v3.rel37_export_content_parity import extract_pdf_text  # noqa: E402
from release_engine_v3.rel37_live_attach import stamp_rel37_keys  # noqa: E402
from release_engine_v3.rel37_preview_section_contract import public_status_sections  # noqa: E402
from release_engine_v3.rel37_selection import rel37_supported_selection  # noqa: E402

GUIDE_ERROR = (
    'Technical Strategy cannot be saved without: Gap Implementation Guides, '
    'KPI Assessment Guidelines. These sections are mandatory for Technical '
    'Strategy (including drafting mode). Please regenerate.'
)
FORBIDDEN_HEADINGS = (
    'Gap #1 Implementation Guide',
    'KPI Assessment Guidelines',
    'KPI #1 Assessment Guide',
    'Workstream 1',
    'Step-by-Step',
)
_PDPL = (
    'data subject rights, access request, rectification, erasure, '
    'personal data classification, data breach notification, consent management'
)

# Observed UI fields from staging. Fields marked reconstructed were not
# recovered from a HAR / full request body.
UI_REQUEST = {
    'domain': 'Data Management',
    'language': 'en',
    'doc_subtype': 'technical',
    'generation_mode': 'drafting',
    'frameworks': [
        'PDPL (Personal Data Protection Law)',
        'NDMO Data Governance Framework',
    ],
    'org_name': 'REL37.13 Data EN UI Org',
    'sector': 'Government',  # reconstructed
    'size': 'Small (<100)',  # reconstructed
    'budget': '< 1M SAR',  # reconstructed
    'org_structure': 'centralized',  # reconstructed
    'technologies': [],  # reconstructed
    'additional_tech': '',  # reconstructed
    'maturity_level': 'initial',  # reconstructed
    'challenges': '',  # reconstructed
    'diagnostic_id': None,
}


def _thin_section(key, *, wrong_section_guides=False, with_headings=False):
    extra = ''
    if with_headings and key == 'gaps':
        extra = (
            '\n\n#### Gap #1 Implementation Guide\n'
            '| Step | Action | Owner | Timeline | Output |\n'
            '|------|--------|-------|----------|--------|\n'
            '| 1 | Publish access request procedure | DPO | Week 1 | SOP |\n'
        )
    if with_headings and key == 'kpis':
        extra = (
            '\n\n### KPI Assessment Guidelines\n'
            '| KPI | Assessment Method | Owner |\n'
            '|-----|-------------------|-------|\n'
            '| 1 | Access request cycle time | DPO |\n'
            '#### KPI #1 Assessment Guide\n'
        )
    if wrong_section_guides and key == 'vision':
        extra = (
            '\n\nGuide-like prose only: Gap #1 Implementation Guide and '
            'KPI Assessment Guidelines belong in operations, not vision.\n'
        )
    tables = {
        'vision': (
            '## 1. Vision and Objectives\n\n' + _PDPL + '\n\n'
            '| # | Objective | Target Metric | Justification | Timeframe |\n'
            '|---|-----------|---------------|---------------|-----------|\n'
            '| 1 | Establish data office | Charter approved | Closes gap 1 | 6 months |\n'
            '| 2 | Data subject rights | 100% SLA | PDPL | 9 months |\n'
            '| 3 | Classify personal data | 100% assets | PDPL | 6 months |\n'
            '| 4 | Breach notification | Procedure | PDPL | 6 months |\n'
            '| 5 | Consent register | Live register | PDPL | 9 months |\n'
            '| 6 | NDMO policy | Policy approved | NDMO | 12 months |\n'
        ),
        'pillars': (
            '## 2. Strategic Pillars\n\n' + _PDPL + '\n\n'
            '### Pillar 1: Data governance\n'
            'Narrative covering data subject rights and personal data classification.\n\n'
            '| Initiative | Description | Expected Deliverable | Owner |\n'
            '|------------|-------------|----------------------|-------|\n'
            '| Rights desk | Operate access request and erasure | RACI | DPO |\n'
        ),
        'environment': (
            '## 3. Business Environment\n\n' + _PDPL + '\n\n'
            'Regulatory landscape includes PDPL (Personal Data Protection Law) '
            'and NDMO Data Governance Framework.\n'
        ),
        'gaps': (
            '## 4. Gap Analysis\n\n' + _PDPL + '\n\n'
            '| # | Gap | Description | Priority | Status |\n'
            '|---|-----|-------------|----------|--------|\n'
            '| 1 | No data subject rights path | Access request missing | High | Open |\n'
            '| 2 | Weak personal data classification | Sensitive unmarked | High | Open |\n'
            '| 3 | No data breach notification | Reporting absent | High | Open |\n'
            '| 4 | No consent management | Register missing | Medium | Open |\n'
        ),
        'roadmap': (
            '## 5. Implementation Roadmap\n\n### Phase 1 (0-6 months)\n\n'
            + _PDPL + '\n\n'
            '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |\n'
            '|-------|--------|------------|-------|----------------------|------------------|\n'
            '| 1 | 0-6 months | Rights desk | DPO | SOP | PDPL |\n'
        ),
        'kpis': (
            '## 6. Key Performance Indicators\n\n' + _PDPL + '\n\n'
            '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |\n'
            '|---|---------------|------|--------------|---------------------|--------|-----------|-------|\n'
            '| 1 | Access request SLA | KPI | 95% | closed / received × 100 | Service desk | Monthly | DPO |\n'
        ),
        'confidence': (
            '## 7. Confidence Assessment\n\n'
            '**Confidence Score:** 72%\n\n'
            '**Score Justification:** Executive urgency from PDPL and NDMO '
            'is offset by talent shortage. ' + _PDPL + '\n\n'
            '| Factor | Weight | Score | Rationale |\n'
            '|--------|--------|-------|-----------|\n'
            '| Mandate | 20% | 80 | Regulatory urgency |\n'
        ),
    }
    text = tables[key] + extra
    if not with_headings and not wrong_section_guides:
        for needle in FORBIDDEN_HEADINGS:
            if needle.lower() in text.lower():
                raise AssertionError('provider fixture leaked ' + needle)
    return text


class _Provider:
    def __init__(self, mode='thin'):
        self.mode = mode
        self.calls = 0

    def __call__(self, prompt='', language='en', **_kwargs):
        self.calls += 1
        text = str(prompt or '')
        low = text.lower()
        with_headings = self.mode == 'headings'
        wrong = self.mode == 'wrong_section'
        if '[section]' in low or 'hidden sync' in low or 'json_sync' in low or len(text) > 4000:
            return '\n\n[SECTION]\n'.join(
                _thin_section(k, wrong_section_guides=wrong, with_headings=with_headings)
                for k in (
                    'vision', 'pillars', 'environment', 'gaps',
                    'roadmap', 'kpis', 'confidence',
                )
            )
        order = (
            ('vision', ('## 1.', 'vision', 'objectives')),
            ('pillars', ('## 2.', 'pillar')),
            ('environment', ('## 3.', 'environment', 'regulatory')),
            ('gaps', ('## 4.', 'gap analysis', 'gap assessment')),
            ('roadmap', ('## 5.', 'roadmap', 'phase 1')),
            ('kpis', ('## 6.', 'kpi', 'key performance')),
            ('confidence', ('## 7.', 'confidence', 'score justification')),
        )
        for key, needles in order:
            if any(n in low for n in needles):
                return _thin_section(
                    key, wrong_section_guides=wrong, with_headings=with_headings)
        return _thin_section(
            'vision', wrong_section_guides=wrong, with_headings=with_headings)


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


def _fake_openai(provider):
    class _Completions:
        def create(self, **kwargs):
            messages = kwargs.get('messages') or []
            prompt = '\n'.join(str(m.get('content') or '') for m in messages)
            return _Resp(provider(prompt))

    class _Fake:
        def __init__(self, *a, **k):
            self.chat = type('C', (), {'completions': _Completions()})()

    return _Fake


def tearDownModule():
    for key, previous in _ENV_BEFORE.items():
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


def _register_login(username, password, email, *, admin=False):
    client = app_mod.app.test_client()
    client.get('/login?lang=en')
    if not admin:
        client.post('/register', data={
            'username': username,
            'email': email,
            'password': password,
        }, follow_redirects=False)
    resp = client.post(
        '/login',
        data={'username': username, 'password': password},
        follow_redirects=False,
    )
    with client.session_transaction() as sess:
        csrf = sess.get('csrf_token')
        uid = sess.get('user_id')
        role = sess.get('role')
    return client, {
        'X-CSRFToken': csrf,
        'Content-Type': 'application/json',
    }, uid, role, resp.status_code


def _run_async(client, headers, payload, provider, timeout=180):
    with patch.object(openai, 'OpenAI', _fake_openai(provider)):
        submit = client.post(
            '/api/generate-strategy-async',
            json=dict(payload),
            headers=headers,
        )
        body = submit.get_json(silent=True) or {}
        task_id = body.get('task_id')
        status = {}
        deadline = time.time() + timeout
        while task_id and time.time() < deadline:
            poll = client.get(f'/api/strategy-status/{task_id}', headers=headers)
            status = poll.get_json(silent=True) or {}
            if status.get('status') in ('done', 'error', 'failed', 'not_found'):
                break
            time.sleep(0.2)
    return submit.status_code, task_id, status


def _saved_row(uid):
    with app_mod.app.app_context():
        db = app_mod.get_db()
        return db.execute(
            'SELECT id, org_name, domain, language, sections_json, content '
            'FROM strategies WHERE user_id = ? ORDER BY id DESC LIMIT 1',
            (uid,),
        ).fetchone()


def _sections_from_row(row):
    if row is None:
        return {}
    raw = row['sections_json']
    if not raw:
        return {}
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


class Rel37GuideCompletenessPersistTests(unittest.TestCase):
    def setUp(self):
        app_mod.rate_limit_store.clear()

    def test_00_evidence_skip_is_not_active(self):
        self.assertNotEqual(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE'), '1')
        self.assertFalse(bool(os.environ.get('REL2_SKIP_EXPORT_EVIDENCE')))

    def test_01_ci_blind_spot_is_the_old_ui_contract(self):
        src = (ROOT / 'tests' / 'test_rel37_ui_request_type_contract.py').read_text(
            encoding='utf-8')
        self.assertIn('class ImmediateThread', src)
        self.assertIn('ai_repair_strategy_section', src)
        self.assertIn('### KPI Assessment Guidelines', src)
        self.assertIn('Gap #1 Implementation Guide', src)

    def test_02_mechanism_stale_markdown_still_has_valid_typed_guides(self):
        early = attach_rel37_early_authority(
            {'vision': 'thin', 'kpis': 'thin', 'gaps': 'thin'},
            domain='data',
            domain_input='Data Management',
            lang='en',
            document_type='strategy',
            selected_frameworks=UI_REQUEST['frameworks'],
            explicit_selection=True,
            org_name=UI_REQUEST['org_name'],
            task_id='',
            strategy_id='',
        )
        self.assertTrue(early.applied, early.diagnostic)
        self.assertEqual(early.model.validate() if early.model else ['no'], [])
        stale = dict(early.sections)
        stale['kpis'] = _thin_section('kpis')
        stale['gaps'] = _thin_section('gaps')
        ok, issues = app_mod._audit_doc_quality(
            stale, 'technical', 'en', generation_mode='drafting')
        remaining = app_mod._prcy65_critical_core_tech_issue_tags(issues)
        self.assertIn('kpi_assessment_guides_missing', remaining)
        self.assertIn('gap_guidance_missing', remaining)
        self.assertFalse(ok)
        typed = rel37_guide_completeness_persist_result(
            stale,
            domain='data',
            lang='en',
            document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'],
        )
        self.assertEqual(typed, [], typed)
        model = load_model(stale)
        restored = stamp_rel37_keys(stale, model)
        self.assertIn('Implementation Guide', restored.get('gaps') or '')
        self.assertIn('KPI Assessment Guidelines', restored.get('kpis') or '')
        human = ', '.join(
            {
                'kpi_assessment_guides_missing': 'KPI Assessment Guidelines',
                'gap_guidance_missing': 'Gap Implementation Guides',
            }[k] for k in sorted(remaining)
            if k in ('kpi_assessment_guides_missing', 'gap_guidance_missing')
        )
        self.assertIn('Gap Implementation Guides', human)
        self.assertIn('KPI Assessment Guidelines', human)

    def test_03_standard_user_real_worker_persists(self):
        provider = _Provider('thin')
        client, headers, uid, role, login_http = _register_login(
            'rel3714std', 'Rel37user1', 'rel3714std@example.com')
        self.assertEqual(role, 'user', (role, login_http))
        http, task_id, status = _run_async(client, headers, UI_REQUEST, provider)
        self.assertEqual(http, 200, status)
        self.assertTrue(task_id)
        self.assertGreaterEqual(len(task_id), 32)
        self.assertEqual(status.get('status'), 'done', status)
        err = status.get('error') or ''
        if isinstance(status.get('result'), dict):
            err = err or status['result'].get('error') or ''
        self.assertNotIn('cannot be saved without', str(err))
        row = _saved_row(uid)
        self.assertIsNotNone(row)
        sections = _sections_from_row(row)
        self.assertTrue(is_rel37_authoritative(sections), list(sections)[:12])
        model = load_model(sections)
        self.assertIsNotNone(model)
        self.assertEqual(model.validate(), [])
        self.assertTrue(model.gap_guides)
        self.assertTrue(model.kpi_guides)
        self.assertEqual(len(model.gap_guides), len(model.gaps))
        self.assertEqual(len(model.kpi_guides), len(model.kpis))
        ident_ok, ident_err = rel37_request_model_consistent(
            sections,
            domain='data',
            lang='en',
            document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'],
        )
        self.assertTrue(ident_ok, ident_err)
        public = public_status_sections(sections)
        self.assertIn('gaps', public)
        self.assertIn('Implementation Guide', sections.get('gaps') or '')
        self.assertIn('KPI Assessment Guidelines', sections.get('kpis') or '')
        latest = client.get(
            '/api/strategy/latest?domain=Data%20Management&lang=en'
            '&document_type=strategy',
            headers=headers,
        )
        latest_json = latest.get_json(silent=True) or {}
        latest_sections = latest_json.get('sections') or {}
        self.assertIn('Implementation Guide', latest_sections.get('gaps') or '')
        reload = client.get(
            '/api/strategy/latest?domain=Data%20Management&lang=en'
            f'&document_type=strategy&strategy_id={row["id"]}',
            headers=headers,
        )
        reload_json = reload.get_json(silent=True) or {}
        reload_sections = reload_json.get('sections') or {}
        self.assertIn('Implementation Guide', reload_sections.get('gaps') or '')
        self.assertEqual(provider.calls > 0, True)

        export_body = {
            'content': row['content'],
            'filename': 'rel37_guide_persist',
            'language': 'en',
            'domain': 'Data Management',
            'doc_type': 'Strategy Document',
            'document_type': 'strategy',
            'artifact_type': 'strategy',
            'generation_mode': 'drafting',
            'strategy_id': row['id'],
            'artifact_id': row['id'],
            'selected_frameworks': list(UI_REQUEST['frameworks']),
            'frameworks': list(UI_REQUEST['frameworks']),
            'org_name': UI_REQUEST['org_name'],
        }
        pdf = client.post('/api/generate-pdf', json=export_body, headers=headers)
        self.assertEqual(pdf.status_code, 200, pdf.get_json(silent=True))
        self.assertTrue((pdf.data or b'').startswith(b'%PDF'))
        text, meta = extract_pdf_text(pdf.data)
        self.assertTrue(meta.get('reliable'), meta)
        self.assertIn('Implementation Guide', text)
        docx = client.post('/api/generate-docx', json=export_body, headers=headers)
        self.assertEqual(docx.status_code, 200, docx.get_json(silent=True))
        self.assertIn(b'PK', (docx.data or b'')[:4])

    def test_04_admin_same_request_also_persists(self):
        provider = _Provider('thin')
        client, headers, uid, role, _login = _register_login(
            'admin', 'test-admin-password', 'admin@mizan.local', admin=True)
        self.assertEqual(role, 'admin')
        http, task_id, status = _run_async(client, headers, UI_REQUEST, provider)
        self.assertEqual(http, 200, status)
        self.assertEqual(status.get('status'), 'done', status)
        self.assertIsNotNone(_saved_row(uid))

    def test_05_heading_bearing_fixture_still_persists(self):
        provider = _Provider('headings')
        client, headers, uid, _role, _login = _register_login(
            'rel3714hd', 'Rel37user1', 'rel3714hd@example.com')
        _http, _tid, status = _run_async(client, headers, UI_REQUEST, provider)
        self.assertEqual(status.get('status'), 'done', status)
        self.assertIsNotNone(_saved_row(uid))

    def test_06_wrong_section_guide_prose_does_not_satisfy_typed_guides(self):
        stale = {
            'vision': _thin_section('vision', wrong_section_guides=True),
            'kpis': _thin_section('kpis'),
            'gaps': _thin_section('gaps'),
            REL37_APPLIED_KEY: 'true',
        }
        ok, issues = app_mod._audit_doc_quality(
            stale, 'technical', 'en', generation_mode='drafting')
        remaining = app_mod._prcy65_critical_core_tech_issue_tags(issues)
        self.assertIn('kpi_assessment_guides_missing', remaining)
        self.assertFalse(is_rel37_authoritative(stale))
        self.assertIsNone(rel37_guide_completeness_persist_result(
            stale, domain='data', lang='en', document_type='strategy',
            selected_frameworks=UI_REQUEST['frameworks']))

    def test_07_alternate_display_labels_supported(self):
        sel = rel37_supported_selection(
            domain='Data Management', lang='en', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], explicit_selection=True)
        self.assertTrue(sel.supported, sel.reason)
        early = attach_rel37_early_authority(
            {'vision': 'thin'},
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'],
            explicit_selection=True,
            org_name=UI_REQUEST['org_name'],
        )
        self.assertTrue(early.applied)
        self.assertTrue(early.model.gap_guides)

    def test_08_negative_missing_and_invalid_guides_block(self):
        early = attach_rel37_early_authority(
            {'vision': 'thin'},
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=UI_REQUEST['frameworks'],
            explicit_selection=True,
            org_name=UI_REQUEST['org_name'],
        )
        model = early.model
        payload = model.to_dict()
        sections = dict(early.sections)

        missing_gap = dict(sections)
        cut = dict(payload)
        cut['gap_guides'] = list(cut['gap_guides'])[:-1]
        missing_gap[REL37_MODEL_KEY] = json.dumps(cut, ensure_ascii=False)
        missing_gap[REL37_HASH_KEY] = model.model_hash
        blockers = rel37_guide_completeness_persist_result(
            missing_gap, domain='data', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'])
        self.assertTrue(blockers, blockers)
        self.assertTrue(any('gap_guide' in str(b) for b in blockers), blockers)

        missing_kpi = dict(sections)
        cut = dict(payload)
        cut['kpi_guides'] = list(cut['kpi_guides'])[:-1]
        missing_kpi[REL37_MODEL_KEY] = json.dumps(cut, ensure_ascii=False)
        blockers = rel37_guide_completeness_persist_result(
            missing_kpi, domain='data', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'])
        self.assertTrue(any('kpi_guide' in str(b) for b in blockers), blockers)

        empty_steps = dict(sections)
        cut = dict(payload)
        cut['gap_guides'][0]['steps'] = []
        empty_steps[REL37_MODEL_KEY] = json.dumps(cut, ensure_ascii=False)
        blockers = rel37_guide_completeness_persist_result(
            empty_steps, domain='data', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'])
        self.assertTrue(any('steps_missing' in str(b) for b in blockers), blockers)

        orphan = dict(sections)
        cut = dict(payload)
        cut['gap_guides'][0]['number'] = 99
        orphan[REL37_MODEL_KEY] = json.dumps(cut, ensure_ascii=False)
        blockers = rel37_guide_completeness_persist_result(
            orphan, domain='data', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'])
        self.assertTrue(any('association' in str(b) for b in blockers), blockers)

        forged = {
            REL37_APPLIED_KEY: 'true',
            'kpis': _thin_section('kpis', with_headings=True),
            'gaps': _thin_section('gaps', with_headings=True),
        }
        self.assertFalse(is_rel37_authoritative(forged))
        self.assertIsNone(rel37_guide_completeness_persist_result(
            forged, domain='data', lang='en', document_type='strategy',
            selected_frameworks=UI_REQUEST['frameworks']))

        mismatch = dict(sections)
        mismatch[REL37_HASH_KEY] = '0' * 64
        blockers = rel37_guide_completeness_persist_result(
            mismatch, domain='data', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=UI_REQUEST['frameworks'])
        self.assertTrue(any('hash' in str(b) for b in blockers), blockers)

        wrong_domain = rel37_guide_completeness_persist_result(
            sections, domain='cyber', lang='en', document_type='strategy',
            org_name=UI_REQUEST['org_name'],
            selected_frameworks=['NCA ECC'])
        self.assertTrue(wrong_domain)

    def test_09_unsupported_and_feature_off_keep_legacy(self):
        cyber = attach_rel37_early_authority(
            {'vision': 'cyber', 'kpis': _thin_section('kpis'),
             'gaps': _thin_section('gaps')},
            domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True,
        )
        self.assertFalse(cyber.applied)
        self.assertIsNone(rel37_guide_completeness_persist_result(
            cyber.sections, domain='cyber', lang='en',
            document_type='strategy', selected_frameworks=['NCA ECC']))
        with patch.dict(os.environ, {'REL37_DATA_AI_DT_COMPILER': '0'}):
            off = attach_rel37_early_authority(
                {'vision': 'thin'},
                domain='data', lang='en', document_type='strategy',
                selected_frameworks=UI_REQUEST['frameworks'],
                explicit_selection=True,
            )
            self.assertFalse(off.applied)

    def test_10_failed_save_creates_no_strategy(self):
        client, headers, uid, _role, _login = _register_login(
            'rel3714neg', 'Rel37user1', 'rel3714neg@example.com')
        before = _saved_row(uid)
        resp = client.post(
            '/api/generate-strategy-async',
            json={'domain': ''},
            headers=headers,
        )
        self.assertIn(resp.status_code, (400, 422))
        self.assertEqual(_saved_row(uid), before)

    def test_11_export_ownership_still_requires_saved_id(self):
        client, headers, uid, _role, _login = _register_login(
            'rel3714own', 'Rel37user1', 'rel3714own@example.com')
        other, other_headers, _oid, _orole, _ologin = _register_login(
            'rel3714oth', 'Rel37user1', 'rel3714oth@example.com')
        provider = _Provider('thin')
        _http, _tid, status = _run_async(client, headers, UI_REQUEST, provider)
        self.assertEqual(status.get('status'), 'done', status)
        row = _saved_row(uid)
        self.assertIsNotNone(row)
        body = {
            'content': row['content'],
            'filename': 'stolen',
            'language': 'en',
            'domain': 'Data Management',
            'doc_type': 'Strategy Document',
            'document_type': 'strategy',
            'strategy_id': row['id'],
            'artifact_id': row['id'],
            'selected_frameworks': list(UI_REQUEST['frameworks']),
            'org_name': UI_REQUEST['org_name'],
        }
        denied = other.post('/api/generate-pdf', json=body, headers=other_headers)
        payload = denied.get_json(silent=True) or {}
        self.assertEqual(denied.status_code, 403, payload)
        self.assertEqual(payload.get('reason'), 'cross_user_export_denied', payload)
        missing = client.post(
            '/api/generate-pdf',
            json={k: v for k, v in body.items() if k not in ('strategy_id', 'artifact_id')},
            headers=headers,
        )
        missing_payload = missing.get_json(silent=True) or {}
        self.assertIn(missing.status_code, (400, 403, 422), missing_payload)
        self.assertFalse((missing.data or b'').startswith(b'%PDF'))


if __name__ == '__main__':
    unittest.main()
