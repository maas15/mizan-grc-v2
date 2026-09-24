"""REL37 sector operating-context contract.

The captured live Data AR failure (task e00b8a79-..., sector بنوك/مالي)
is reproduced as a request/compiler/validator mechanism. Provider output
for that live task is not retained, so this is not an exact replay.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel37_sector_ctx_')
os.environ['ADMIN_PASSWORD'] = 'test-admin-password'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['DATABASE_PATH'] = os.path.join(_TMP, 'sector.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(_TMP, 'sector.db')
os.environ['OPENAI_API_KEY'] = 'sk-test-rel37-sector'
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
    load_model,
    overlay_rel37_authority,
    rel37_hash_identity_blockers,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_compilers import (  # noqa: E402
    _environment_prose,
    compile_for_domain,
)
from release_engine_v3.rel37_early_authority import (  # noqa: E402
    attach_rel37_early_authority,
    confirm_rel37_final_persist,
)
from release_engine_v3.rel37_render import model_to_sections, render  # noqa: E402
from release_engine_v3.rel37_sector_context import (  # noqa: E402
    cover_sector_from_hashed_narrative,
    environment_mentions_requested_sector,
    present_sector_label,
    request_sector,
)

CAPTURED = {
    'domain': 'Data Management',
    'language': 'ar',
    'org_name': 'منظمة بيانات نسبي ٣٧٫٢٠',
    'sector': 'بنوك/مالي',
    'size': 'صغيرة (أقل من 100)',
    'budget': '< 1 مليون ريال',
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

_PDPL = (
    'data subject rights, access request, rectification, erasure, '
    'personal data classification, data breach notification, consent management'
)


def _thin_env_without_sector(lang='ar'):
    if lang == 'ar':
        return (
            '## البيئة التنظيمية والتهديدات\n\n'
            'تعمل الجهة في بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO '
            'وحماية بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات '
            'والكتالوج وإدارة الموافقات وحقوق أصحاب البيانات.\n\n'
            'تشمل المحركات التشغيلية اكتمال التصنيف، ضبط دورة الحياة، '
            'توثيق المشاركة، وإخطار الحوادث ضمن المهلة النظامية.'
        )
    return (
        '## 3. Business Environment and Regulatory Context\n\n'
        'The organization operates under NDMO and PDPL (Personal Data Protection Law) '
        'with catalog, quality, consent, and data-subject rights pressure.\n\n'
        'Operating drivers include classification completeness and on-time notification.'
    )


def _compile(domain, lang, org_name, sector='', frameworks=None):
    payload = {
        'domain': domain,
        'lang': lang,
        'org_name': org_name,
        'sector': sector,
        'document_type': 'strategy',
    }
    if frameworks is not None:
        payload['selected_frameworks'] = list(frameworks)
        payload['frameworks'] = list(frameworks)
    return compile_for_domain(domain, payload)


def _diag(payload):
    return app_mod.build_diagnostic_model(payload, lang=payload.get('language') or 'ar')


def _defects(sections, payload):
    lang = 'ar' if str(payload.get('language') or 'ar').startswith('ar') else 'en'
    return [
        item[0]
        for item in app_mod.validate_strategy_fail_closed(
            sections, lang, diag_model=_diag(payload))
    ]


def _early(payload, sections=None, **kwargs):
    lang = payload.get('language') or 'ar'
    return attach_rel37_early_authority(
        sections or {'environment': _thin_env_without_sector(lang)},
        domain=payload.get('domain'),
        domain_input=payload.get('domain'),
        lang=lang,
        document_type='strategy',
        selected_frameworks=payload.get('frameworks'),
        explicit_selection=True,
        org_name=payload.get('org_name') or '',
        request=dict(payload),
        **kwargs,
    )


class _Provider:
    def __call__(self, prompt='', language='ar', **_kwargs):
        return (
            _thin_env_without_sector(language)
            + '\n\n## vision\n' + _PDPL
        )


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


def _register(username):
    client = app_mod.app.test_client()
    client.get('/login?lang=en')
    client.post('/register', data={
        'username': username,
        'email': username + '@example.test',
        'password': 'SectorCtx-1',
    }, follow_redirects=False)
    client.post('/login', data={
        'username': username,
        'password': 'SectorCtx-1',
    }, follow_redirects=False)
    with client.session_transaction() as sess:
        csrf = sess.get('csrf_token')
        uid = sess.get('user_id')
        role = sess.get('role')
    return client, {
        'X-CSRFToken': csrf,
        'Content-Type': 'application/json',
    }, uid, role


class SectorHelperTests(unittest.TestCase):
    def test_present_label_pairs(self):
        self.assertEqual(present_sector_label('بنوك/مالي', 'en'), 'Banking/Finance')
        self.assertEqual(present_sector_label('Banking/Finance', 'ar'), 'بنوك/مالي')
        self.assertEqual(present_sector_label('رعاية صحية', 'en'), 'Healthcare')

    def test_org_name_only_does_not_count(self):
        env = 'تعمل منظمة بنوك/مالي التجريبية في بيئة NDMO و PDPL طويلة بما يكفي.'
        self.assertFalse(environment_mentions_requested_sector(
            env, 'بنوك/مالي', 'منظمة بنوك/مالي التجريبية'))

    def test_empty_sector_follows_omission(self):
        self.assertEqual(request_sector({}), '')
        self.assertTrue(environment_mentions_requested_sector('no sector here', ''))
        self.assertEqual(_environment_prose('data', 'ar', 'جهة'), _environment_prose(
            'data', 'ar', 'جهة', ''))

    def test_cover_sector_from_hashed_narrative_only(self):
        ar = (
            'تعمل منظمة بيانات نسبي ٣٧٫٢٠ في سياق تشغيلي لقطاع بنوك/مالي، '
            'ضمن بيئة تنظيمية تتطلب حوكمة بيانات وطنية وفق NDMO.'
        )
        self.assertEqual(cover_sector_from_hashed_narrative(ar, 'ar'), 'بنوك/مالي')
        self.assertEqual(
            cover_sector_from_hashed_narrative(ar, 'en'), 'Banking/Finance')
        self.assertEqual(cover_sector_from_hashed_narrative('', 'ar'), '')
        self.assertEqual(
            cover_sector_from_hashed_narrative(
                'تعمل الجهة في بيئة تنظيمية تتطلب حوكمة بيانات.', 'ar'),
            '')
        # HASH_EXCLUDED raw Healthcare is not a narrative mention.
        self.assertNotEqual(
            cover_sector_from_hashed_narrative(ar, 'ar'), 'Healthcare')
        incidental = (
            'Healthcare Analytics operates in the Banking/Finance '
            'sector operating context under NDMO.')
        self.assertEqual(
            cover_sector_from_hashed_narrative(incidental, 'en'),
            'Banking/Finance')
        self.assertEqual(
            cover_sector_from_hashed_narrative(
                'Healthcare Analytics reviews NDMO catalog coverage.', 'en'),
            '')


class CompilerContextTests(unittest.TestCase):
    def test_captured_sector_reaches_narrative(self):
        model = _compile('data', 'ar', CAPTURED['org_name'], CAPTURED['sector'])
        self.assertIn('بنوك/مالي', model.environment_narrative)
        self.assertEqual(model.sector, 'بنوك/مالي')
        self.assertNotIn('SAMA', model.environment_narrative)
        self.assertNotIn('NCA', model.environment_narrative)

    def test_english_equivalent_and_no_arabic_leak(self):
        model = _compile('data', 'en', 'Data Example Org', 'Banking/Finance')
        self.assertIn('Banking/Finance', model.environment_narrative)
        self.assertNotRegex(model.environment_narrative, r'[\u0600-\u06FF]')
        mapped = _compile('data', 'en', 'Data Example Org', 'بنوك/مالي')
        self.assertIn('Banking/Finance', mapped.environment_narrative)
        self.assertNotIn('بنوك/مالي', mapped.environment_narrative)

    def test_other_ui_sectors_and_shared_domains(self):
        cases = (
            ('data', 'ar', 'رعاية صحية'),
            ('data', 'en', 'Healthcare'),
            ('ai', 'ar', 'طاقة'),
            ('ai', 'en', 'Energy'),
            ('dt', 'ar', 'اتصالات'),
            ('dt', 'en', 'Telecom'),
        )
        for domain, lang, sector in cases:
            model = _compile(domain, lang, 'جهة مثال' if lang == 'ar' else 'Example Org', sector)
            presented = present_sector_label(sector, lang)
            self.assertIn(presented, model.environment_narrative, (domain, lang, sector))
            defects = _defects(model_to_sections(model), {
                'language': lang,
                'sector': sector,
                'org_name': model.org_name,
                'frameworks': list(model.selected_frameworks),
                'domain': domain,
            })
            self.assertNotIn('environment_missing_sector_reference', defects)

    def test_empty_sector_keeps_baseline_prose(self):
        with_empty = _environment_prose('data', 'en', 'Data Example Org', '')
        without = _environment_prose('data', 'en', 'Data Example Org')
        self.assertEqual(with_empty, without)
        self.assertNotIn('sector operating context', without)

    def test_old_saved_hash_stable_without_injected_sector(self):
        model = _compile('data', 'ar', 'شركة البيانات')
        payload = model.to_dict()
        stored_hash = payload['model_hash']
        payload.pop('sector', None)
        loaded = CanonicalDocument.from_dict(payload)
        loaded.compute_hashes()
        self.assertEqual(loaded.model_hash, stored_hash)
        self.assertEqual(loaded.sector, '')


class ValidatorNegativeTests(unittest.TestCase):
    def test_missing_sector_still_blocked(self):
        payload = dict(CAPTURED)
        sections = {'environment': _thin_env_without_sector('ar')}
        self.assertIn('environment_missing_sector_reference', _defects(sections, payload))

    def test_wrong_sector_blocked(self):
        payload = dict(CAPTURED)
        model = _compile('data', 'ar', payload['org_name'], 'رعاية صحية')
        self.assertIn(
            'environment_missing_sector_reference',
            _defects(model_to_sections(model), payload),
        )

    def test_org_name_only_blocked(self):
        payload = dict(CAPTURED)
        payload['org_name'] = 'منظمة بنوك/مالي التجريبية'
        sections = {'environment': (
            f"تعمل {payload['org_name']} في بيئة تنظيمية تتطلب حوكمة بيانات وطنية "
            'وفق NDMO وحماية بيانات شخصية وفق PDPL، مع ضغط متزايد على جودة البيانات '
            'والكتالوج وإدارة الموافقات وحقوق أصحاب البيانات.\n\n'
            'تشمل المحركات التشغيلية اكتمال التصنيف، ضبط دورة الحياة، '
            'توثيق المشاركة، وإخطار الحوادث ضمن المهلة النظامية.'
        )}
        self.assertIn('environment_missing_sector_reference', _defects(sections, payload))

    def test_stale_other_request_blocked(self):
        banking = _compile('data', 'ar', CAPTURED['org_name'], 'بنوك/مالي')
        other = dict(CAPTURED)
        other['sector'] = 'طاقة'
        self.assertIn(
            'environment_missing_sector_reference',
            _defects(model_to_sections(banking), other),
        )

    def test_forged_rel37_flag_does_not_skip(self):
        payload = dict(CAPTURED)
        sections = {
            'environment': _thin_env_without_sector('ar'),
            '_rel37_applied': '1',
        }
        self.assertIn('environment_missing_sector_reference', _defects(sections, payload))

    def test_feature_off_and_unsupported_keep_gate(self):
        payload = dict(CAPTURED)
        off = attach_rel37_early_authority(
            {'environment': _thin_env_without_sector('ar')},
            domain='data',
            lang='ar',
            document_type='strategy',
            selected_frameworks=payload['frameworks'],
            explicit_selection=True,
            org_name=payload['org_name'],
            request=payload,
            flags={'rel37_data_ai_dt_compiler': False},
        )
        self.assertFalse(off.applied)
        self.assertIn(
            'environment_missing_sector_reference',
            _defects(off.sections, payload),
        )
        unsupported = attach_rel37_early_authority(
            {'environment': _thin_env_without_sector('ar')},
            domain='data',
            lang='ar',
            document_type='strategy',
            selected_frameworks=['NCA ECC'],
            explicit_selection=True,
            org_name=payload['org_name'],
            request=payload,
        )
        self.assertFalse(unsupported.applied)
        self.assertIn(
            'environment_missing_sector_reference',
            _defects(unsupported.sections, payload),
        )


class PersistAndExportTests(unittest.TestCase):
    def test_captured_request_attaches_and_validates(self):
        early = _early(CAPTURED)
        self.assertTrue(early.applied)
        self.assertIn('بنوك/مالي', str(early.sections.get('environment') or ''))
        self.assertNotIn('environment_missing_sector_reference', _defects(
            early.sections, CAPTURED))
        confirmed = confirm_rel37_final_persist(
            early.sections,
            domain='data',
            domain_input=CAPTURED['domain'],
            lang='ar',
            document_type='strategy',
            selected_frameworks=CAPTURED['frameworks'],
            explicit_selection=True,
            org_name=CAPTURED['org_name'],
            request=dict(CAPTURED),
            early_diagnostic=early.diagnostic,
        )
        self.assertTrue(confirmed.sections.get('_rel37_applied'))
        first_hash = confirmed.sections.get('_rel37_model_hash')
        again = confirm_rel37_final_persist(
            deepcopy(confirmed.sections),
            domain='data',
            domain_input=CAPTURED['domain'],
            lang='ar',
            document_type='strategy',
            selected_frameworks=CAPTURED['frameworks'],
            explicit_selection=True,
            org_name=CAPTURED['org_name'],
            request=dict(CAPTURED),
            early_diagnostic=confirmed.diagnostic,
        )
        self.assertEqual(again.sections.get('_rel37_model_hash'), first_hash)

    def test_preview_docx_pdf_keep_sector_and_guides(self):
        model = _compile('data', 'ar', CAPTURED['org_name'], CAPTURED['sector'])
        preview = render(model, 'preview')
        docx = render(model, 'docx')
        pdf = render(model, 'pdf')
        self.assertEqual(preview.evidence.model_hash, model.model_hash)
        self.assertEqual(docx.evidence.model_hash, model.model_hash)
        self.assertEqual(pdf.evidence.model_hash, model.model_hash)
        self.assertIn('بنوك/مالي', preview.markdown)
        self.assertIn('بنوك/مالي', docx.markdown)
        self.assertTrue(model.gap_guides and model.kpi_guides)
        en = _compile('data', 'en', 'Data Example Org', 'Banking/Finance')
        en_kpi = ' '.join(row.description for row in en.kpis)
        self.assertIn('On-time data-subject request closure', en_kpi)
        self.assertIn('On-time eligible-incident notification', en_kpi)

    def test_client_export_cannot_change_saved_sector(self):
        model = _compile('data', 'ar', CAPTURED['org_name'], 'بنوك/مالي')
        saved = {
            **model_to_sections(model),
            '_rel37_applied': '1',
            '_rel37_canonical': model.to_dict(),
            '_rel37_model_hash': model.model_hash,
            '_rel37_source_hash': model.model_hash,
        }
        tampered = overlay_rel37_authority(
            {**saved, 'environment': 'Healthcare only', 'sector': 'Healthcare'},
            saved,
            domain='data',
            lang='ar',
            org_name=CAPTURED['org_name'],
            selected_frameworks=['PDPL', 'NDMO'],
        )
        restored = load_model(tampered)
        self.assertIsNotNone(restored)
        self.assertIn('بنوك/مالي', restored.environment_narrative)
        self.assertEqual(restored.sector, 'بنوك/مالي')
        self.assertEqual(tampered.get('_rel37_model_hash'), model.model_hash)
        self.assertFalse(rel37_hash_identity_blockers(saved))
        forged = dict(saved)
        forged['_rel37_model_hash'] = '0' * 64
        self.assertTrue(rel37_hash_identity_blockers(forged))

    def test_worker_persist_captured_data_ar(self):
        app_mod.rate_limit_store.clear()
        client, headers, uid, role = _register('rel37sector_a')
        self.assertEqual(role, 'user')
        provider = _Provider()
        with patch.object(openai, 'OpenAI', _fake_openai(provider)):
            submit = client.post(
                '/api/generate-strategy-async',
                json=dict(CAPTURED),
                headers=headers,
            )
            body = submit.get_json(silent=True) or {}
            task_id = body.get('task_id')
            status = {}
            deadline = time.time() + 180
            while task_id and time.time() < deadline:
                poll = client.get(f'/api/strategy-status/{task_id}', headers=headers)
                status = poll.get_json(silent=True) or {}
                if status.get('status') in ('done', 'error', 'failed', 'not_found'):
                    break
                time.sleep(0.2)
        inner = status.get('result') if isinstance(status.get('result'), dict) else {}
        strategy_id = status.get('strategy_id') or inner.get('strategy_id')
        self.assertTrue(task_id)
        self.assertEqual(status.get('status'), 'done', {
            'status': status.get('status'),
            'error': status.get('error') or inner.get('error'),
            'strategy_id': strategy_id,
        })
        self.assertTrue(strategy_id, {
            'status': status.get('status'),
            'error': status.get('error') or inner.get('error'),
        })
        with app_mod.app.app_context():
            db = app_mod.get_db()
            row = db.execute(
                'SELECT id, org_name, sector, language, sections_json '
                'FROM strategies WHERE user_id = ? ORDER BY id DESC LIMIT 1',
                (uid,),
            ).fetchone()
        self.assertIsNotNone(row)
        sections = json.loads(row['sections_json'])
        self.assertEqual(row['sector'], 'بنوك/مالي')
        self.assertIn('بنوك/مالي', str(sections.get('environment') or ''))
        self.assertNotIn('environment_missing_sector_reference', _defects(sections, CAPTURED))
        reload_preview = client.get(
            f"/api/strategy/{row['id']}", headers=headers
        )
        if reload_preview.status_code != 200:
            reload_preview = client.get(
                '/api/strategy/latest?domain=Data%20Management', headers=headers)
        latest = reload_preview.get_json(silent=True) or {}
        latest_env = ''
        if isinstance(latest, dict):
            latest_env = str(
                (latest.get('sections') or {}).get('environment')
                or latest.get('environment')
                or ''
            )
        if latest_env:
            self.assertIn('بنوك/مالي', latest_env)


if __name__ == '__main__':
    unittest.main()
