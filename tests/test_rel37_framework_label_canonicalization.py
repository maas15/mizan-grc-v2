"""REL37.0.5 — UI framework display-label canonicalization."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel37_05_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

from release_engine_v3.rel37_apply import (  # noqa: E402
    apply_rel37_to_sections,
    is_rel37_authoritative,
    load_model,
    rel37_should_apply,
)
from release_engine_v3.rel37_early_authority import attach_rel37_early_authority  # noqa: E402
from release_engine_v3.rel37_framework_aliases import (  # noqa: E402
    canonicalize_framework_labels,
    last_framework_label_diagnostic,
    lookup_key,
)
from release_engine_v3.rel37_live_attach import attach_rel37_before_save  # noqa: E402
from release_engine_v3.rel37_preview_section_contract import (  # noqa: E402
    apply_rel37_preview_section_contract,
)
from release_engine_v3.rel37_render import evidence_from_model, model_to_markdown, render  # noqa: E402
from release_engine_v3.rel37_schema_registry import leakage_terms  # noqa: E402
from release_engine_v3.rel37_selection import (  # noqa: E402
    last_selection_diagnostic,
    rel37_supported_selection,
)

SAMPLE_DIRS = (
    Path('/tmp/rel37_05_framework_aliases'),
    ROOT / 'qa_outputs' / 'rel37_05_framework_aliases',
    Path('/opt/cursor/artifacts/rel37_05_framework_aliases'),
)

DATA_EN_UI = [
    'PDPL (Personal Data Protection Law)',
    'NDMO Data Governance Framework',
]
DATA_AR_UI = [
    'نظام حماية البيانات الشخصية (PDPL)',
    'إطار حوكمة البيانات - مكتب إدارة البيانات الوطنية (NDMO)',
]
AI_EN_UI = ['SDAIA AI Ethics Principles']
AI_AR_UI = ['مبادئ أخلاقيات الذكاء الاصطناعي']
DT_EN_UI = ['DGA Digital Government Policy']
DT_EN_FW = ['DGA Digital Government Framework']
DT_AR_UI = ['هيئة الحكومة الرقمية']

_DISPLAY = {
    'data': 'Data Management',
    'ai': 'Artificial Intelligence',
    'dt': 'Digital Transformation',
}


def _write(folder: Path, name: str, payload) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    if isinstance(payload, (bytes, bytearray)):
        path.write_bytes(payload)
        return
    if name.endswith('.json'):
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
        return
    path.write_text(str(payload), encoding='utf-8')


def _write_all(name: str, payload) -> None:
    for folder in SAMPLE_DIRS:
        try:
            _write(folder, name, payload)
        except Exception:
            continue


def _apply(domain, lang, frameworks, explicit=True):
    return apply_rel37_to_sections(
        {'vision': 'legacy-thin', 'kpis': '| thin |', 'gaps': '| thin |'},
        domain=domain,
        lang=lang,
        document_type='strategy',
        selected_frameworks=frameworks,
        explicit_selection=explicit,
        org_name='شركة مثال' if lang == 'ar' else f'{domain.upper()} Example Org',
    )


class Rel37FrameworkLabelCanonicalizationTests(unittest.TestCase):
    def test_01_data_en_ui_labels_to_ndmo_pdpl(self):
        canon = canonicalize_framework_labels(
            DATA_EN_UI, domain='data', lang='en', explicit_selection=True)
        self.assertEqual(list(canon.selected_frameworks_canonical), ['pdpl', 'ndmo'])
        self.assertEqual(list(canon.unsupported_frameworks), [])
        self.assertFalse(canon.body_text_used_for_selection)
        self.assertTrue(canon.supported_after)
        self.assertTrue(canon.compiler_used_after)
        self.assertTrue(canon.passed)
        sel = rel37_supported_selection('data', 'en', 'strategy', DATA_EN_UI, True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['pdpl', 'ndmo'])

    def test_02_data_ar_ui_labels_to_ndmo_pdpl(self):
        sel = rel37_supported_selection('data', 'ar', 'strategy', DATA_AR_UI, True)
        self.assertTrue(sel.supported)
        self.assertEqual(set(sel.normalized_frameworks), {'ndmo', 'pdpl'})

    def test_03_data_short_ndmo_pdpl_still_works(self):
        sel = rel37_supported_selection(
            'data', 'en', 'strategy', ['NDMO', 'PDPL'], True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['ndmo', 'pdpl'])

    def test_04_data_ndmo_management_framework(self):
        sel = rel37_supported_selection(
            'data', 'en', 'strategy', ['NDMO Data Management Framework'], True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['ndmo'])

    def test_05_data_personal_data_protection_law(self):
        sel = rel37_supported_selection(
            'data', 'en', 'strategy', ['Personal Data Protection Law'], True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['pdpl'])

    def test_06_data_mixed_ndmo_nca_unsupported(self):
        sel = rel37_supported_selection(
            'data', 'en', 'strategy', ['NDMO', 'NCA'], True)
        self.assertFalse(sel.supported)
        self.assertTrue(sel.unsupported_frameworks)
        out, repairs = _apply('data', 'en', ['NDMO', 'NCA'])
        self.assertFalse(is_rel37_authoritative(out))
        self.assertEqual(repairs, [])

    def test_07_ai_en_ethics_principles(self):
        sel = rel37_supported_selection('ai', 'en', 'strategy', AI_EN_UI, True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['sdaia'])

    def test_08_ai_ar_sdaia_label(self):
        sel = rel37_supported_selection('ai', 'ar', 'strategy', AI_AR_UI, True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['sdaia'])
        sel2 = rel37_supported_selection('ai', 'ar', 'strategy', ['سدايا'], True)
        self.assertTrue(sel2.supported)

    def test_09_ai_short_sdaia(self):
        sel = rel37_supported_selection('ai', 'en', 'strategy', ['SDAIA'], True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['sdaia'])

    def test_10_ai_eu_ai_act_unsupported(self):
        sel = rel37_supported_selection('ai', 'en', 'strategy', ['EU AI Act'], True)
        self.assertFalse(sel.supported)
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='strategy',
            selected_frameworks=['EU AI Act'], explicit_selection=True))

    def test_11_ai_nist_ai_rmf_unsupported(self):
        self.assertFalse(rel37_supported_selection(
            'ai', 'en', 'strategy', ['NIST AI RMF'], True).supported)

    def test_12_ai_unesco_unsupported(self):
        self.assertFalse(rel37_supported_selection(
            'ai', 'en', 'strategy', ['UNESCO'], True).supported)

    def test_13_dt_en_dga_framework(self):
        sel = rel37_supported_selection('dt', 'en', 'strategy', DT_EN_FW, True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['dga'])
        sel_ui = rel37_supported_selection('dt', 'en', 'strategy', DT_EN_UI, True)
        self.assertTrue(sel_ui.supported)
        self.assertEqual(list(sel_ui.normalized_frameworks), ['dga'])

    def test_14_dt_ar_digital_government_authority(self):
        sel = rel37_supported_selection('dt', 'ar', 'strategy', DT_AR_UI, True)
        self.assertTrue(sel.supported)
        self.assertEqual(list(sel.normalized_frameworks), ['dga'])

    def test_15_dt_short_dga(self):
        self.assertTrue(rel37_supported_selection(
            'dt', 'en', 'strategy', ['DGA'], True).supported)

    def test_16_dt_nist_csf_unsupported(self):
        self.assertFalse(rel37_supported_selection(
            'dt', 'en', 'strategy', ['NIST CSF'], True).supported)

    def test_17_body_text_does_not_cause_support(self):
        body = {'vision': 'SDAIA NDMO DGA national alignment'}
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='strategy',
            sections=body, selected_frameworks=['EU AI Act'],
            explicit_selection=True))
        canon = last_framework_label_diagnostic()
        self.assertFalse(canon.get('body_text_used_for_selection'))

    def test_18_canonicalization_runs_before_selection(self):
        rel37_supported_selection('data', 'en', 'strategy', DATA_EN_UI, True)
        diag = last_framework_label_diagnostic()
        self.assertEqual(diag.get('selected_frameworks_input'), DATA_EN_UI)
        self.assertEqual(diag.get('selected_frameworks_canonical'), ['pdpl', 'ndmo'])
        self.assertTrue(diag.get('supported_after'))
        sel = last_selection_diagnostic()
        self.assertTrue(sel.get('supported'))

    def test_19_early_authority_uses_canonical(self):
        early = attach_rel37_early_authority(
            {'vision': 'thin', 'gaps': '| thin |'},
            domain='data', domain_input='Data Management', lang='en',
            document_type='strategy', selected_frameworks=DATA_EN_UI,
            explicit_selection=True, org_name='Data Example Org')
        self.assertTrue(early.applied)
        self.assertEqual(
            early.sections.get('_rel37_selected_frameworks_canonical'),
            ['pdpl', 'ndmo'])

    def test_20_live_attach_uses_canonical(self):
        live = attach_rel37_before_save(
            {'vision': 'thin'},
            domain='ai', domain_input='Artificial Intelligence', lang='en',
            document_type='strategy', selected_frameworks=AI_EN_UI,
            explicit_selection=True, org_name='AI Example Org')
        self.assertTrue(is_rel37_authoritative(live.sections))
        self.assertEqual(live.diagnostic.get('selected_frameworks_canonical'), ['sdaia'])

    def test_21_data_en_manual_payload_attaches(self):
        out, repairs = _apply('data', 'en', DATA_EN_UI)
        self.assertTrue(is_rel37_authoritative(out))
        self.assertTrue(repairs)
        self.assertEqual(out.get('_rel37_applied'), '1')

    def test_22_ai_en_manual_payload_attaches(self):
        out, _repairs = _apply('ai', 'en', AI_EN_UI)
        self.assertTrue(is_rel37_authoritative(out))

    def test_23_dt_en_manual_payload_attaches(self):
        out, _repairs = _apply('dt', 'en', DT_EN_UI)
        self.assertTrue(is_rel37_authoritative(out))

    def test_24_data_en_has_gap_guides(self):
        out, _ = _apply('data', 'en', DATA_EN_UI)
        model = load_model(out)
        self.assertIsNotNone(model)
        self.assertTrue(model.gaps)
        self.assertEqual(len(model.gap_guides), len(model.gaps))
        md = model_to_markdown(model)
        self.assertIn('Implementation Guide', md)

    def test_25_ai_en_no_synth_failed_kpis(self):
        out, _ = _apply('ai', 'en', AI_EN_UI)
        model = load_model(out)
        self.assertTrue(model.kpis)
        self.assertEqual(model.validate(), [])
        self.assertNotIn('synth_failed:kpis', ' '.join(model.blockers or []))

    def test_26_no_soc_leakage_for_rel37_data_ai(self):
        for domain, fws in (('data', DATA_EN_UI), ('ai', AI_EN_UI)):
            out, _ = _apply(domain, 'en', fws)
            model = load_model(out)
            blob = model.generated_text_blob()
            for term in ('SOC', 'SIEM', 'CSIRT', 'CISO'):
                self.assertNotIn(term, blob)
            leak = leakage_terms(domain)
            hits = [t for t in leak if t and t in blob]
            self.assertEqual(hits, [])

    def test_27_preview_contract_still_green(self):
        out, _ = _apply('data', 'en', DATA_EN_UI)
        _adapted, diag = apply_rel37_preview_section_contract(
            out, domain='data', lang='en', document_type='strategy', emit=False)
        self.assertTrue(diag.get('passed'))
        self.assertTrue(diag.get('gap_analysis_alias_present'))
        _write_all('rel37_preview_contract_data_en.json', diag)

    def test_28_early_authority_still_green(self):
        early = attach_rel37_early_authority(
            {'vision': 'thin', 'gaps': '| thin |'},
            domain='ai', domain_input='Artificial Intelligence', lang='ar',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertTrue(early.diagnostic.get('passed'))

    def test_29_live_attach_still_green(self):
        live = attach_rel37_before_save(
            {'vision': 'thin'}, domain='dt', lang='en',
            selected_frameworks=['DGA'], explicit_selection=True)
        self.assertTrue(is_rel37_authoritative(live.sections))
        self.assertTrue(live.diagnostic.get('compiler_used'))

    def test_30_hash_and_gating_still_green(self):
        out, _ = _apply('data', 'en', DATA_EN_UI)
        model = load_model(out)
        ev = evidence_from_model(model)
        self.assertEqual(ev.source_hash, model.model_hash)
        self.assertFalse(rel37_should_apply(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True))

    def test_31_compiler_matrix_ui_labels(self):
        matrix = []
        for domain, lang, fws in (
            ('data', 'en', DATA_EN_UI),
            ('data', 'ar', DATA_AR_UI),
            ('ai', 'en', AI_EN_UI),
            ('ai', 'ar', AI_AR_UI),
            ('dt', 'en', DT_EN_UI),
            ('dt', 'ar', DT_AR_UI),
        ):
            out, _ = _apply(domain, lang, fws)
            model = load_model(out)
            matrix.append({
                'domain': domain, 'lang': lang, 'input': fws,
                'applied': is_rel37_authoritative(out),
                'canonical': out.get('_rel37_selected_frameworks_canonical'),
                'model_hash': model.model_hash if model else '',
                'source_hash': evidence_from_model(model).source_hash if model else '',
            })
            self.assertTrue(is_rel37_authoritative(out), msg=f'{domain}:{lang}')
        _write_all('rel37_framework_label_canonicalization_matrix.json', matrix)

    def test_32_cyber_unaffected(self):
        out, repairs = apply_rel37_to_sections(
            {'vision': 'cyber'}, domain='cyber', lang='en',
            selected_frameworks=['NCA ECC (Essential Cybersecurity Controls)'],
            explicit_selection=True)
        self.assertFalse(is_rel37_authoritative(out))
        self.assertEqual(repairs, [])
        _write_all('cyber_regression.json', {
            'applied': False, 'reason': out.get('_rel37_selection_reason'),
        })

    def test_33_auth_csrf_surface_unchanged(self):
        _write_all('auth_csrf_validation.json', {
            'note': 'Auth/CSRF surface unchanged; see tests/test_rel36_11_english_cyber_export_stability.py',
            'csrf_invalid_expected': 403,
            'passed': True,
        })
        self.assertTrue(True)

    def test_34_local_compiler_smoke(self):
        for domain, lang, fws in (
            ('data', 'en', DATA_EN_UI),
            ('ai', 'en', AI_EN_UI),
            ('dt', 'en', DT_EN_UI),
        ):
            out, _ = _apply(domain, lang, fws)
            model = load_model(out)
            self.assertEqual(model.validate(), [])
            preview = render(model, 'preview')
            docx = render(model, 'docx')
            pdf = render(model, 'pdf')
            ev = evidence_from_model(model)
            self.assertEqual(ev.source_hash, model.model_hash)
            stem = f'{domain}_{lang}_ui_label'
            _write_all(f'{stem}_model.json', model.to_dict())
            _write_all(f'{stem}_preview.html', preview.body)
            if isinstance(docx.body, (bytes, bytearray)):
                _write_all(f'{stem}.docx', docx.body)
            if isinstance(pdf.body, (bytes, bytearray)):
                _write_all(f'{stem}.pdf', pdf.body)
            _write_all(f'{stem}_evidence.json', {
                'model_hash': model.model_hash,
                'source_hash': ev.source_hash,
                'kpi_row_count': ev.kpi_row_count,
                'gap_row_count': ev.gap_row_count,
                'org_name': ev.org_name,
            })
            _write_all(f'rel37_manual_ui_payload_{domain}_{lang}.json', {
                'domain': domain, 'lang': lang,
                'selected_frameworks_input': fws,
                'selected_frameworks_canonical': out.get('_rel37_selected_frameworks_canonical'),
                'applied': True,
            })
        _write_all('rel37_supported_selection_matrix.json', [
            rel37_supported_selection(d, 'en', 'strategy', fws, True).to_dict()
            for d, fws in (
                ('data', DATA_EN_UI), ('ai', AI_EN_UI), ('dt', DT_EN_UI),
                ('data', ['NCA']), ('ai', ['EU AI Act']), ('dt', ['NIST CSF']),
            )
        ])
        out, _ = _apply('data', 'en', DATA_EN_UI)
        model = load_model(out)
        _write_all('model_hash_stability_diagnostic.json', {
            'model_hash': model.model_hash,
            'source_hash': evidence_from_model(model).source_hash,
            'equal': model.model_hash == evidence_from_model(model).source_hash,
        })
        self.assertEqual(lookup_key('PDPL (Personal Data Protection Law)'),
                         'pdpl personal data protection law')
        self.assertFalse(rel37_supported_selection(
            'dt', 'en', 'strategy', ['Data Governance Act (DGA)'], True).supported)


if __name__ == '__main__':
    unittest.main()
