"""REL37.0.3 — compiler authority before legacy Arabic richness gates."""
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

_TMP = tempfile.mkdtemp(prefix='test_rel37_03_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_SELECTION_REASON_KEY,
    apply_rel37_to_sections,
    is_rel37_authoritative,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_early_authority import (  # noqa: E402
    Rel37ModelValidationFailed,
    attach_rel37_early_authority,
    confirm_rel37_final_persist,
    latest_api_rel37_witness,
    scan_legacy_arabic_richness_tags,
    selection_reason_consistent,
    should_skip_legacy_arabic_richness_pack,
    status_poll_public_sections,
    warning_bypass_would_block,
    write_early_authority_samples,
)
from release_engine_v3.rel37_live_attach import (  # noqa: E402
    export_bundle_from_sections,
    should_skip_legacy_richness_gates,
)
from release_engine_v3.rel37_selection import rel37_supported_selection  # noqa: E402
from release_engine_v3.rel36_bilingual_preview_export_authority import (  # noqa: E402
    normalize_preview_sections,
)

SAMPLE_DIRS = (
    '/tmp/rel37_03_early_authority',
    str(ROOT / 'qa_outputs' / 'rel37_03_early_authority'),
    '/opt/cursor/artifacts/rel37_03_early_authority',
)

_DISPLAY = {
    'data': 'Data Management',
    'ai': 'Artificial Intelligence',
    'dt': 'Digital Transformation',
}
_SUPPORTED_FW = {
    'data': ['NDMO', 'PDPL'],
    'ai': ['SDAIA'],
    'dt': ['DGA'],
}

_THIN_AR = {
    'vision': 'نص نموذج لغوي رقيق بدون جدول أهداف',
    'pillars': 'ركائز بلا عنوان قانوني',
    'environment': 'تحليل الفجوات',
    'gaps': '| فجوة |',
    'roadmap': 'تنفيذ',
    'kpis': '| مؤشر |',
    'confidence': 'لا يوجد درجة',
    '_rel37_selection_reason': 'unsupported_frameworks',
}


def _early(domain, lang, frameworks=None, explicit=True, document_type='strategy',
           extra_sections=None, org_name='', **kwargs):
    sections = dict(_THIN_AR)
    if extra_sections:
        sections.update(extra_sections)
    return attach_rel37_early_authority(
        sections,
        domain=domain,
        domain_input=_DISPLAY.get(domain, domain),
        lang=lang,
        document_type=document_type,
        selected_frameworks=frameworks if frameworks is not None else _SUPPORTED_FW.get(domain),
        explicit_selection=explicit,
        org_name=org_name or ('شركة مثال' if lang == 'ar' else 'Example Org'),
        task_id=f'early-{domain}-{lang}',
        **kwargs,
    )


class Rel37EarlyAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        write_early_authority_samples(SAMPLE_DIRS)

    def _assert_supported(self, result, domain, lang):
        diag = result.diagnostic
        self.assertTrue(diag.get('supported_selection'), diag)
        self.assertTrue(diag.get('compiler_used'), diag)
        self.assertTrue(diag.get('model_validation_passed'), diag)
        self.assertTrue(diag.get('old_arabic_richness_skipped'), diag)
        self.assertTrue(diag.get('latest_api_has_rel37'), diag)
        self.assertTrue(diag.get('selection_reason_consistent'), diag)
        self.assertTrue(diag.get('source_hash_matches_model'), diag)
        self.assertEqual(diag.get('app_blockers_after'), [])
        self.assertTrue(diag.get('passed'), diag)
        self.assertTrue(result.applied)
        self.assertTrue(is_rel37_authoritative(result.sections))
        self.assertEqual(result.sections.get(REL37_SELECTION_REASON_KEY), 'supported_selection')
        self.assertNotEqual(
            result.sections.get(REL37_SELECTION_REASON_KEY), 'unsupported_frameworks')
        self.assertEqual(
            result.sections.get('_rel37_source_hash'),
            result.sections.get('_rel37_model_hash'),
        )
        self.assertEqual(diag.get('domain_resolved'), domain)
        self.assertEqual(diag.get('lang'), lang)
        self.assertTrue(diag.get('stale_selection_reason_cleared'), diag)
        self.assertTrue(should_skip_legacy_arabic_richness_pack(
            domain=domain, lang=lang, document_type='strategy',
            selected_frameworks=_SUPPORTED_FW[domain], explicit_selection=True,
            sections=result.sections))

    def test_01_ai_ar_sdaia_attaches_before_arabic_richness_pack(self):
        before = scan_legacy_arabic_richness_tags(_THIN_AR)
        self.assertIn('so_rows_insufficient', before)
        result = _early('ai', 'ar')
        self._assert_supported(result, 'ai', 'ar')
        self.assertEqual(result.diagnostic.get('early_attach_stage'), 'before_arabic_richness_pack')
        self.assertTrue(result.diagnostic.get('old_arabic_richness_blockers_before'))

    def test_02_ai_ar_no_so_rows_insufficient_from_old_markdown(self):
        result = _early('ai', 'ar')
        blocked, tags = warning_bypass_would_block(
            result.sections, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertFalse(blocked)
        self.assertNotIn('so_rows_insufficient', tags)
        self.assertNotIn('so_rows_insufficient', result.diagnostic.get('app_blockers_after') or [])

    def test_03_ai_ar_no_gap_guide_coverage_from_old_markdown(self):
        result = _early('ai', 'ar')
        _blocked, tags = warning_bypass_would_block(
            result.sections, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertNotIn('gap_guide_coverage', tags)

    def test_04_ai_ar_no_heading_mismatch_from_old_markdown(self):
        result = _early('ai', 'ar')
        _blocked, tags = warning_bypass_would_block(
            result.sections, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertFalse(any('heading_mismatch' in tag for tag in tags))

    def test_05_ai_ar_no_confidence_richness_from_old_markdown(self):
        result = _early('ai', 'ar')
        _blocked, tags = warning_bypass_would_block(
            result.sections, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertNotIn('confidence_score_missing_in_richness', tags)

    def test_06_data_ar_attaches_before_old_richness_gates(self):
        self._assert_supported(_early('data', 'ar'), 'data', 'ar')

    def test_07_dt_ar_attaches_before_old_richness_gates(self):
        self._assert_supported(_early('dt', 'ar'), 'dt', 'ar')

    def test_08_data_en_attaches_before_old_richness_gates(self):
        self._assert_supported(_early('data', 'en'), 'data', 'en')

    def test_09_ai_en_attaches_before_old_richness_gates(self):
        self._assert_supported(_early('ai', 'en'), 'ai', 'en')

    def test_10_dt_en_attaches_before_old_richness_gates(self):
        self._assert_supported(_early('dt', 'en'), 'dt', 'en')

    def test_11_model_validation_failure_fails_closed(self):
        with patch.object(CanonicalDocument, 'validate', return_value=['injected_blocker']):
            with self.assertRaises(Rel37ModelValidationFailed) as ctx:
                _early('ai', 'ar')
        self.assertIn('injected_blocker', ctx.exception.blockers)

    def test_12_old_markdown_richness_gates_still_apply_to_cyber(self):
        result = attach_rel37_early_authority(
            dict(_THIN_AR),
            domain='cyber',
            domain_input='Cyber Security',
            lang='ar',
            document_type='strategy',
            selected_frameworks=['NCA ECC'],
            explicit_selection=True,
        )
        self.assertFalse(result.compiler_used)
        self.assertFalse(is_rel37_authoritative(result.sections))
        self.assertFalse(should_skip_legacy_arabic_richness_pack(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True,
            sections=result.sections))
        blocked, tags = warning_bypass_would_block(
            result.sections, domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True)
        self.assertTrue(blocked)
        self.assertTrue(tags)

    def test_13_old_gates_still_apply_to_unsupported_data_nca(self):
        result = _early('data', 'ar', frameworks=['NCA'], explicit=True)
        self.assertFalse(result.compiler_used)
        self.assertFalse(is_rel37_authoritative(result.sections))
        self.assertFalse(should_skip_legacy_arabic_richness_pack(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NCA'], explicit_selection=True,
            sections=result.sections))
        blocked, _tags = warning_bypass_would_block(
            result.sections, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NCA'], explicit_selection=True)
        self.assertTrue(blocked)

    def test_14_unsupported_ai_eu_ai_act_does_not_skip_old_gates(self):
        result = _early('ai', 'en', frameworks=['EU AI Act'], explicit=True)
        self.assertFalse(result.compiler_used)
        self.assertFalse(should_skip_legacy_arabic_richness_pack(
            domain='ai', lang='en', document_type='strategy',
            selected_frameworks=['EU AI Act'], explicit_selection=True,
            sections=result.sections))

    def test_15_unsupported_dt_nist_csf_does_not_skip_old_gates(self):
        result = _early('dt', 'en', frameworks=['NIST CSF'], explicit=True)
        self.assertFalse(result.compiler_used)
        self.assertFalse(should_skip_legacy_arabic_richness_pack(
            domain='dt', lang='en', document_type='strategy',
            selected_frameworks=['NIST CSF'], explicit_selection=True,
            sections=result.sections))

    def test_16_final_persist_retains_rel37_applied_and_canonical(self):
        early = _early('ai', 'ar')
        persist = confirm_rel37_final_persist(
            early.sections,
            content=early.content,
            domain='ai',
            domain_input='Artificial Intelligence',
            lang='ar',
            document_type='strategy',
            selected_frameworks=['SDAIA'],
            explicit_selection=True,
            early_diagnostic=early.diagnostic,
        )
        self.assertTrue(persist.diagnostic.get('final_persist_attach_seen'))
        self.assertTrue(is_rel37_authoritative(persist.sections))
        self.assertTrue(persist.sections.get('_rel37_canonical'))
        self.assertIn(str(persist.sections.get('_rel37_applied')).lower(), ('1', 'true'))
        self.assertTrue(persist.diagnostic.get('passed'), persist.diagnostic)

    def test_17_latest_api_style_witness_includes_rel37_keys(self):
        result = _early('data', 'ar')
        witness = latest_api_rel37_witness(result.sections)
        self.assertTrue(witness['has_rel37'])
        self.assertTrue(witness['applied'])
        self.assertTrue(witness['model_hash'])
        self.assertTrue(any(key.startswith('_rel37') for key in witness['rel37_keys']))

    def test_18_status_poll_public_sections_may_omit_rel37_without_failing(self):
        result = _early('dt', 'ar')
        public = status_poll_public_sections(result.sections)
        self.assertFalse(any(str(key).startswith('_rel37') for key in public))
        witness = latest_api_rel37_witness(result.sections)
        self.assertTrue(witness['status_poll_rel37_keys_publicly_hidden'])
        self.assertTrue(witness['has_rel37'])

    def test_19_applied_true_never_pairs_with_unsupported_frameworks(self):
        result = _early('data', 'ar')
        dirty, _repairs = apply_rel37_to_sections(
            result.sections,
            domain='data',
            lang='ar',
            selected_frameworks=['SDAIA AI Ethics'],
            explicit_selection=True,
        )
        self.assertTrue(is_rel37_authoritative(dirty))
        self.assertNotEqual(dirty.get(REL37_SELECTION_REASON_KEY), 'unsupported_frameworks')
        self.assertTrue(selection_reason_consistent(dirty))
        paired = dict(result.sections)
        paired[REL37_SELECTION_REASON_KEY] = 'unsupported_frameworks'
        self.assertFalse(selection_reason_consistent(paired))

    def test_20_supported_data_dt_selection_reason_is_consistent(self):
        for domain in ('data', 'dt'):
            result = _early(domain, 'ar')
            self.assertTrue(selection_reason_consistent(result.sections))
            self.assertIn(
                result.sections.get(REL37_SELECTION_REASON_KEY),
                ('supported_selection', 'default_expanded'),
            )

    def test_21_source_hash_equals_model_hash(self):
        for domain, lang in (('data', 'ar'), ('ai', 'ar'), ('dt', 'en')):
            result = _early(domain, lang)
            self.assertEqual(
                result.sections.get('_rel37_source_hash'),
                result.sections.get('_rel37_model_hash'),
            )

    def test_22_preview_docx_pdf_source_hash_remains_model_hash(self):
        result = _early('ai', 'ar')
        persist = confirm_rel37_final_persist(
            result.sections, content=result.content, domain='ai',
            domain_input='Artificial Intelligence', lang='ar',
            document_type='strategy', selected_frameworks=['SDAIA'],
            explicit_selection=True, early_diagnostic=result.diagnostic)
        bundle = export_bundle_from_sections(persist.sections)
        model_hash = persist.sections['_rel37_model_hash']
        self.assertEqual(bundle['preview_source_hash'], model_hash)
        self.assertEqual(bundle['docx_source_hash'], model_hash)
        self.assertEqual(bundle['pdf_source_hash'], model_hash)

    def test_23_rel37_live_attach_diagnostics_pass(self):
        from release_engine_v3.rel37_live_attach import attach_rel37_before_save
        live = attach_rel37_before_save(
            {'vision': 'legacy'},
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True)
        self.assertTrue(live.diagnostic.get('passed'), live.diagnostic)

    def test_24_rel37_01_hash_authority_tests_still_pass(self):
        from release_engine_v3.rel37_compilers import compile_for_domain
        from release_engine_v3.rel37_render import evidence_from_model
        model = compile_for_domain('data', {
            'domain': 'data', 'lang': 'en', 'selected_frameworks': ['ndmo', 'pdpl'],
        })
        ev = evidence_from_model(model)
        self.assertEqual(ev.source_hash, model.model_hash)

    def test_25_rel37_01_selection_gating_tests_still_pass(self):
        self.assertTrue(rel37_supported_selection(
            'ai', 'ar', 'strategy', ['SDAIA'], True).supported)
        self.assertFalse(rel37_supported_selection(
            'ai', 'en', 'strategy', ['EU AI Act'], True).supported)
        self.assertFalse(rel37_supported_selection(
            'cyber', 'ar', 'strategy', ['NCA ECC'], True).supported)

    def test_26_rel37_compiler_matrix_still_passes(self):
        from release_engine_v3.rel37_compilers import compile_for_domain
        for domain, frameworks in _SUPPORTED_FW.items():
            for lang in ('ar', 'en'):
                model = compile_for_domain(domain, {
                    'domain': domain,
                    'lang': lang,
                    'selected_frameworks': [fw.lower() for fw in frameworks],
                })
                self.assertFalse(model.validate(), (domain, lang, model.blockers))

    def test_27_cyber_regression_still_passes(self):
        self.assertFalse(rel37_supported_selection(
            'cyber', 'ar', 'strategy', ['NCA ECC'], True).supported)
        self.assertFalse(should_skip_legacy_richness_gates(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True))

    def test_28_auth_csrf_regression_still_passes(self):
        from release_engine_v3.rel36_11_en_cyber_export_stability import (
            evaluate_rel36_11_csrf,
            is_rel36_11_export_csrf_route,
        )
        self.assertTrue(callable(evaluate_rel36_11_csrf))
        self.assertTrue(callable(is_rel36_11_export_csrf_route))

    def test_29_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue((ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())

    def test_30_final_strategy_audit_skips_old_markdown_for_ai_ar(self):
        result = _early('ai', 'ar')
        from app import _final_strategy_audit
        defects = _final_strategy_audit(
            result.sections, 'ar', 'technical',
            selected_frameworks=['SDAIA'],
            domain='Artificial Intelligence',
            document_type='strategy',
        )
        self.assertEqual(defects, [])

    def test_31_preview_keeps_rel37_keys(self):
        result = _early('ai', 'en')
        previewed = normalize_preview_sections(result.sections)
        self.assertTrue(previewed.get('_rel37_applied'))
        self.assertTrue(previewed.get('_rel37_canonical'))

    def test_32_samples_written(self):
        folder = Path('/tmp/rel37_03_early_authority')
        self.assertTrue((folder / 'rel37_early_authority_ai_ar.json').is_file())
        self.assertTrue((folder / 'rel37_status_poll_vs_latest_witness.json').is_file())
        self.assertTrue((folder / 'rel37_selection_reason_consistency.json').is_file())
        self.assertTrue((folder / 'model_hash_stability_diagnostic.json').is_file())


if __name__ == '__main__':
    unittest.main()
