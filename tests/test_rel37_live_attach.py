"""REL37.0.2 — live generate/save compiler attachment."""
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

_TMP = tempfile.mkdtemp(prefix='test_rel37_02_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

from release_engine_v3.rel37_apply import (  # noqa: E402
    is_rel37_authoritative,
)
from release_engine_v3.rel37_canonical_document import CanonicalDocument  # noqa: E402
from release_engine_v3.rel37_live_attach import (  # noqa: E402
    Rel37ModelValidationFailed,
    attach_rel37_before_save,
    candidate_matches_latest_preview,
    export_bundle_from_sections,
    pick_latest_preview_row,
    should_skip_legacy_richness_gates,
    write_live_attach_samples,
)
from release_engine_v3.rel37_selection import rel37_supported_selection  # noqa: E402
from release_engine_v3.rel36_bilingual_preview_export_authority import (  # noqa: E402
    normalize_preview_sections,
)

SAMPLE_DIRS = (
    '/tmp/rel37_02_live_attach',
    str(ROOT / 'qa_outputs' / 'rel37_02_live_attach'),
    '/opt/cursor/artifacts/rel37_02_live_attach',
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


def _attach(domain, lang, frameworks=None, explicit=True, document_type='strategy',
            extra_sections=None, org_name='', **kwargs):
    sections = {'vision': 'legacy-pre-rel37', 'kpis': '| thin |'}
    if extra_sections:
        sections.update(extra_sections)
    return attach_rel37_before_save(
        sections,
        domain=domain,
        domain_input=_DISPLAY.get(domain, domain),
        lang=lang,
        document_type=document_type,
        selected_frameworks=frameworks if frameworks is not None else _SUPPORTED_FW.get(domain),
        explicit_selection=explicit,
        org_name=org_name or ('شركة مثال' if lang == 'ar' else 'Example Org'),
        task_id=f'{domain}-{lang}',
        **kwargs,
    )


class Rel37LiveAttachTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        write_live_attach_samples(SAMPLE_DIRS)

    def _assert_attached(self, result, domain, lang):
        self.assertTrue(result.diagnostic.get('compiler_used'), result.diagnostic)
        self.assertTrue(result.diagnostic.get('saved_sections_has_rel37'), result.diagnostic)
        self.assertTrue(is_rel37_authoritative(result.sections))
        self.assertIn(str(result.sections.get('_rel37_applied')).lower(), ('1', 'true'))
        self.assertTrue(result.sections.get('_rel37_canonical'))
        self.assertTrue(result.sections.get('_rel37_model_hash'))
        self.assertEqual(
            result.sections.get('_rel37_source_hash'),
            result.sections.get('_rel37_model_hash'),
        )
        self.assertTrue(result.content)
        self.assertNotIn('legacy-pre-rel37', result.content)
        self.assertEqual(result.diagnostic.get('domain_resolved'), domain)
        self.assertEqual(result.diagnostic.get('lang'), lang)
        self.assertTrue(result.diagnostic.get('old_richness_gates_skipped'))
        self.assertTrue(result.diagnostic.get('model_validation_passed'))
        self.assertEqual(result.diagnostic.get('app_blockers_after'), [])
        self.assertTrue(result.diagnostic.get('passed'), result.diagnostic)
        self.assertEqual(
            result.diagnostic.get('save_input_hash'),
            result.diagnostic.get('rendered_markdown_hash'),
        )
        self.assertEqual(
            result.diagnostic.get('preview_source_hash'),
            result.diagnostic.get('model_hash'),
        )
        self.assertEqual(
            result.diagnostic.get('docx_source_hash'),
            result.diagnostic.get('model_hash'),
        )
        self.assertEqual(
            result.diagnostic.get('pdf_source_hash'),
            result.diagnostic.get('model_hash'),
        )

    def test_01_data_ar_supported_attaches_before_save(self):
        self._assert_attached(_attach('data', 'ar'), 'data', 'ar')

    def test_02_data_en_supported_attaches_before_save(self):
        self._assert_attached(_attach('data', 'en'), 'data', 'en')

    def test_03_ai_ar_supported_attaches_before_save(self):
        self._assert_attached(_attach('ai', 'ar'), 'ai', 'ar')

    def test_04_ai_en_supported_attaches_before_save(self):
        self._assert_attached(_attach('ai', 'en'), 'ai', 'en')

    def test_05_dt_ar_supported_attaches_before_save(self):
        self._assert_attached(_attach('dt', 'ar'), 'dt', 'ar')

    def test_06_dt_en_supported_attaches_before_save(self):
        self._assert_attached(_attach('dt', 'en'), 'dt', 'en')

    def test_07_saved_sections_json_contains_rel37_keys(self):
        result = _attach('data', 'ar')
        dumped = json.loads(json.dumps(result.sections, ensure_ascii=False))
        self.assertTrue(dumped.get('_rel37_applied'))
        self.assertTrue(dumped.get('_rel37_canonical'))
        self.assertTrue(json.loads(dumped['_rel37_canonical']))

    def test_08_saved_content_comes_from_rel37_model(self):
        result = _attach('ai', 'en')
        self.assertIn('## 1. Strategic Vision and Objectives', result.content)
        self.assertIn('| KPI Description |', result.content)
        self.assertEqual(result.content, result.sections.get('_rel37_markdown'))

    def test_09_old_richness_gate_does_not_block_data_en(self):
        result = _attach('data', 'en')
        self.assertTrue(should_skip_legacy_richness_gates(
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], explicit_selection=True,
            sections=result.sections))
        from app import _final_strategy_audit
        defects = _final_strategy_audit(
            result.sections, 'en', 'technical',
            selected_frameworks=['NDMO', 'PDPL'],
            domain='Data Management',
            document_type='strategy',
        )
        self.assertEqual(defects, [])

    def test_10_old_richness_gate_does_not_block_ai_en(self):
        result = _attach('ai', 'en')
        from app import _final_strategy_audit
        defects = _final_strategy_audit(
            result.sections, 'en', 'technical',
            selected_frameworks=['SDAIA'],
            domain='Artificial Intelligence',
            document_type='strategy',
        )
        self.assertEqual(defects, [])

    def test_11_old_richness_gate_does_not_block_dt_en(self):
        result = _attach('dt', 'en')
        from app import _final_strategy_audit
        defects = _final_strategy_audit(
            result.sections, 'en', 'technical',
            selected_frameworks=['DGA'],
            domain='Digital Transformation',
            document_type='strategy',
        )
        self.assertEqual(defects, [])

    def test_12_model_validation_failure_fails_closed(self):
        with patch.object(CanonicalDocument, 'validate', return_value=['injected_blocker']):
            with self.assertRaises(Rel37ModelValidationFailed) as ctx:
                _attach('data', 'en')
        self.assertIn('injected_blocker', ctx.exception.blockers)

    def test_13_unsupported_data_nca_does_not_attach(self):
        result = _attach('data', 'ar', frameworks=['NCA'], explicit=True)
        self.assertFalse(result.diagnostic.get('compiler_used'))
        self.assertFalse(is_rel37_authoritative(result.sections))
        self.assertNotIn('_rel37_canonical', result.sections)
        self.assertEqual(result.diagnostic.get('support_reason'), 'unsupported_frameworks')

    def test_14_unsupported_ai_eu_ai_act_does_not_attach(self):
        result = _attach('ai', 'en', frameworks=['EU AI Act'], explicit=True)
        self.assertFalse(is_rel37_authoritative(result.sections))
        self.assertFalse(result.diagnostic.get('compiler_used'))

    def test_15_unsupported_dt_nist_csf_does_not_attach(self):
        result = _attach('dt', 'en', frameworks=['NIST CSF'], explicit=True)
        self.assertFalse(is_rel37_authoritative(result.sections))
        self.assertFalse(result.diagnostic.get('compiler_used'))

    def test_16_cyber_does_not_attach(self):
        result = attach_rel37_before_save(
            {'vision': 'cyber-legacy'},
            domain='cyber',
            domain_input='Cyber Security',
            lang='ar',
            document_type='strategy',
            selected_frameworks=['NCA ECC'],
            explicit_selection=True,
        )
        self.assertFalse(result.diagnostic.get('compiler_used'))
        self.assertEqual(result.diagnostic.get('support_reason'), 'domain_not_supported')
        self.assertFalse(is_rel37_authoritative(result.sections))

    def test_17_erm_does_not_attach(self):
        result = attach_rel37_before_save(
            {'vision': 'erm-legacy'},
            domain='erm',
            domain_input='Enterprise Risk Management',
            lang='ar',
            document_type='strategy',
            selected_frameworks=['ISO 31000'],
            explicit_selection=True,
        )
        self.assertFalse(result.diagnostic.get('compiler_used'))
        self.assertEqual(result.diagnostic.get('support_reason'), 'domain_not_supported')

    def test_18_global_gap_assessment_does_not_attach(self):
        result = attach_rel37_before_save(
            {'vision': 'global-gap'},
            domain='global',
            domain_input='Global Standards',
            lang='ar',
            document_type='gap_assessment',
            selected_frameworks=['ISO 27001'],
            explicit_selection=True,
        )
        self.assertFalse(result.diagnostic.get('compiler_used'))
        self.assertIn(
            result.diagnostic.get('support_reason'),
            ('domain_not_supported', 'document_type_not_supported'),
        )

    def test_19_preview_loads_rel37_data_ar(self):
        result = _attach('data', 'ar')
        previewed = normalize_preview_sections(result.sections)
        self.assertTrue(previewed.get('_rel37_canonical'))
        self.assertTrue(previewed.get('_rel37_applied'))
        bundle = export_bundle_from_sections(result.sections)
        self.assertEqual(bundle['preview_source_hash'], result.diagnostic['model_hash'])

    def test_20_preview_loads_rel37_data_en(self):
        result = _attach('data', 'en')
        previewed = normalize_preview_sections(result.sections)
        self.assertTrue(previewed.get('_rel37_model_hash'))
        bundle = export_bundle_from_sections(result.sections)
        self.assertEqual(bundle['preview_source_hash'], result.diagnostic['model_hash'])
        self.assertIn('Strategic Vision', bundle['markdown'])

    def test_21_docx_export_uses_rel37_source_hash(self):
        result = _attach('ai', 'ar')
        bundle = export_bundle_from_sections(result.sections)
        self.assertEqual(bundle['docx_source_hash'], result.sections['_rel37_model_hash'])

    def test_22_pdf_export_uses_rel37_source_hash(self):
        result = _attach('dt', 'en')
        bundle = export_bundle_from_sections(result.sections)
        self.assertEqual(bundle['pdf_source_hash'], result.sections['_rel37_model_hash'])

    def test_23_preview_docx_pdf_source_hash_equals_model_hash(self):
        for domain, lang in (('data', 'ar'), ('ai', 'en'), ('dt', 'ar')):
            result = _attach(domain, lang)
            bundle = export_bundle_from_sections(result.sections)
            model_hash = result.sections['_rel37_model_hash']
            self.assertEqual(bundle['preview_source_hash'], model_hash)
            self.assertEqual(bundle['docx_source_hash'], model_hash)
            self.assertEqual(bundle['pdf_source_hash'], model_hash)
            self.assertTrue(bundle['hashes_match'])

    def test_24_latest_preview_does_not_load_wrong_lang_domain_type(self):
        data_ar = _attach('data', 'ar')
        data_en = _attach('data', 'en')
        ai_ar = _attach('ai', 'ar')
        rows = [
            {
                'id': 1,
                'domain': 'Data Management',
                'language': 'en',
                'document_type': 'strategy',
                'sections': data_en.sections,
            },
            {
                'id': 2,
                'domain': 'Data Management',
                'language': 'ar',
                'document_type': 'strategy',
                'sections': data_ar.sections,
            },
            {
                'id': 3,
                'domain': 'Artificial Intelligence',
                'language': 'ar',
                'document_type': 'strategy',
                'sections': ai_ar.sections,
            },
            {
                'id': 4,
                'domain': 'Data Management',
                'language': 'ar',
                'document_type': 'gap_assessment',
                'sections': {**data_ar.sections, '_document_type': 'gap_assessment'},
            },
        ]
        picked = pick_latest_preview_row(
            rows, domain='data', lang='ar', document_type='strategy')
        self.assertEqual(picked['id'], 2)
        self.assertFalse(candidate_matches_latest_preview(
            rows[0], domain='data', lang='ar', document_type='strategy'))
        self.assertIsNone(pick_latest_preview_row(
            rows, domain='cyber', lang='ar', document_type='strategy'))
        self.assertEqual(
            pick_latest_preview_row(rows, strategy_id='3')['id'], 3)

    def test_25_feature_switch_off_disables_attach(self):
        with patch.dict(os.environ, {'REL37_DATA_AI_DT_COMPILER': '0'}):
            result = _attach('data', 'ar')
        self.assertFalse(result.diagnostic.get('compiler_used'))
        self.assertEqual(result.diagnostic.get('support_reason'), 'feature_switch_off')
        self.assertFalse(is_rel37_authoritative(result.sections))

    def test_26_diagnostic_passed_true_for_supported_routes(self):
        for domain in ('data', 'ai', 'dt'):
            for lang in ('ar', 'en'):
                result = _attach(domain, lang)
                self.assertTrue(result.diagnostic.get('passed'), result.diagnostic)
                self.assertTrue(result.diagnostic.get('compiler_used'))

    def test_27_rel37_01_hash_tests_still_pass(self):
        from release_engine_v3.rel37_compilers import compile_for_domain
        from release_engine_v3.rel37_render import evidence_from_model
        model = compile_for_domain('data', {
            'domain': 'data', 'lang': 'en', 'selected_frameworks': ['ndmo', 'pdpl'],
        })
        ev = evidence_from_model(model)
        self.assertEqual(ev.source_hash, model.model_hash)
        self.assertEqual(model.compute_model_hash(), model.model_hash)

    def test_28_rel37_01_supported_selection_tests_still_pass(self):
        self.assertTrue(rel37_supported_selection(
            'data', 'ar', 'strategy', ['NDMO', 'PDPL'], True).supported)
        self.assertFalse(rel37_supported_selection(
            'data', 'ar', 'strategy', ['NCA'], True).supported)
        self.assertFalse(rel37_supported_selection(
            'ai', 'en', 'strategy', ['EU AI Act'], True).supported)

    def test_29_data_ai_dt_compiler_matrix_still_passes(self):
        from release_engine_v3.rel37_compilers import compile_for_domain
        for domain, frameworks in _SUPPORTED_FW.items():
            for lang in ('ar', 'en'):
                model = compile_for_domain(domain, {
                    'domain': domain,
                    'lang': lang,
                    'selected_frameworks': [fw.lower() for fw in frameworks],
                })
                self.assertFalse(model.validate(), (domain, lang, model.blockers))

    def test_30_cyber_regression_still_no_rel37(self):
        self.assertFalse(rel37_supported_selection(
            'cyber', 'ar', 'strategy', ['NCA ECC'], True).supported)
        self.assertFalse(should_skip_legacy_richness_gates(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True))

    def test_31_auth_csrf_regression_hooks_unchanged(self):
        from release_engine_v3.rel36_11_en_cyber_export_stability import (
            evaluate_rel36_11_csrf,
            is_rel36_11_export_csrf_route,
        )
        self.assertTrue(callable(evaluate_rel36_11_csrf))
        self.assertTrue(callable(is_rel36_11_export_csrf_route))

    def test_32_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue((ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())

    def test_live_display_names_normalize(self):
        for domain, display in _DISPLAY.items():
            result = attach_rel37_before_save(
                {'vision': 'x'},
                domain=display,
                domain_input=display,
                lang='ar',
                document_type='strategy',
                selected_frameworks=_SUPPORTED_FW[domain],
                explicit_selection=True,
            )
            self.assertEqual(result.diagnostic['domain_resolved'], domain)
            self.assertTrue(result.diagnostic['compiler_used'], result.diagnostic)

    def test_document_type_strategy_document_alias_not_required_at_hook(self):
        # Live generate aliases this before persist; unaliased is unsupported.
        result = attach_rel37_before_save(
            {'vision': 'x'},
            domain='data',
            lang='ar',
            document_type='Strategy Document',
            selected_frameworks=['NDMO'],
            explicit_selection=True,
        )
        self.assertFalse(result.diagnostic['compiler_used'])
        self.assertEqual(
            result.diagnostic['support_reason'], 'document_type_not_supported')


if __name__ == '__main__':
    unittest.main()
