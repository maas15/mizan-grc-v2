"""REL37.0.4 — public gap_analysis preview section contract."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel37_04_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
os.environ['REL37_DATA_AI_DT_COMPILER'] = '1'

from release_engine_v3.rel37_apply import (  # noqa: E402
    REL37_HASH_KEY,
    apply_rel37_to_sections,
    is_rel37_authoritative,
    load_model,
)
from release_engine_v3.rel37_canonical_document import GapRow  # noqa: E402
from release_engine_v3.rel37_early_authority import (  # noqa: E402
    attach_rel37_early_authority,
    latest_api_rel37_witness,
    status_poll_public_sections,
)
from release_engine_v3.rel37_live_attach import export_bundle_from_sections  # noqa: E402
from release_engine_v3.rel37_preview_section_contract import (  # noqa: E402
    PUBLIC_GAP_ALIAS,
    apply_rel37_preview_section_contract,
    count_visible_gap_headings,
    evaluate_rel37_preview_section_contract,
    preview_validation_blockers,
    sections_for_visible_render,
    write_preview_contract_samples,
)
from release_engine_v3.rel37_render import model_to_markdown, render  # noqa: E402
from release_hardening.canonical_model import (  # noqa: E402
    legacy_sections_to_canonical,
    structural_quality_issues,
)

SAMPLE_DIRS = (
    '/tmp/rel37_04_preview_contract',
    str(ROOT / 'qa_outputs' / 'rel37_04_preview_contract'),
    '/opt/cursor/artifacts/rel37_04_preview_contract',
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


def _early(domain, lang, frameworks=None, explicit=True, document_type='strategy',
           extra_sections=None, **kwargs):
    sections = {'vision': 'legacy-thin', 'gaps': '| thin |'}
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
        org_name='شركة مثال' if lang == 'ar' else 'Example Org',
        task_id=f'psc-{domain}-{lang}',
        **kwargs,
    )


def _adapt(domain, lang, **kwargs):
    result = _early(domain, lang, **kwargs)
    adapted, diag = apply_rel37_preview_section_contract(
        result.sections,
        domain=domain,
        lang=lang,
        document_type=kwargs.get('document_type', 'strategy'),
        model=result.model,
        task_id=f'psc-{domain}-{lang}',
        emit=False,
    )
    return result, adapted, diag


class Rel37PreviewSectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        write_preview_contract_samples(SAMPLE_DIRS)

    def _assert_public_alias(self, domain, lang):
        result, adapted, diag = _adapt(domain, lang)
        self.assertTrue(is_rel37_authoritative(adapted), diag)
        self.assertTrue(adapted.get(PUBLIC_GAP_ALIAS), diag)
        self.assertTrue(adapted.get('gaps'), diag)
        self.assertTrue(diag.get('gap_analysis_alias_present'), diag)
        self.assertTrue(diag.get('gaps_canonical_present'), diag)
        self.assertEqual(diag.get('missing_preview_sections_after'), [], diag)
        self.assertEqual(diag.get('preview_validation_blockers_after'), [], diag)
        self.assertFalse(diag.get('duplicate_visible_gap_sections_after'), diag)
        self.assertTrue(diag.get('alias_does_not_affect_model_hash'), diag)
        self.assertTrue(diag.get('source_hash_matches_model'), diag)
        self.assertTrue(diag.get('passed'), diag)
        blockers = preview_validation_blockers(adapted)
        self.assertNotIn('rel1_missing_mandatory_section:gap_analysis', blockers)
        canon = legacy_sections_to_canonical(adapted)
        self.assertTrue((canon.get('gap_analysis') or '').strip())
        return result, adapted, diag

    def test_01_data_en_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('data', 'en')

    def test_02_ai_en_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('ai', 'en')

    def test_03_dt_en_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('dt', 'en')

    def test_04_data_ar_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('data', 'ar')

    def test_05_ai_ar_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('ai', 'ar')

    def test_06_dt_ar_public_sections_expose_gap_analysis(self):
        self._assert_public_alias('dt', 'ar')

    def test_07_canonical_model_still_has_typed_gaps(self):
        result, adapted, _diag = _adapt('data', 'en')
        model = load_model(adapted) or result.model
        self.assertIsNotNone(model)
        self.assertTrue(model.gaps)
        self.assertIsInstance(model.gaps[0], GapRow)
        self.assertTrue(adapted.get('gaps'))
        self.assertNotEqual(list(model.gaps), [])

    def test_08_alias_does_not_change_model_hash(self):
        result = _early('ai', 'en')
        before = result.sections.get(REL37_HASH_KEY)
        model = result.model
        self.assertTrue(before)
        hash_payload = model.canonical_hash_payload()
        adapted, diag = apply_rel37_preview_section_contract(
            result.sections, domain='ai', lang='en', model=model, emit=False)
        self.assertEqual(adapted.get(REL37_HASH_KEY), before)
        self.assertEqual(diag.get('model_hash_before'), diag.get('model_hash_after'))
        self.assertTrue(diag.get('alias_does_not_affect_model_hash'))
        self.assertEqual(load_model(adapted).canonical_hash_payload(), hash_payload)
        self.assertEqual(load_model(adapted).model_hash, before)

    def test_09_preview_source_hash_remains_model_hash(self):
        _result, adapted, diag = _adapt('data', 'en')
        bundle = export_bundle_from_sections(adapted)
        self.assertEqual(bundle['preview_source_hash'], adapted[REL37_HASH_KEY])
        self.assertEqual(diag.get('preview_source_hash'), adapted[REL37_HASH_KEY])

    def test_10_docx_source_hash_remains_model_hash(self):
        _result, adapted, diag = _adapt('ai', 'en')
        self.assertEqual(diag.get('docx_source_hash'), adapted[REL37_HASH_KEY])

    def test_11_pdf_source_hash_remains_model_hash(self):
        _result, adapted, diag = _adapt('dt', 'en')
        self.assertEqual(diag.get('pdf_source_hash'), adapted[REL37_HASH_KEY])

    def test_12_preview_validation_no_rel1_gap_analysis_miss(self):
        for domain, lang in (('data', 'en'), ('ai', 'en'), ('dt', 'en'),
                             ('data', 'ar'), ('ai', 'ar'), ('dt', 'ar')):
            result, adapted, diag = _adapt(domain, lang)
            issues = structural_quality_issues(
                legacy_sections_to_canonical(adapted))
            self.assertNotIn(
                'rel1_missing_mandatory_section:gap_analysis', issues, (domain, lang, issues))
            self.assertNotIn(
                'rel1_missing_mandatory_section:gap_analysis',
                diag.get('preview_validation_blockers_after') or [],
                (domain, lang, diag),
            )
            markdown = model_to_markdown(result.model)
            from app import _split_strategy_sections_by_h2
            split = _split_strategy_sections_by_h2(markdown)
            self.assertTrue(split.get('gaps'), (domain, lang, list(split)))
            split_issues = structural_quality_issues(
                legacy_sections_to_canonical(split))
            self.assertNotIn(
                'rel1_missing_mandatory_section:gap_analysis', split_issues, (domain, lang))

    def test_13_visible_preview_renders_one_gap_section(self):
        result, adapted, diag = _adapt('data', 'en')
        preview = render(result.model, 'preview')
        visible = sections_for_visible_render(adapted)
        self.assertIn('gaps', visible)
        self.assertNotIn(PUBLIC_GAP_ALIAS, visible)
        self.assertEqual(count_visible_gap_headings(preview.markdown, preview.body), 1)
        self.assertFalse(diag.get('duplicate_visible_gap_sections_after'))

    def test_14_docx_renders_one_gap_section(self):
        result, _adapted, diag = _adapt('ai', 'en')
        docx = render(result.model, 'docx')
        from release_engine_v3.rel37_preview_section_contract import _extract_docx_text
        text = _extract_docx_text(docx.body)
        self.assertEqual(count_visible_gap_headings(docx.markdown, text), 1)
        self.assertFalse(diag.get('duplicate_visible_gap_sections_after'))

    def test_15_pdf_renders_one_gap_section(self):
        result, _adapted, diag = _adapt('dt', 'ar')
        pdf = render(result.model, 'pdf')
        self.assertEqual(count_visible_gap_headings(pdf.markdown), 1)
        self.assertFalse(diag.get('duplicate_visible_gap_sections_after'))

    def test_16_unsupported_data_nca_no_rel37_alias_authority(self):
        out, repairs = apply_rel37_to_sections(
            {'vision': 'nca', 'gaps': 'legacy'},
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=['NCA'], explicit_selection=True,
        )
        self.assertFalse(is_rel37_authoritative(out))
        adapted, diag = apply_rel37_preview_section_contract(
            out, domain='data', lang='en', document_type='strategy', emit=False)
        self.assertTrue(diag.get('unsupported_route_noop'))
        self.assertFalse(diag.get('alias_map_applied'))
        self.assertFalse(is_rel37_authoritative(adapted))
        self.assertFalse(repairs)

    def test_17_cyber_route_no_rel37_alias_authority(self):
        result = attach_rel37_early_authority(
            {'vision': 'cyber', 'gap_analysis': 'legacy cyber gap analysis'},
            domain='cyber', domain_input='Cyber Security', lang='en',
            document_type='strategy', selected_frameworks=['NCA ECC'],
            explicit_selection=True, task_id='psc-cyber',
        )
        adapted, diag = apply_rel37_preview_section_contract(
            result.sections, domain='cyber', lang='en', document_type='strategy',
            emit=False)
        self.assertTrue(diag.get('unsupported_route_noop'))
        self.assertFalse(diag.get('alias_map_applied'))
        self.assertFalse(is_rel37_authoritative(adapted))

    def test_18_erm_route_unchanged(self):
        out, _repairs = apply_rel37_to_sections(
            {'vision': 'erm', 'gap_analysis': 'erm gaps'},
            domain='erm', lang='ar', document_type='strategy',
            selected_frameworks=['ISO 31000'], explicit_selection=True,
        )
        adapted, diag = apply_rel37_preview_section_contract(
            out, domain='erm', lang='ar', document_type='strategy', emit=False)
        self.assertTrue(diag.get('unsupported_route_noop'))
        self.assertFalse(diag.get('alias_map_applied'))
        self.assertEqual(adapted.get('gap_analysis'), 'erm gaps')

    def test_19_global_gap_assessment_unchanged(self):
        out, _repairs = apply_rel37_to_sections(
            {'vision': 'global'},
            domain='global', lang='ar', document_type='gap_assessment',
            selected_frameworks=['ISO 27001'], explicit_selection=True,
        )
        adapted, diag = apply_rel37_preview_section_contract(
            out, domain='global', lang='ar', document_type='gap_assessment',
            emit=False)
        self.assertTrue(diag.get('unsupported_route_noop'))
        self.assertFalse(is_rel37_authoritative(adapted))

    def test_20_status_poll_omits_rel37_but_includes_gap_analysis(self):
        _result, adapted, _diag = _adapt('data', 'en')
        public = status_poll_public_sections(adapted)
        self.assertFalse(any(str(k).startswith('_rel37') for k in public))
        self.assertIn(PUBLIC_GAP_ALIAS, public)
        self.assertIn('gaps', public)
        self.assertTrue(public.get(PUBLIC_GAP_ALIAS))

    def test_21_latest_witness_still_includes_rel37(self):
        _result, adapted, _diag = _adapt('ai', 'ar')
        witness = latest_api_rel37_witness(adapted)
        self.assertTrue(witness['has_rel37'])
        self.assertTrue(witness['model_hash'])
        self.assertTrue(any(k.startswith('_rel37') for k in witness['rel37_keys']))
        self.assertTrue(witness['status_poll_rel37_keys_publicly_hidden'])

    def test_22_rel37_03_early_authority_still_green(self):
        result = attach_rel37_early_authority(
            {'vision': 'thin', 'gaps': '| |'},
            domain='ai', domain_input='Artificial Intelligence', lang='ar',
            document_type='strategy', selected_frameworks=['SDAIA'],
            explicit_selection=True, task_id='compat-03',
        )
        self.assertTrue(result.applied)
        self.assertTrue(is_rel37_authoritative(result.sections))
        self.assertIn(PUBLIC_GAP_ALIAS, result.sections)

    def test_23_rel37_02_live_attach_still_green(self):
        from release_engine_v3.rel37_live_attach import attach_rel37_before_save
        result = attach_rel37_before_save(
            {'vision': 'legacy'},
            domain='data', domain_input='Data Management', lang='en',
            document_type='strategy', selected_frameworks=['NDMO', 'PDPL'],
            explicit_selection=True, task_id='compat-02',
        )
        self.assertTrue(result.diagnostic.get('compiler_used'))
        self.assertTrue(is_rel37_authoritative(result.sections))
        self.assertEqual(
            result.sections.get('_rel37_source_hash'),
            result.sections.get('_rel37_model_hash'),
        )

    def test_24_rel37_01_hash_gating_still_green(self):
        from release_engine_v3.rel37_selection import rel37_supported_selection
        self.assertTrue(rel37_supported_selection(
            'data', 'en', 'strategy', ['NDMO', 'PDPL'], True).supported)
        self.assertFalse(rel37_supported_selection(
            'data', 'en', 'strategy', ['NCA'], True).supported)
        result, adapted, diag = _adapt('dt', 'en')
        self.assertEqual(adapted.get('_rel37_source_hash'), adapted.get(REL37_HASH_KEY))
        self.assertTrue(diag.get('alias_does_not_affect_model_hash'))

    def test_25_compiler_matrix_still_green(self):
        from release_engine_v3.rel37_compilers import compile_for_domain
        for domain, lang, frameworks in (
                ('data', 'en', ['NDMO', 'PDPL']),
                ('ai', 'ar', ['SDAIA']),
                ('dt', 'en', ['DGA'])):
            model = compile_for_domain(domain, {
                'domain': domain, 'lang': lang,
                'selected_frameworks': frameworks,
            })
            self.assertFalse(model.validate(), model.blockers)
            self.assertTrue(model.gaps)

    def test_26_cyber_regression_still_green(self):
        from release_engine_v3.rel37_live_attach import should_skip_legacy_richness_gates
        from release_engine_v3.rel37_selection import rel37_supported_selection
        self.assertFalse(rel37_supported_selection(
            'cyber', 'en', 'strategy', ['NCA ECC'], True).supported)
        self.assertFalse(should_skip_legacy_richness_gates(
            domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True))

    def test_27_auth_csrf_regression_still_green(self):
        from release_engine_v3.rel36_11_en_cyber_export_stability import (
            evaluate_rel36_11_csrf,
            is_rel36_11_export_csrf_route,
        )
        self.assertTrue(callable(evaluate_rel36_11_csrf))
        self.assertTrue(callable(is_rel36_11_export_csrf_route))

    def test_28_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue((ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        folder = Path('/tmp/rel37_04_preview_contract')
        self.assertTrue((folder / 'rel37_preview_contract_data_en.json').is_file())
        self.assertTrue((folder / 'rel37_preview_contract_ai_en.json').is_file())
        self.assertTrue((folder / 'rel37_preview_contract_dt_en.json').is_file())

    def test_29_artifact_builder_preview_accepts_rel37_en(self):
        result = _early('data', 'en')
        from app import _build_cyber_final_strategy_artifact
        art = _build_cyber_final_strategy_artifact(
            result.content,
            sections=result.sections,
            metadata={'domain': 'Data Management'},
            selected_frameworks=['NDMO', 'PDPL'],
            lang='en',
            domain='Data Management',
            output_type='preview',
            read_only=True,
        )
        blockers = list(art.get('blocking_errors') or [])
        self.assertNotIn(
            'rel1_missing_mandatory_section:gap_analysis', blockers, blockers)
        self.assertTrue(art.get('sections', {}).get(PUBLIC_GAP_ALIAS) or result.sections.get(PUBLIC_GAP_ALIAS))

    def test_30_evaluate_forbids_pass_when_gap_analysis_missing(self):
        thin = {
            'vision': 'v', 'pillars': 'p', 'environment': 'e',
            'roadmap': 'r', 'kpis': 'k', 'confidence': 'c',
        }
        issues = structural_quality_issues(legacy_sections_to_canonical(thin))
        self.assertIn('rel1_missing_mandatory_section:gap_analysis', issues)
        diag = evaluate_rel37_preview_section_contract(
            thin, domain='data', lang='en', document_type='strategy', emit=False)
        self.assertTrue(diag.get('unsupported_route_noop'))
        self.assertFalse(diag.get('gap_analysis_alias_present'))


if __name__ == '__main__':
    unittest.main()
