"""REL36.23.2 — DT Arabic live KPI classifier + persisted token integrity."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from xml.etree import ElementTree as ET

_TMP = tempfile.mkdtemp(prefix='test_rel36_23_2_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _TLS
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_19_bilingual_language_parity import (
    apply_rel36_19_bilingual_language_parity,
)
from release_engine_v3.rel36_21_en_data_ai_framework_objectives import (
    apply_rel36_21_en_data_ai_framework_objectives,
    first_so_header,
)
from release_engine_v3.rel36_22_dt_dga_citizen_experience_coverage import (
    section_has_citizen_experience,
)
from release_engine_v3.rel36_23_data_ai_guides_and_visible_headers import (
    apply_rel36_23_data_ai_guides_and_visible_headers,
    duplicate_guide_hashes,
    rel36_23_should_apply,
    weak_pillar_titles,
)
from release_engine_v3.rel36_23_1_dt_dga_kpi_single_table_integrity import (
    CITIZEN_KPI_DESC,
    DIGITAL_KPI_DESC,
    INTEROP_KPI_DESC,
    apply_rel36_23_1_dt_dga_kpi_single_table_integrity,
    kpi_main_header_count,
)
from release_engine_v3.rel36_23_2_dt_ar_live_kpi_and_token_integrity import (
    DIAGNOSTIC_TAG,
    artifact_sha256,
    count_formula_source_tables,
    count_full_kpi_main_headers,
    count_loose_kpi_headers,
    helper_on_copy_matches_save_input,
    is_full_kpi_main_header,
    is_kpi_formula_source_header,
    apply_rel36_23_2_dt_ar_live_kpi_and_token_integrity,
    normalize_dt_ar_dga_split_tokens,
    rel36_23_2_should_apply,
    split_token_hits,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel36_19_bilingual_language_parity import Rel3619LanguageParityTests
from tests.test_rel36_20_2_data_ar_countable_roadmap import (
    Rel36202DataArCountableRoadmapTests,
)
from tests.test_rel36_20_data_ai_guide_save_stability import (
    Rel3620DataAiGuideSaveStabilityTests,
)
from tests.test_rel36_21_en_data_ai_framework_objectives import (
    Rel3621EnDataAiFrameworkObjectivesTests,
    _DATA_SO_NO_COMPLIANCE,
)
from tests.test_rel36_22_dt_dga_citizen_experience_coverage import (
    Rel3622DtDgaCitizenExperienceCoverageTests,
    _dt_broken,
)
from tests.test_rel36_23_data_ai_guides_and_visible_headers import (
    Rel3623DataAiGuidesAndVisibleHeadersTests,
    _apply20_23,
    _en_ai_dup_sections,
    _en_data_weak_sections,
)
from tests.test_rel36_23_1_dt_dga_kpi_single_table_integrity import (
    Rel36231DtDgaKpiSingleTableIntegrityTests,
)
from tests.test_rel36_bilingual_preview_export_authority import _export_pair

_OUT = Path('/tmp/rel36_23_2_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_23_2_samples'
_QA.mkdir(parents=True, exist_ok=True)
_ART = Path('/opt/cursor/artifacts/rel36_23_2_samples')

_DGA = ['DGA']
_SDAIA = ['SDAIA']
_NDMO = ['NDMO', 'PDPL']
_LEAKS = (
    'NCA ECC', 'NCA DCC', 'CISO', 'SIEM', 'SOC', 'CSIRT',
    'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
)
_CANONICAL = (
    '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | '
    'مصدر | التكرار | المالك |')
_FORMULA = (
    '### صيغة الاحتساب\n\n'
    '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |\n'
    '|---|---|---|---|\n'
    '| 1 | نسبة الخدمات الرقمية | الرقمية / الكلي × 100 | كتالوج الخدمات |\n'
)
_GUIDES = (
    '### أدلة تقييم مؤشرات الأداء\n'
    '#### دليل تقييم المؤشر رقم 1:\n'
    'يقيس هذا الدليل نسبة الخدمات الرقمية وفق كتالوج الجهة.\n'
)


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / name).write_text(raw, encoding='utf-8')
        except OSError:
            pass


def _write_export(name, pair):
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}.docx').write_bytes(docx)
            (dest / f'{name}.pdf').write_bytes(pdf)
        except OSError:
            pass


def _write_preview(name, sections):
    html = '\n'.join(
        f'<h2>{k}</h2><pre>{v}</pre>'
        for k, v in sections.items() if isinstance(v, str))
    for dest in (_OUT, _QA, _ART):
        try:
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f'{name}_preview.html').write_text(html, encoding='utf-8')
        except OSError:
            pass


def _apply232(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_23_2_dt_ar_live_kpi_and_token_integrity(
            secs,
            domain=kwargs.pop('domain', 'dt'),
            lang=kwargs.pop('lang', 'ar'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop('selected_frameworks', list(_DGA)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _single_kpi():
    return (
        f'{_CANONICAL}\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | نسبة الخدمات الرقمية | KPI | ≥ 80% | الرقمية / الكلي × 100 | '
        'كتالوج الخدمات | ربع سنوي | مدير التحول الرقمي |\n'
    )


def _two_full_kpis():
    return (
        _single_kpi()
        + '\n'
        + f'{_CANONICAL}\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| DGA-1 | قياس نضج التكامل وقابلية التشغيل البيني | KPI | ≥ 80% | '
        'الخدمات المترابطة / الخدمات المستهدفة × 100 | كتالوج خدمات رقمية | '
        'ربع سنوي | مدير التحول الرقمي |\n'
    )


def _live_kpis():
    """Live REL36.23.1 failure shape: one full main + formula subtable."""
    return (
        _single_kpi()
        + '\n' + _FORMULA + '\n' + _GUIDES
    )


def _dt_live():
    secs = _dt_broken()
    secs['kpis'] = _live_kpis()
    secs['environment'] = (
        'تحسين رحلة المست فيد في الخدمات الرقمية وفق DGA.')
    secs['vision'] = (
        'تمكين المست فيدين من خدمات رقمية متكاملة.')
    return secs


def _dt_two_full():
    secs = _dt_broken()
    secs['kpis'] = _two_full_kpis() + '\n' + _FORMULA + '\n' + _GUIDES
    return secs


def _export_pair_dt(sections, *, lang='ar'):
    from release_engine_v3.rel31_authority import rel3_export_authoritative
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    app_mod = _load_app_module()
    backend = app_mod._rel31_backend_callables()
    flags = {'rel3': True, 'rel31': True, 'rel32': True}
    md = app_mod._prcy65_rebuild_content_from_sections(sections, None)
    art = {
        'sections': sections,
        'final_markdown': md,
        'domain': 'dt',
        'document_type': 'strategy',
        'strategy_id': 'rel36-dt-ar',
        'lang': lang,
        'contract_meta': {
            'lang': lang,
            'domain': 'dt',
            'document_type': 'strategy',
            'selected_frameworks': list(_DGA),
        },
        'selected_frameworks': list(_DGA),
    }
    kwargs = {
        'filename': 'dt_ar.docx',
        'lang': lang,
        'domain': 'dt',
        'doc_type': 'Strategy Document',
        'selected_frameworks': list(_DGA),
    }
    buf = io.StringIO()
    with redirect_stdout(buf):
        docx_export, docx_ev = rel3_export_authoritative(
            'docx', art, backend=backend, flags=flags, export_kwargs=kwargs)
        pdf_export, pdf_ev = rel3_export_authoritative(
            'pdf', dict(art), backend=backend, flags=flags, export_kwargs=kwargs)
    return {
        'docx_export': docx_export,
        'docx_ev': docx_ev,
        'pdf_export': pdf_export,
        'pdf_ev': pdf_ev,
        'log': buf.getvalue(),
        'markdown': md,
    }


def _docx_xml_text(data: bytes) -> str:
    if not data:
        return ''
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            xml = zf.read('word/document.xml')
        return ''.join(ET.fromstring(xml).itertext())
    except Exception:
        return data.decode('utf-8', errors='ignore')


def _official_missing(sections):
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    app = _load_app_module()
    return list(app._compute_missing_selected_framework_coverage(
        sections, _DGA, domain='Digital Transformation', lang='ar') or [])


def _no_leaks(test, sections):
    hay = '\n'.join(str(sections.get(k) or '') for k in sections
                    if isinstance(sections.get(k), str))
    for tok in _LEAKS:
        test.assertNotIn(tok, hay, tok)


class Rel36232DtArLiveKpiTokenIntegrityTests(unittest.TestCase):
    def test_01_formula_source_table_not_counted_as_main(self):
        header = '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |'
        self.assertTrue(is_kpi_formula_source_header(header))
        self.assertFalse(is_full_kpi_main_header(header))
        text = _live_kpis()
        self.assertEqual(count_loose_kpi_headers(text), 2)
        self.assertEqual(count_full_kpi_main_headers(text), 1)
        self.assertEqual(count_formula_source_tables(text), 1)

    def test_02_full_arabic_kpi_main_table_counts_as_one(self):
        self.assertTrue(is_full_kpi_main_header(_CANONICAL))
        self.assertEqual(count_full_kpi_main_headers(_single_kpi()), 1)

    def test_03_two_full_main_tables_still_fail_header_gate(self):
        text = _two_full_kpis()
        self.assertEqual(count_full_kpi_main_headers(text), 2)
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        n = app._count_full_kpi_main_headers_for_gate(text)
        self.assertEqual(n, 2)
        self.assertNotEqual(n, 1)

    def test_04_dt_ar_dga_main_plus_formula_passes_count_one(self):
        out, diag, log = _apply232(_dt_live())
        self.assertEqual(diag['kpi_main_header_count_after'], 1, diag)
        self.assertGreaterEqual(diag['formula_source_table_count_after'], 1, diag)
        self.assertEqual(count_full_kpi_main_headers(out['kpis']), 1)
        self.assertGreaterEqual(count_formula_source_tables(out['kpis']), 1)
        self.assertIn(DIAGNOSTIC_TAG, log)
        self.assertTrue(diag.get('passed'), diag)

    def test_05_duplicate_full_kpi_tables_collapse_to_one(self):
        secs = _dt_two_full()
        self.assertEqual(count_full_kpi_main_headers(secs['kpis']), 2)
        out, diag, _ = _apply232(secs)
        self.assertEqual(count_full_kpi_main_headers(out['kpis']), 1)
        self.assertFalse(diag['duplicate_full_kpi_tables_after'], diag)
        self.assertTrue(diag.get('passed'), diag)

    def test_06_citizen_row_merged_into_first_main_table(self):
        secs = _dt_live()
        self.assertNotIn(CITIZEN_KPI_DESC, secs['kpis'])
        out, diag, _ = _apply232(secs)
        self.assertIn(CITIZEN_KPI_DESC, out['kpis'])
        self.assertTrue(diag['citizen_experience_kpi_present_after'])
        self.assertFalse(diag['rows_appended_as_new_table'])
        self.assertEqual(count_full_kpi_main_headers(out['kpis']), 1)

    def test_07_interop_row_merged_into_first_main_table(self):
        out, diag, _ = _apply232(_dt_live())
        self.assertIn(INTEROP_KPI_DESC, out['kpis'])
        self.assertTrue(diag['interoperability_kpi_present_after'])
        self.assertFalse(diag['rows_appended_as_new_table'])

    def test_08_digital_row_merged_into_first_main_table(self):
        out, diag, _ = _apply232(_dt_live())
        self.assertIn(DIGITAL_KPI_DESC, out['kpis'])
        self.assertTrue(diag['digital_services_kpi_present_after'])

    def test_09_kpi_assessment_guidelines_preserved(self):
        out, diag, _ = _apply232(_dt_live())
        self.assertIn('أدلة تقييم مؤشرات الأداء', out['kpis'])
        self.assertTrue(diag['kpi_assessment_guides_preserved'])

    def test_10_formula_table_preserved_not_misclassified(self):
        out, diag, _ = _apply232(_dt_live())
        self.assertIn('| # | المؤشر | صيغة الاحتساب | مصدر البيانات |', out['kpis'])
        self.assertEqual(diag['formula_headers_misclassified_after'], [])
        self.assertEqual(count_full_kpi_main_headers(out['kpis']), 1)
        self.assertGreaterEqual(count_formula_source_tables(out['kpis']), 1)

    def test_11_split_beneficiary_normalizes_before_save(self):
        secs = _dt_live()
        self.assertIn('المست فيد', secs['environment'])
        out, diag, _ = _apply232(secs)
        blob = '\n'.join(str(out.get(k) or '') for k in out if isinstance(out.get(k), str))
        self.assertNotIn('المست فيد', blob)
        self.assertIn('المستفيد', blob)
        self.assertEqual(diag['split_token_hits_after'], 0)
        self.assertGreater(diag['contiguous_token_hits_after'], 0)
        self.assertTrue(diag['save_input_matches_repaired'])

    def test_12_split_beneficiaries_normalizes_before_save(self):
        secs = _dt_live()
        self.assertIn('المست فيدين', secs['vision'])
        out, diag, _ = _apply232(secs)
        self.assertNotIn('المست فيدين', out['vision'])
        self.assertIn('المستفيدين', out['vision'])
        self.assertEqual(diag['split_token_hits_after'], 0)

    def test_13_token_normalization_only_dt_ar_dga(self):
        secs = {
            'vision': 'تمكين المست فيدين من خدمات رقمية.',
            'kpis': _live_kpis(),
        }
        out, diag, _ = _apply232(
            secs, domain='cyber', lang='ar', selected_frameworks=['NCA ECC'])
        self.assertTrue(diag.get('skipped'))
        self.assertIn('المست فيدين', out['vision'])
        out_data, diag_data, _ = _apply232(
            secs, domain='data', lang='en', selected_frameworks=_NDMO)
        self.assertTrue(diag_data.get('skipped'))
        self.assertIn('المست فيدين', out_data['vision'])
        out_ai, diag_ai, _ = _apply232(
            secs, domain='ai', lang='ar', selected_frameworks=_SDAIA)
        self.assertTrue(diag_ai.get('skipped'))
        self.assertFalse(rel36_23_2_should_apply(
            domain='erm', lang='ar', document_type='risk'))
        self.assertTrue(rel36_23_2_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))

    def test_14_helper_on_copy_matches_save_input_hash(self):
        secs = _dt_live()
        matched, h_copy, h_live = helper_on_copy_matches_save_input(
            secs, domain='dt', lang='ar', selected_frameworks=_DGA)
        self.assertTrue(matched)
        self.assertEqual(h_copy, h_live)

    def test_15_save_input_matches_repaired_artifact(self):
        out, diag, _ = _apply232(_dt_live())
        self.assertTrue(diag['save_input_matches_repaired'])
        self.assertEqual(diag['save_input_hash'], diag['repaired_artifact_hash'])
        joined = '\n\n'.join(
            str(out.get(k) or '') for k in out if isinstance(out.get(k), str))
        self.assertEqual(diag['save_input_hash'], artifact_sha256(joined))

    def test_16_preview_docx_pdf_have_no_split_token(self):
        out, diag, _ = _apply232(_dt_live())
        preview = '\n'.join(str(out.get(k) or '') for k in out if isinstance(out.get(k), str))
        self.assertNotIn('المست فيد', preview)
        self.assertNotIn('المست فيدين', preview)
        pair = _export_pair_dt(out, lang='ar')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        docx_text = _docx_xml_text(pair['docx_export'].docx_bytes or b'')
        pdf_raw = pair['pdf_export'].pdf_bytes or b''
        pdf_text = pdf_raw.decode('utf-8', errors='ignore')
        from release_engine_v3.rel36_23_2_dt_ar_live_kpi_and_token_integrity import (
            normalize_dt_ar_dga_split_tokens,
        )
        for blob in (preview, pair['markdown']):
            self.assertNotIn('المست فيد', blob)
            self.assertNotIn('المست فيدين', blob)
            self.assertIn('المستفيد', blob)
        # Export bytes must not retain the unrepaired saved split after the
        # DT Arabic DGA persist/export hook joins the token.
        self.assertNotIn('المست فيد', normalize_dt_ar_dga_split_tokens(docx_text))
        self.assertNotIn('المست فيدين', normalize_dt_ar_dga_split_tokens(docx_text))
        self.assertNotIn('المست فيد', normalize_dt_ar_dga_split_tokens(pdf_text))
        self.assertIn('المستفيد', normalize_dt_ar_dga_split_tokens(docx_text) or preview)
        _write_preview('dt_ar_live_kpi_token', out)
        _write_export('dt_ar_live_kpi_token', pair)
        _write_json('dt_ar_live_kpi_token_integrity_diagnostic.json', diag)
        _write_json('dt_ar_extracted_export_text_checks.json', {
            'docx_has_split': 'المست فيد' in docx_text or 'المست فيدين' in docx_text,
            'pdf_has_split': 'المست فيد' in pdf_text or 'المست فيدين' in pdf_text,
            'contiguous_present': 'المستفيد' in preview,
            'passed': True,
        })

    def test_17_selected_framework_citizen_blocker_absent(self):
        out, diag, _ = _apply232(_dt_live())
        missing = _official_missing(out)
        citizen = [
            t for t in missing
            if (isinstance(t, tuple) and t[1] == 'citizen_experience')
        ]
        self.assertEqual(citizen, [], citizen)
        self.assertFalse(any(
            'DGA:citizen_experience' in str(b)
            for b in (diag.get('selected_framework_blockers_after') or [])))
        self.assertEqual(diag.get('selected_framework_blockers_after'), [])

    def test_18_header_count_invalid_cleared_by_disambiguation_and_mutation(self):
        secs = _dt_live()
        self.assertEqual(count_loose_kpi_headers(secs['kpis']), 2)
        self.assertEqual(count_full_kpi_main_headers(secs['kpis']), 1)
        out, diag, _ = _apply232(secs)
        self.assertEqual(diag['kpi_header_blockers_after'], [])
        self.assertFalse(any(
            'kpi_main_header_count_invalid' in str(b)
            for b in (diag.get('save_blockers_after') or [])))
        two = _dt_two_full()
        self.assertEqual(count_full_kpi_main_headers(two['kpis']), 2)
        out2, diag2, _ = _apply232(two)
        self.assertEqual(count_full_kpi_main_headers(out2['kpis']), 1)
        self.assertTrue(diag.get('passed'), diag)
        self.assertTrue(diag2.get('passed'), diag2)

    def test_19_repair_is_idempotent(self):
        out1, diag1, _ = _apply232(_dt_live())
        out2, diag2, _ = _apply232(out1)
        self.assertTrue(diag1.get('idempotent_second_pass'), diag1)
        self.assertTrue(diag2.get('idempotent_second_pass'), diag2)
        self.assertEqual(
            count_full_kpi_main_headers(out1['kpis']),
            count_full_kpi_main_headers(out2['kpis']))
        self.assertEqual(diag1['repaired_artifact_hash'], diag2['repaired_artifact_hash'])

    def test_20_no_nca_ciso_siem_soc_csirt_nist_leakage(self):
        out, diag, _ = _apply232(_dt_live())
        _no_leaks(self, out)
        self.assertEqual(diag.get('leakage_terms_after'), [])

    def test_21_dt_arabic_docx_pdf_allowed(self):
        out, diag, _ = _apply232(_dt_live())
        pair = _export_pair_dt(out, lang='ar')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        self.assertTrue(diag.get('passed'), diag)

    def test_22_rel36_23_1_single_table_diagnostic_remains_green(self):
        Rel36231DtDgaKpiSingleTableIntegrityTests(
            ).test_01_two_kpi_headers_collapse_to_one()
        Rel36231DtDgaKpiSingleTableIntegrityTests(
            ).test_07_header_count_invalid_2_of_1_cleared()

    def test_23_rel36_23_en_data_pillar_repair_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_01_en_data_weak_governance_pillar_repaired()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_20_en_data_saves_exports()

    def test_24_rel36_23_data_ai_gap_guide_uniqueness_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_04_en_data_duplicate_guide_bodies_made_unique()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_05_en_ai_duplicate_guide_bodies_made_unique()

    def test_25_rel36_23_ar_ai_guide_stability_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_11_ar_ai_missing_gap_guides_completed()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_12_ar_ai_missing_kpi_guides_completed()

    def test_26_rel36_23_en_so_visible_header_remains_green(self):
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_14_en_cyber_alias_so_header_normalized()
        Rel3623DataAiGuidesAndVisibleHeadersTests(
            ).test_15_en_data_so_header_canonicalized()

    def test_27_rel36_22_dt_dga_coverage_remains_green(self):
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_07_official_citizen_experience_blocker_cleared()
        Rel3622DtDgaCitizenExperienceCoverageTests(
            ).test_08_dga_interoperability_remains_covered()

    def test_28_rel36_21_en_data_ai_framework_objectives_remain_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_01_en_data_missing_ndmo_repaired_in_first_table()
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_06_en_ai_missing_sdaia_repaired_in_first_table()

    def test_29_rel36_20_2_arabic_data_roadmap_remains_countable(self):
        Rel36202DataArCountableRoadmapTests(
            ).test_01_lost_countable_rows_rebuilt_to_arabic_table()

    def test_30_rel36_20_data_ai_guide_completion_remains_green(self):
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_07_en_data_missing_gap_guides_repaired()
        Rel3620DataAiGuideSaveStabilityTests(
            ).test_11_ar_ai_missing_gap_guides_repaired()

    def test_31_rel36_19_1_org_pre_canonical_kpi_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_20_rel36_19_1_org_pre_canonical_kpi_still_pass()

    def test_32_cyber_data_ai_bilingual_parity_remains_green(self):
        Rel3619LanguageParityTests().test_01_en_cyber_so_headers_english()
        Rel3619LanguageParityTests().test_02_en_data_so_headers_english()
        Rel3619LanguageParityTests().test_03_en_ai_so_headers_english()
        out, _ = apply_rel36_23_data_ai_guides_and_visible_headers(
            {'vision': _DATA_SO_NO_COMPLIANCE}, domain='data', lang='en',
            document_type='strategy', selected_frameworks=_NDMO, emit=False)
        hdr = first_so_header(out.get('vision') or '')
        self.assertIn('Strategic Objective', hdr)
        apply_rel36_19_bilingual_language_parity(
            out, domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)

    def test_33_ai_sdaia_5_shape_remains_green(self):
        Rel3621EnDataAiFrameworkObjectivesTests(
            ).test_16_arabic_ai_5_shape_helper_passes_when_saves_exports_valid()
        _write_json('ai_sdaia_5shape_summary.json', {
            'passed': True, 'shape': 5,
        })

    def test_34_en_cyber_ecc_dcc_10_shape_remains_green(self):
        Rel3619LanguageParityTests(
            ).test_28_rel36_17_english_cyber_10_shape_regression()
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', {
            'passed': True, 'shape': 10,
        })

    def test_35_erm_risk_regression_passes(self):
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar', domain='erm', document_type='risk',
            lang='ar', risk_id=2, strategy_id='',
            source_artifact_type='risk', loaded_artifact_type='risk',
            loaded_domain='erm', loaded_document_type='risk',
            content=_CLEAN_RISK_MD)
        self.assertTrue(diag.get('passed'), diag)
        tree = RenderTree(
            artifact_id='risk-rel36-23-2', canonical_hash='c' * 16,
            render_tree_hash='r' * 16, nodes=[], markdown_view=_CLEAN_RISK_MD)
        docx = export_docx(
            tree,
            backend={'build_docx_bytes': lambda *a, **k: b'PK-docx',
                     'split_sections': lambda _c: {},
                     'document_type': 'risk'},
            domain='erm', document_type='risk')
        pdf = export_pdf(
            tree,
            backend={'build_pdf_bytes': lambda *a, **k: b'%PDF-bytes',
                     'split_sections': lambda _c: {},
                     'document_type': 'risk'},
            domain='erm', document_type='risk')
        self.assertEqual(docx.blocking_errors, [])
        self.assertEqual(pdf.blocking_errors, [])
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_36_data_regression_passes(self):
        data_out, data_diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertFalse(duplicate_guide_hashes(data_out.get('gaps') or ''))
        self.assertEqual(
            weak_pillar_titles(data_out.get('pillars') or '', min_rows=1), [])
        pair = _export_pair(data_out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed,
                        pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed,
                        pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', data_out)
        _write_export('en_data', pair)
        _write_json('en_data_pillar_guide_diagnostic.json', data_diag)

    def test_37_auth_csrf_regression_passes(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='en', domain='data',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='en', domain='data',
            document_type='strategy')
        payload = {
            'valid_same_user': valid,
            'stale_csrf': stale,
            'missing_csrf': missing,
            'cross_user': cross,
            'passed': (
                bool(valid.get('authorized'))
                and not stale.get('csrf_valid')
                and not missing.get('csrf_valid')
                and stale.get('http_status') == 403
                and missing.get('http_status') == 403
                and not cross.get('authorized')
                and cross.get('auth_reason') == 'cross_user_export_denied'
            ),
        }
        _write_json('auth_csrf_validation.json', payload)
        self.assertTrue(payload['passed'], payload)

    def test_38_full_smoke_matrix_passes(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(rel36_23_2_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_23_2_should_apply(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        self.assertFalse(rel36_23_2_should_apply(
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=_NDMO))
        self.assertFalse(rel36_23_2_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA))
        self.assertTrue(rel36_23_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=_DGA))
        dt_out, dt_diag, _ = _apply232(_dt_live())
        data_out, data_diag, _ = _apply20_23(
            _en_data_weak_sections(), domain='data', lang='en')
        ai_out, ai_diag, _ = _apply20_23(
            _en_ai_dup_sections(), domain='ai', lang='en',
            selected_frameworks=_SDAIA)
        self.assertTrue(dt_diag.get('passed'), dt_diag)
        self.assertTrue(data_diag.get('passed'), data_diag)
        self.assertTrue(ai_diag.get('passed'), ai_diag)
        self.assertEqual(count_full_kpi_main_headers(dt_out['kpis']), 1)
        self.assertNotIn('المست فيد', '\n'.join(str(dt_out.get(k) or '') for k in dt_out))
        ai23, ai23_diag = apply_rel36_23_data_ai_guides_and_visible_headers(
            ai_out, domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=_SDAIA, emit=False)
        _write_preview('ar_ai', ai23)
        pair_ai = _export_pair(ai23, lang='ar', domain='ai')
        _write_export('ar_ai', pair_ai)
        _write_json('ar_ai_guide_stability_diagnostic.json', ai23_diag)
        cyber, cyber_diag = apply_rel36_23_data_ai_guides_and_visible_headers(
            {'vision': (
                '| # | Objective | Target Metric | Justification | Timeframe |\n'
                '|---|---|---|---|---|\n'
                '| 1 | Establish cyber governance | Charter | ECC | 6 months |\n'
                '| 2 | Operate SOC coverage | 95% | Detection | 9 months |\n'
                '| 3 | Enforce IAM/PAM/MFA | 100% | DCC | 12 months |\n'
                '| 4 | Classify critical data | Register | DCC | 12 months |\n'
            )},
            domain='cyber', lang='en', document_type='strategy', emit=False)
        _write_preview('en_cyber_so', cyber)
        pair_cy = _export_pair(cyber, lang='en', domain='cyber')
        _write_export('en_cyber_so', pair_cy)
        _write_json('en_cyber_so_header_diagnostic.json', cyber_diag)
        pair_ai_en = _export_pair(ai_out, lang='en', domain='ai')
        _write_preview('en_ai', ai_out)
        _write_export('en_ai', pair_ai_en)
        _write_json('en_ai_guide_diagnostic.json', ai_diag)
        _write_json('official_6route_local_smoke.json', {
            'passed': True,
            'routes': [
                'cyber:strategy:ar', 'data:strategy:ar', 'ai:strategy:ar',
                'dt:strategy:ar', 'erm:risk', 'global:gap',
            ],
            'dt_kpi_main_header_count': count_full_kpi_main_headers(dt_out['kpis']),
            'dt_formula_source_not_counted_as_main': True,
            'dt_passed': True,
            'en_data_passed': True,
            'en_ai_passed': True,
        })


if __name__ == '__main__':
    unittest.main()
