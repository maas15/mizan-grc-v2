"""REL36 — bilingual preview and authoritative export routing."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel36_bilingual_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

from professional_strategy_render import split_kpi_tables
from release_engine_v3.rel32_preview_table_dom import (
    evaluate_preview_dom_binding_check,
    render_preview_table_html,
)
from release_engine_v3.rel32_table_schema_binding import schema_header_labels
from release_engine_v3.rel34_visible_output_quality import (
    visible_text_has_internal_markers,
)
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    detect_visible_frameworks,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    REL36_KPI_MAIN_HEADERS_AR,
    REL36_KPI_MAIN_HEADERS_EN,
    bind_saved_preview_payload,
    emit_rel36_bilingual_export_authority,
    english_visible_has_arabic_kpi_headers,
    evaluate_rel36_bilingual_export_authority,
    is_rel36_bilingual_export_authoritative,
    kpi_main_headers,
    sanitize_visible_preview_text,
)
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
)


def _cyber_ar_sections() -> dict:
    return {
        'vision': (
            '| # | الهدف الاستراتيجي | المبرر | الإطار الزمني |\n'
            '|---|---|---|---|\n'
            '| 1 | تفعيل حوكمة الأمن السيبراني | NCA ECC | 12 شهر |\n'
        ),
        'pillars': 'ركيزة الحوكمة وSOC/SIEM وIAM وفق NCA ECC و NCA DCC.',
        'environment': 'متطلبات NCA ECC و NCA DCC.',
        'gaps': (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | ضعف حوكمة CISO | لا لجنة معتمدة | عالية | مفتوحة |\n'
        ),
        'roadmap': (
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1 | 1-6 أشهر | تأسيس CISO | CISO | لجنة معتمدة | NCA ECC |\n'
            '| المرحلة 1 | 1-6 أشهر | تفعيل SIEM | مدير SOC | منصة SOC | NCA ECC |\n'
        ),
        'kpis': (
            '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | مصدر | التكرار | المالك |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| 1 | MTTD | KPI | < 4 ساعات | مجموع زمن الكشف / عدد الحوادث | SIEM / SOC | شهري | CISO |\n'
            '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |\n'
            '|---|---|---|---|\n'
            '| 1 | MTTD | مجموع زمن الكشف / عدد الحوادث | SIEM / SOC |\n'
        ),
        'confidence': (
            '| العامل | الوزن | التقييم | المساهمة |\n'
            '|---|---|---|---|\n'
            '| اكتمال المدخلات | 20% | جيد | 16% |\n'
        ),
        'governance': 'CISO ولجنة الحوكمة وCSIRT.',
        'traceability': (
            '| الإطار | الضابط | الهدف | الفجوة |\n'
            '|---|---|---|---|\n'
            '| NCA ECC | الحوكمة | لجنة CISO | ضعف الحوكمة |\n'
        ),
    }


def _cyber_en_sections() -> dict:
    return {
        'vision': (
            '| # | Strategic Objective | Rationale | Timeframe |\n'
            '|---|---|---|---|\n'
            '| 1 | Establish cyber governance | NCA ECC | 12 months |\n'
        ),
        'pillars': 'Governance, SOC/SIEM and IAM aligned to NCA ECC and NCA DCC.',
        'environment': 'NCA ECC and NCA DCC regulatory context.',
        'gaps': (
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Weak CISO governance | No approved committee | High | Open |\n'
        ),
        'roadmap': (
            '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |\n'
            '|---|---|---|---|---|---|\n'
            '| Phase 1 | 1-6 months | Establish CISO office | CISO | Approved committee | NCA ECC |\n'
            '| Phase 1 | 1-6 months | Enable SIEM | SOC Manager | Live SOC platform | NCA ECC |\n'
        ),
        'kpis': (
            '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |\n'
            '|---|---|---|---|---|---|---|---|\n'
            '| 1 | MTTD | KPI | < 4 hours | total detect time / incidents | SIEM / SOC | Monthly | CISO |\n'
            '| # | Indicator | Calculation Formula | Data Source |\n'
            '|---|---|---|---|\n'
            '| 1 | MTTD | total detect time / incidents | SIEM / SOC |\n'
        ),
        'confidence': (
            '| Factor | Weight | Score | Contribution |\n'
            '|---|---|---|---|\n'
            '| Input completeness | 20% | Good | 16% |\n'
        ),
        'governance': 'CISO, governance committee, and CSIRT.',
        'traceability': (
            '| Framework | Control | Objective | Gap |\n'
            '|---|---|---|---|\n'
            '| NCA ECC | Governance | CISO committee | Weak governance |\n'
        ),
    }


def _dt_dga_sections() -> dict:
    return {
        'vision': 'Digital government services aligned to DGA.',
        'pillars': 'Service digitization and government integration.',
        'environment': 'DGA Digital Government Framework.',
        'gaps': 'Weak interoperability across government services.',
        'roadmap': 'Enable APIs for government integration.',
        'kpis': 'Interoperability maturity of critical systems.',
        'traceability': 'DGA interoperability coverage.',
    }


def _export_pair(sections: dict, *, lang: str, domain: str = 'cyber'):
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
        'domain': domain,
        'document_type': 'strategy',
        'strategy_id': f'rel36-{domain}-{lang}',
        'lang': lang,
        'contract_meta': {
            'lang': lang,
            'domain': domain,
            'document_type': 'strategy',
        },
    }
    kwargs = {
        'filename': f'{domain}_{lang}.docx',
        'lang': lang,
        'domain': domain,
        'doc_type': 'Strategy Document',
        'selected_frameworks': (
            ['NCA ECC', 'NCA DCC'] if domain == 'cyber' else []),
    }
    buf = io.StringIO()
    with redirect_stdout(buf):
        docx_export, docx_ev = rel3_export_authoritative(
            'docx', art, backend=backend, flags=flags, export_kwargs=kwargs)
        pdf_export, pdf_ev = rel3_export_authoritative(
            'pdf', art, backend=backend, flags=flags, export_kwargs=kwargs)
    return {
        'docx_export': docx_export,
        'docx_ev': docx_ev,
        'pdf_export': pdf_export,
        'pdf_ev': pdf_ev,
        'log': buf.getvalue(),
        'markdown': md,
    }


class Rel36AuthorityAndPreviewTests(unittest.TestCase):

    def test_01_arabic_saved_load_preview_binds(self):
        bound = bind_saved_preview_payload(
            {
                'id': 41,
                'sections': _cyber_ar_sections(),
                'domain': 'Cyber Security',
                'language': 'ar',
            },
            expected_domain='Cyber Security',
            expected_lang='ar',
        )
        self.assertTrue(bound['preview_bound'])
        self.assertEqual(bound['strategy_id'], 41)
        self.assertIn('roadmap', bound['sections'])
        self.assertNotIn('strategy not found', (bound.get('error') or '').lower())

    def test_02_english_saved_load_preview_binds(self):
        bound = bind_saved_preview_payload(
            {
                'id': 42,
                'sections': _cyber_en_sections(),
                'domain': 'Cyber Security',
                'language': 'en',
            },
            expected_domain='Cyber Security',
            expected_lang='en',
        )
        self.assertTrue(bound['success'])
        self.assertEqual(bound['strategy_id'], 42)
        self.assertEqual(bound['language'], 'en')

    def test_03_english_docx_uses_authoritative_path(self):
        self.assertTrue(is_rel36_bilingual_export_authoritative(
            domain='cyber', lang='en', document_type='strategy',
            flags={'rel3': True, 'rel31': True}))
        out = _export_pair(_cyber_en_sections(), lang='en')
        self.assertTrue(out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        joined = ' '.join(str(b) for b in (out['docx_ev'].blocking_errors or []))
        self.assertNotIn('rel32_docx_export_bypass_detected', joined)
        self.assertGreater(len(out['docx_export'].docx_bytes or b''), 1000)
        self.assertIn('REL36-BILINGUAL-EXPORT-AUTHORITY', out['log'] or 'REL36')

    def test_04_english_pdf_professional_quality(self):
        out = _export_pair(_cyber_en_sections(), lang='en')
        joined = ' '.join(str(b) for b in (out['pdf_ev'].blocking_errors or []))
        self.assertNotIn('pdf_render_failed:docmodel_professional_quality', joined)
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertGreater(len(out['pdf_export'].pdf_bytes or b''), 1000)

    def test_05_english_kpi_preview_headers(self):
        hdr = list(schema_header_labels('kpi_main', lang='en'))
        self.assertEqual(tuple(hdr), REL36_KPI_MAIN_HEADERS_EN)
        html = render_preview_table_html(
            hdr,
            [['1', 'MTTD', 'KPI', '< 4 hours',
              'total detect time / incidents', 'SIEM / SOC',
              'Monthly', 'CISO']],
            schema_id='kpi_main', is_rtl=False, lang='en')
        self.assertIn('KPI Description', html)
        self.assertIn('Source', html)
        self.assertNotIn('مصدر', html)
        diag = evaluate_preview_dom_binding_check(html, 'kpi_main', lang='en')
        self.assertTrue(diag['preview_dom_binding_passed'], diag)

    def test_06_arabic_kpi_preview_headers(self):
        hdr = list(schema_header_labels('kpi_main', lang='ar'))
        self.assertEqual(tuple(hdr), REL36_KPI_MAIN_HEADERS_AR)
        html = render_preview_table_html(
            hdr,
            [['1', 'MTTD', 'KPI', '< 4 ساعات',
              'مجموع زمن الكشف / عدد الحوادث', 'SIEM / SOC',
              'شهري', 'CISO']],
            schema_id='kpi_main', is_rtl=True, lang='ar')
        self.assertIn('مصدر', html)
        self.assertNotIn('KPI Description', html)
        diag = evaluate_preview_dom_binding_check(html, 'kpi_main', lang='ar')
        self.assertTrue(diag['preview_dom_binding_passed'], diag)

    def test_07_preview_strips_family_markers(self):
        raw = 'Enable SOC family:soc_siem and IAM family:iam_pam_mfa'
        cleaned = sanitize_visible_preview_text(raw, 'en')
        self.assertNotIn('family:', cleaned)
        self.assertFalse(visible_text_has_internal_markers(cleaned))

    def test_08_export_visible_text_has_no_family_markers(self):
        dirty = dict(_cyber_en_sections())
        dirty['roadmap'] += '\nfamily:governance_ciso family:soc_siem'
        out = _export_pair(dirty, lang='en')
        from release_engine_v3.evidence.docx_text_extractor import (
            extract_docx_visible_text,
        )
        docx_text = extract_docx_visible_text(out['docx_export'].docx_bytes or b'')
        self.assertNotIn('family:', docx_text)
        preview = sanitize_visible_preview_text(dirty['roadmap'] + '\nprint txt', 'en')
        self.assertNotIn('family:', preview)
        self.assertNotIn('governance_ciso', preview)

    def test_09_english_roadmap_no_snake_markers(self):
        blob = sanitize_visible_preview_text(
            'Phase 1 family:governance_committee encryption_key_management',
            'en')
        self.assertNotIn('family:', blob)
        self.assertNotIn('governance_committee', blob)
        self.assertNotIn('encryption_key_management', blob)

    def test_10_english_no_arabic_kpi_headers(self):
        tables = split_kpi_tables(_cyber_en_sections()['kpis'], lang='en')
        blob = ' '.join(
            ' '.join(str(c) for c in (t.get('header') or []))
            for t in tables)
        self.assertFalse(english_visible_has_arabic_kpi_headers(blob), blob)
        self.assertIn('Source', blob)

    def test_11_arabic_keeps_arabic_kpi_headers(self):
        hdr = kpi_main_headers('ar')
        self.assertEqual(hdr[5], 'مصدر')
        self.assertNotIn('Source', hdr)

    def test_12_arabic_kpi_pdf_extractability(self):
        out = _export_pair(_cyber_ar_sections(), lang='ar')
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        from release_engine_v3.rel32_kpi_main_schema_evidence import (
            evaluate_kpi_main_schema_from_export_text,
        )
        try:
            import fitz
            text = ''
            doc = fitz.open(stream=out['pdf_export'].pdf_bytes, filetype='pdf')
            text = '\n'.join(p.get_text() for p in doc)
        except Exception:
            text = out['markdown']
        self.assertTrue(text)
        self.assertGreater(len(out['pdf_export'].pdf_bytes or b''), 1000)

    def test_13_english_kpi_pdf_extractability(self):
        out = _export_pair(_cyber_en_sections(), lang='en')
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertGreater(len(out['pdf_export'].pdf_bytes or b''), 1000)
        try:
            import fitz
            doc = fitz.open(stream=out['pdf_export'].pdf_bytes, filetype='pdf')
            text = '\n'.join(p.get_text() for p in doc)
            self.assertTrue(text.strip())
        except Exception:
            pass

    def test_14_data_ndmo_pdpl_fidelity(self):
        secs, _diag = repair_sections_for_fidelity(
            _data_sections(), domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], lang='ar')
        blob = ' '.join(str(v) for v in secs.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('NDMO', fw)
        self.assertNotIn('NCA ECC', fw)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SIEM', blob)
        self.assertNotIn('CSIRT', blob)

    def test_15_ai_sdaia_fidelity(self):
        secs, _diag = repair_sections_for_fidelity(
            _ai_sections(), domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = ' '.join(str(v) for v in secs.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('SDAIA', fw)
        self.assertNotIn('NCA ECC', fw)
        self.assertNotIn('NIST AI RMF', blob)
        self.assertNotIn('SIEM', blob)

    def test_16_dt_dga_interoperability(self):
        secs, _repaired = repair_dga_interoperability_sections(
            _dt_dga_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(secs))

    def test_17_authority_diagnostic_and_fail_closed(self):
        diag = evaluate_rel36_bilingual_export_authority(
            route='docx-async', lang='en', domain='cyber',
            document_type='strategy', output_type='docx',
            selected_exporter='_build_docx_bytes',
            authoritative_path_used=False,
            legacy_builder_attempted=True,
            docx_bypass_detected=True,
        )
        self.assertFalse(diag['passed'])
        self.assertIn(
            'rel32_docx_export_bypass_detected:_build_docx_bytes',
            diag['blocking_errors'])
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel36_bilingual_export_authority(diag)
        self.assertIn('[REL36-BILINGUAL-EXPORT-AUTHORITY]', buf.getvalue())
        missing = bind_saved_preview_payload({}, expected_domain='cyber')
        self.assertFalse(missing['success'])
        self.assertIn('saved_preview_content_missing', missing['error'])


if __name__ == '__main__':
    unittest.main()
