"""REL37 deterministic Data / AI / DT strategy compilers."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = tempfile.mkdtemp(prefix='test_rel37_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')
os.environ.setdefault('REL37_DATA_AI_DT_COMPILER', '1')

from release_engine_v3.rel37_apply import (  # noqa: E402
    is_rel37_authoritative,
    rel37_should_apply,
)
from release_engine_v3.rel37_canonical_document import (  # noqa: E402
    CanonicalDocument,
    KpiFormulaRow,
    KpiRow,
)
from release_engine_v3.rel37_compilers import compile_for_domain  # noqa: E402
from release_engine_v3.rel37_render import (  # noqa: E402
    evidence_from_model,
    render,
)
from release_engine_v3.rel37_schema_registry import (  # noqa: E402
    header_line,
)
from release_engine_v3.rel37_validate import validate_model  # noqa: E402

SAMPLE_DIRS = (
    Path('/tmp/rel37_samples'),
    ROOT / 'qa_outputs' / 'rel37_samples',
    Path('/opt/cursor/artifacts/rel37_samples'),
)


def _request(domain: str, lang: str, org_name: str = '', frameworks=None):
    payload = {
        'domain': domain,
        'lang': lang,
        'document_type': 'strategy',
        'org_name': org_name,
    }
    if frameworks is not None:
        payload['selected_frameworks'] = list(frameworks)
    return payload


def _compile(domain: str, lang: str, org_name: str = '', frameworks=None):
    return compile_for_domain(domain, _request(domain, lang, org_name, frameworks))


def _write_samples(domain: str, lang: str, model: CanonicalDocument) -> None:
    md = render(model, 'md')
    docx = render(model, 'docx')
    pdf = render(model, 'pdf')
    stem = f'{domain}_{lang}'
    for folder in SAMPLE_DIRS:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f'{stem}.md').write_text(md.markdown, encoding='utf-8')
            (folder / f'{stem}.json').write_text(
                json.dumps(model.to_dict(), ensure_ascii=False, indent=2),
                encoding='utf-8')
            (folder / f'{stem}.docx').write_bytes(docx.body)
            (folder / f'{stem}.pdf').write_bytes(pdf.body)
        except Exception:
            continue


class Rel37DeterministicCompilerTests(unittest.TestCase):
    def test_01_data_ar_valid_model(self):
        model = _compile('data', 'ar', org_name='شركة البيانات')
        self.assertEqual(validate_model(model), [])
        self.assertTrue(model.validation_passed)
        self.assertEqual(header_line('so', 'ar'),
                         '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |')
        self.assertIn('NDMO', model.required_families)
        self.assertIn('PDPL', model.required_families)
        _write_samples('data', 'ar', model)

    def test_02_data_en_valid_model(self):
        model = _compile('data', 'en', org_name='Data Example Org')
        self.assertEqual(validate_model(model), [])
        self.assertEqual(header_line('so', 'en'),
                         '| # | Strategic Objective | Measurable Target | Rationale | Timeframe |')
        self.assertNotRegex(model.generated_text_blob(), r'[\u0600-\u06FF]')
        _write_samples('data', 'en', model)

    def test_03_ai_ar_valid_model(self):
        model = _compile('ai', 'ar', org_name='جهة الذكاء الاصطناعي')
        self.assertEqual(validate_model(model), [])
        self.assertIn('SDAIA', model.required_families)
        _write_samples('ai', 'ar', model)

    def test_04_ai_en_valid_model(self):
        model = _compile('ai', 'en', org_name='AI Example Org')
        self.assertEqual(validate_model(model), [])
        self.assertNotRegex(model.generated_text_blob(), r'[\u0600-\u06FF]')
        _write_samples('ai', 'en', model)

    def test_05_dt_ar_valid_model(self):
        model = _compile('dt', 'ar', org_name='جهة التحول')
        self.assertEqual(validate_model(model), [])
        blob = model.generated_text_blob()
        self.assertIn('المستفيد', blob)
        self.assertNotRegex(blob, r'المست\s+فيد')
        self.assertIn('digital_services', model.required_families)
        self.assertIn('interoperability', model.required_families)
        self.assertIn('citizen_experience', model.required_families)
        _write_samples('dt', 'ar', model)

    def test_06_dt_en_valid_model(self):
        model = _compile('dt', 'en', org_name='DT Example Org')
        self.assertEqual(validate_model(model), [])
        self.assertNotRegex(model.generated_text_blob(), r'[\u0600-\u06FF]')
        _write_samples('dt', 'en', model)

    def _assert_same_model_renders(self, domain: str, lang: str, org_name: str):
        model = _compile(domain, lang, org_name=org_name)
        preview = render(model, 'preview')
        docx = render(model, 'docx')
        pdf = render(model, 'pdf')
        self.assertEqual(preview.evidence.model_hash, model.model_hash)
        self.assertEqual(docx.evidence.model_hash, model.model_hash)
        self.assertEqual(pdf.evidence.model_hash, model.model_hash)
        self.assertEqual(preview.evidence.to_dict(), docx.evidence.to_dict())
        self.assertEqual(docx.evidence.to_dict(), pdf.evidence.to_dict())
        self.assertTrue(isinstance(docx.body, (bytes, bytearray)) and docx.body)
        self.assertTrue(isinstance(pdf.body, (bytes, bytearray)) and pdf.body)
        self.assertIn(header_line('kpi_main', lang), preview.markdown)
        if org_name:
            self.assertIn(org_name, preview.markdown)

    def test_07_data_ar_preview_docx_pdf(self):
        self._assert_same_model_renders('data', 'ar', 'شركة البيانات')

    def test_08_data_en_preview_docx_pdf(self):
        self._assert_same_model_renders('data', 'en', 'Data Example Org')

    def test_09_ai_ar_preview_docx_pdf(self):
        self._assert_same_model_renders('ai', 'ar', 'جهة الذكاء الاصطناعي')

    def test_10_ai_en_preview_docx_pdf(self):
        self._assert_same_model_renders('ai', 'en', 'AI Example Org')

    def test_11_dt_ar_preview_docx_pdf(self):
        self._assert_same_model_renders('dt', 'ar', 'جهة التحول')

    def test_12_dt_en_preview_docx_pdf(self):
        self._assert_same_model_renders('dt', 'en', 'DT Example Org')

    def test_13_kpi_main_vs_formula_source_types(self):
        model = _compile('data', 'en')
        self.assertTrue(model.kpis)
        self.assertTrue(model.kpi_formula_source)
        self.assertIsInstance(model.kpis[0], KpiRow)
        self.assertIsInstance(model.kpi_formula_source[0], KpiFormulaRow)
        self.assertEqual(header_line('kpi_main', 'en'),
                         '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |')
        self.assertEqual(header_line('kpi_formula', 'en'),
                         '| # | KPI | Calculation Formula | Data Source |')
        self.assertEqual(header_line('kpi_main', 'ar'),
                         '| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | المصدر | التكرار | المالك |')
        self.assertEqual(header_line('kpi_formula', 'ar'),
                         '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |')
        ev = evidence_from_model(model)
        self.assertEqual(ev.kpi_row_count, len(model.kpis))
        self.assertNotEqual(ev.kpi_main_header, ev.formula_header)

    def test_14_kpi_guides_one_to_one(self):
        for domain, lang in (('data', 'ar'), ('ai', 'en'), ('dt', 'ar')):
            model = _compile(domain, lang)
            self.assertEqual(len(model.kpi_guides), len(model.kpis))
            self.assertEqual(
                [g.number for g in model.kpi_guides],
                [k.number for k in model.kpis])

    def test_15_gap_guides_one_to_one(self):
        for domain, lang in (('data', 'en'), ('ai', 'ar'), ('dt', 'en')):
            model = _compile(domain, lang)
            self.assertEqual(len(model.gap_guides), len(model.gaps))
            self.assertEqual(
                [g.number for g in model.gap_guides],
                [k.number for k in model.gaps])

    def test_16_data_roadmap_families_complete_non_restarted(self):
        model = _compile('data', 'ar', frameworks=['NDMO', 'PDPL'])
        families = [row.family for row in model.roadmap]
        self.assertEqual(len(families), len(set(families)))
        for required in model.required_families:
            self.assertIn(required, families)
        seen = []
        for fam in families:
            self.assertNotIn(fam, seen)
            seen.append(fam)

    def test_17_ai_sdaia_coverage_complete(self):
        model = _compile('ai', 'en', frameworks=['SDAIA'])
        self.assertEqual(model.missing_families(), ())
        self.assertTrue(any(row.family == 'sdaia_compliance' for row in model.strategic_objectives))
        self.assertIn('SDAIA', model.required_families)

    def test_18_dt_dga_family_coverage(self):
        model = _compile('dt', 'ar', frameworks=['DGA'])
        have = {row.family for row in model.kpis}
        for fam in ('DGA', 'digital_services', 'interoperability', 'citizen_experience'):
            self.assertIn(fam, have)
            self.assertIn(fam, {row.family for row in model.roadmap})

    def test_19_language_parity(self):
        ar = render(_compile('data', 'ar'), 'md')
        en = render(_compile('data', 'en'), 'md')
        self.assertIn(header_line('so', 'ar'), ar.markdown)
        self.assertIn(header_line('so', 'en'), en.markdown)
        self.assertIn(header_line('roadmap', 'ar'), ar.markdown)
        self.assertIn(header_line('roadmap', 'en'), en.markdown)
        self.assertNotRegex(en.markdown, r'[\u0600-\u06FF]')
        self.assertIn('الهدف الاستراتيجي', ar.markdown)

    def test_20_arabic_org_name_preserved_in_english(self):
        org = 'شركة مثال'
        model = _compile('data', 'en', org_name=org)
        self.assertEqual(model.org_name, org)
        for target in ('md', 'preview', 'docx', 'pdf', 'txt', 'print'):
            out = render(model, target)
            self.assertEqual(out.evidence.org_name, org)
            if target in ('md', 'preview', 'txt', 'print'):
                self.assertIn(org, out.markdown)
            self.assertEqual(out.evidence.source_hash, model.model_hash)

    def test_21_no_cross_domain_leakage(self):
        deny = {
            'data': ('NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT', 'NIST'),
            'ai': ('NCA', 'CISO', 'SIEM', 'SOC', 'IAM', 'PAM', 'MFA', 'CSIRT', 'NIST'),
            'dt': ('NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT', 'NIST'),
        }
        for domain, lang in (
                ('data', 'ar'), ('data', 'en'),
                ('ai', 'ar'), ('ai', 'en'),
                ('dt', 'ar'), ('dt', 'en')):
            model = _compile(domain, lang)
            blob = model.generated_text_blob()
            for term in deny[domain]:
                self.assertNotRegex(
                    blob, r'(?<![A-Za-z])' + term + r'(?![A-Za-z])',
                    msg=f'{domain}:{lang} leaked {term}')

    def test_22_model_hash_equals_render_source_hash(self):
        model = _compile('ai', 'en', org_name='Hash Org')
        for target in ('md', 'preview', 'docx', 'pdf'):
            out = render(model, target)
            self.assertEqual(out.evidence.model_hash, model.model_hash)
            self.assertEqual(out.evidence.source_hash, model.model_hash)

    def test_23_cyber_not_captured_by_rel37(self):
        self.assertFalse(rel37_should_apply(
            domain='cyber', lang='ar', document_type='strategy'))
        self.assertFalse(rel37_should_apply(
            domain='data', lang='ar', document_type='risk'))
        from release_engine_v3.rel32_compiler import compile_canonical_strategy_document
        compiled = compile_canonical_strategy_document(
            {'vision': 'x'},
            request_context={
                'domain': 'cyber', 'lang': 'ar', 'document_type': 'strategy',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            },
        )
        self.assertFalse(is_rel37_authoritative(compiled.legacy_sections or {}))

    def test_24_auth_csrf_surface_still_present(self):
        text = (ROOT / 'tests' / 'test_rel36_11_english_cyber_export_stability.py').read_text(
            encoding='utf-8')
        self.assertIn('csrf_invalid', text)
        self.assertIn('cross_user_export_denied', text)

    def test_25_smoke_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue((ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
