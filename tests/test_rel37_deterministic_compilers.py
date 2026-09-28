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
    apply_rel37_to_sections,
    is_rel37_authoritative,
    rel37_should_apply,
)
from release_engine_v3.rel37_canonical_document import (  # noqa: E402
    HASH_EXCLUDED_FIELDS,
    CanonicalDocument,
    KpiFormulaRow,
    KpiRow,
)
from release_engine_v3.rel37_selection import (  # noqa: E402
    last_selection_diagnostic,
    rel37_supported_selection,
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


class Rel37HashAuthorityTests(unittest.TestCase):
    def test_26_model_hash_stable_across_recompute(self):
        model = _compile('data', 'en', org_name='Hash Org')
        first = model.model_hash
        second = model.compute_hashes().model_hash
        third = model.compute_model_hash()
        self.assertEqual(first, second)
        self.assertEqual(first, third)
        self.assertTrue(first)

    def test_27_hash_payload_excludes_derived_fields(self):
        model = _compile('ai', 'ar')
        payload = model.canonical_hash_payload()
        for field in HASH_EXCLUDED_FIELDS:
            self.assertNotIn(field, payload)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn('"model_hash"', blob)
        self.assertNotIn(model.model_hash, blob)

    def test_28_manual_model_hash_does_not_feed_back(self):
        model = _compile('dt', 'en')
        original = model.model_hash
        model.model_hash = 'deadbeef' * 8
        model.runtime_diagnostics['tampered'] = True
        recomputed = model.compute_hashes().model_hash
        self.assertEqual(recomputed, original)
        self.assertNotEqual(recomputed, 'deadbeef' * 8)

    def test_29_row_mutation_changes_hash(self):
        model = _compile('data', 'ar')
        before = model.model_hash
        rows = list(model.kpis)
        first = rows[0]
        rows[0] = KpiRow(
            number=first.number, description=first.description + ' mutated',
            type=first.type, target=first.target, formula=first.formula,
            source=first.source, frequency=first.frequency, owner=first.owner,
            family=first.family, framework=first.framework,
        )
        model.kpis = tuple(rows)
        after = model.compute_hashes().model_hash
        self.assertNotEqual(before, after)

    def test_30_render_does_not_change_model_hash(self):
        model = _compile('ai', 'en', org_name='Render Hash')
        before = model.model_hash
        for target in ('preview', 'docx', 'pdf'):
            out = render(model, target)
            self.assertEqual(model.model_hash, before)
            self.assertEqual(out.evidence.source_hash, before)
            self.assertEqual(out.evidence.model_hash, before)

    def test_31_diagnostics_do_not_affect_model_hash(self):
        model = _compile('data', 'en')
        before = model.compute_model_hash()
        model.runtime_diagnostics.update({
            'export_debug': {'preview_hash': 'aaa', 'docx_hash': 'bbb'},
            'validation_timestamps': 'now',
        })
        ev = evidence_from_model(model)
        self.assertEqual(model.compute_model_hash(), before)
        self.assertEqual(ev.source_hash, before)
        self.assertNotIn('model_hash', model.canonical_hash_payload())


class Rel37SupportedSelectionTests(unittest.TestCase):
    def _apply(self, domain, lang='ar', document_type='strategy',
               frameworks=None, explicit=None, sections=None):
        return apply_rel37_to_sections(
            sections or {'vision': 'x'},
            domain=domain,
            lang=lang,
            document_type=document_type,
            selected_frameworks=frameworks,
            explicit_selection=explicit,
        )

    def test_32_data_ndmo_applies(self):
        self.assertTrue(rel37_should_apply(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO'], explicit_selection=True))
        out, repairs = self._apply('data', frameworks=['NDMO'], explicit=True)
        self.assertTrue(is_rel37_authoritative(out))
        self.assertTrue(repairs)

    def test_33_data_pdpl_applies(self):
        self.assertTrue(rel37_should_apply(
            domain='data', lang='en', document_type='strategy',
            selected_frameworks=['PDPL'], explicit_selection=True))

    def test_34_data_ndmo_pdpl_applies(self):
        self.assertTrue(rel37_should_apply(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], explicit_selection=True))

    def test_35_data_explicit_nca_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NCA'], explicit_selection=True))
        out, repairs = self._apply('data', frameworks=['NCA'], explicit=True)
        self.assertFalse(is_rel37_authoritative(out))
        self.assertEqual(repairs, [])
        self.assertIn('unsupported', last_selection_diagnostic().get('reason', ''))

    def test_36_data_mixed_ndmo_nca_not_authoritative(self):
        out, repairs = self._apply(
            'data', frameworks=['NDMO', 'NCA'], explicit=True)
        self.assertFalse(is_rel37_authoritative(out))
        self.assertEqual(repairs, [])
        diag = last_selection_diagnostic()
        self.assertFalse(diag.get('supported'))
        self.assertTrue(diag.get('unsupported_frameworks'))

    def test_37_ai_sdaia_applies(self):
        self.assertTrue(rel37_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['SDAIA'], explicit_selection=True))

    def test_38_ai_eu_ai_act_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='strategy',
            selected_frameworks=['EU AI Act'], explicit_selection=True))

    def test_39_ai_nist_ai_rmf_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='strategy',
            selected_frameworks=['NIST AI RMF'], explicit_selection=True))

    def test_40_ai_unesco_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='ar', document_type='strategy',
            selected_frameworks=['UNESCO'], explicit_selection=True))

    def test_41_dt_dga_applies(self):
        self.assertTrue(rel37_should_apply(
            domain='dt', lang='ar', document_type='strategy',
            selected_frameworks=['DGA'], explicit_selection=True))

    def test_42_dt_nist_csf_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='dt', lang='en', document_type='strategy',
            selected_frameworks=['NIST CSF'], explicit_selection=True))

    def test_43_cyber_never_applies(self):
        self.assertFalse(rel37_should_apply(
            domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=['NCA ECC'], explicit_selection=True))

    def test_44_erm_never_applies(self):
        self.assertFalse(rel37_should_apply(
            domain='erm', lang='ar', document_type='risk',
            selected_frameworks=['ISO 31000'], explicit_selection=True))

    def test_45_global_never_applies(self):
        self.assertFalse(rel37_should_apply(
            domain='global', lang='ar', document_type='gap_assessment'))

    def test_46_policy_procedure_does_not_apply(self):
        self.assertFalse(rel37_should_apply(
            domain='data', lang='ar', document_type='policy',
            selected_frameworks=['NDMO'], explicit_selection=True))
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='procedure',
            selected_frameworks=['SDAIA'], explicit_selection=True))

    def test_47_empty_expands_default_only_when_not_explicit(self):
        implicit = rel37_supported_selection(
            'data', 'ar', 'strategy', [], explicit_selection=False)
        self.assertTrue(implicit.supported)
        self.assertTrue(implicit.default_expanded)
        self.assertEqual(list(implicit.normalized_frameworks), ['ndmo', 'pdpl'])
        explicit = rel37_supported_selection(
            'data', 'ar', 'strategy', [], explicit_selection=True)
        self.assertFalse(explicit.supported)
        self.assertEqual(explicit.reason, 'unsupported_empty_explicit')

    def test_48_body_text_does_not_infer_frameworks(self):
        body = {
            'vision': 'SDAIA NDMO DGA national alignment',
            'kpis': '| SDAIA | NDMO | DGA |',
        }
        self.assertFalse(rel37_should_apply(
            domain='ai', lang='en', document_type='strategy',
            sections=body,
            selected_frameworks=['EU AI Act'],
            explicit_selection=True))
        out, repairs = self._apply(
            'ai', lang='en', frameworks=['EU AI Act'], explicit=True,
            sections=body)
        self.assertFalse(is_rel37_authoritative(out))
        self.assertEqual(repairs, [])

    def test_49_unsupported_emits_diagnostic_reason(self):
        rel37_supported_selection(
            'dt', 'en', 'strategy', ['NIST CSF'], explicit_selection=True)
        diag = last_selection_diagnostic()
        self.assertEqual(diag.get('supported'), False)
        self.assertEqual(diag.get('reason'), 'unsupported_frameworks')
        self.assertTrue(diag.get('unsupported_frameworks'))
        self.assertEqual(diag.get('domain'), 'dt')


if __name__ == '__main__':
    unittest.main()
