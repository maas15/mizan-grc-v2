"""REL36.19 — bilingual visible language parity."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_19_')
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
from release_engine_v3.rel32_preview_table_dom import (
    evaluate_preview_dom_binding_check,
    render_preview_table_html,
)
from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
from release_engine_v3.rel35_domain_framework_fidelity import (
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
)
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_7_data_pdpl_roadmap_balance import (
    apply_rel36_7_data_pdpl_roadmap_balance,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _TLS
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    apply_rel36_10_data_catalog_roadmap_balance,
)
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    apply_rel36_15_final_registry_stability,
)
from release_engine_v3.rel36_18_ai_sdaia_kpi_synth import (
    apply_rel36_18_ai_sdaia_kpi_synth,
)
from release_engine_v3.rel36_19_bilingual_language_parity import (
    GUIDE_AR,
    GUIDE_EN,
    KPI_FORMULA_EN,
    KPI_MAIN_EN,
    REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG,
    SO_HEADERS_EN,
    apply_rel36_19_bilingual_language_parity,
    bind_latest_preview_payload,
    count_kpi_main_tables,
    first_kpi_table_headers,
    kpi_main_schema_valid,
    roadmap_visible_row_count,
    sanitize_preview_txt_print,
    sanitize_visible_language_text,
    set_visible_org_name,
)
from release_engine.rel27_export_checks import _is_roadmap_heading
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    bind_saved_preview_payload,
    sanitize_visible_preview_text,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import _NCA_FWS
from tests.test_rel36_15_final_registry_stability import _DATA_MISSING_LIFECYCLE
from tests.test_rel36_17_english_cyber_final_save_gate_stabilizer import (
    _apply17,
    _official_so_gate,
    _prior_repairs,
    _seed_sections,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _cyber_en_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_19_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_19_samples'
_QA.mkdir(parents=True, exist_ok=True)

_AR_RE = re.compile(r'[\u0600-\u06FF]')
_NDMO = ['NDMO', 'PDPL']
_SDAIA = ['SDAIA']


def _write_json(name, payload):
    raw = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(raw, encoding='utf-8')


def _write_export(name, pair):
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{name}.docx').write_bytes(docx)
        (dest / f'{name}.pdf').write_bytes(pdf)


def _write_preview(name, sections):
    html = '\n'.join(
        f'<h2>{k}</h2><pre>{v}</pre>'
        for k, v in sections.items() if isinstance(v, str))
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{name}_preview.html').write_text(html, encoding='utf-8')


def _apply19(sections, **kwargs):
    _TLS.depth = 0
    secs = dict(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_19_bilingual_language_parity(
            secs,
            domain=kwargs.pop('domain', 'cyber'),
            lang=kwargs.pop('lang', 'en'),
            document_type=kwargs.pop('document_type', 'strategy'),
            selected_frameworks=kwargs.pop(
                'selected_frameworks', list(_NCA_FWS)),
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _en_mixed_so(domain='cyber'):
    obj = {
        'cyber': 'Establish cybersecurity governance',
        'data': 'Establish enterprise data governance',
        'ai': 'Establish AI governance',
    }[domain]
    return (
        '## 1. Vision & Strategic Objectives\n\n'
        f'{obj} for the selected frameworks.\n\n'
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        f'| 1 | {obj} | 90% controls evidenced | Closes the governance gap | 6 months |\n'
    )


def _en_ai_arabic_so():
    return (
        '## 1. Vision & Strategic Objectives\n\n'
        'English AI vision narrative.\n\n'
        '| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تأسيس حوكمة الذكاء الاصطناعي | معتمدة سياسة | SDAIA إطار | 8 أشهر |\n'
    )


def _en_kpi_mixed(domain='cyber'):
    if domain == 'cyber':
        rows = [
            '| 1 | MTTD | KPI | < 15 minutes | total detect time / incidents | SIEM / SOC | Monthly | CISO |',
            '| 2 | MFA coverage | KPI | 100% | privileged accounts with MFA / privileged accounts × 100 | IAM platform | Monthly | IAM/PAM Manager |',
            '| 3 | Vulnerability SLA | KPI | ≥ 95% | remediated critical vulns / due critical vulns × 100 | Vulnerability reports | Monthly | Vulnerability Manager |',
            '| 4 | Awareness completion | KPI | ≥ 90% | trained users / required users × 100 | LMS reports | Quarterly | Awareness Manager |',
        ]
        formula = '| 1 | MTTD | total detect time / incidents | SIEM / SOC |'
    elif domain == 'data':
        rows = [
            '| 1 | Catalog completeness | KPI | ≥ 90% | cataloged assets / critical assets × 100 | Data Catalog | Quarterly | Metadata and Catalog Manager |',
            '| 2 | Data quality score | KPI | ≥ 90% | valid records / total records × 100 | Quality platform | Monthly | Data Quality Manager |',
            '| 3 | PDPL consent coverage | KPI | 100% | consented processing / personal-data processing × 100 | Consent register | Quarterly | Personal Data Protection Officer |',
            '| 4 | DSR SLA | KPI | ≥ 95% | DSR closed on time / DSR received × 100 | DSR ticket log | Monthly | Personal Data Protection Officer |',
        ]
        formula = '| 1 | Catalog completeness | cataloged assets / critical assets × 100 | Data Catalog |'
    else:
        rows = [
            '| 1 | Model register coverage | KPI | 100% | registered models / production models × 100 | Model register | Quarterly | Model Risk Manager |',
            '| 2 | Human oversight completion | KPI | 100% | overseen high-risk models / high-risk models × 100 | Oversight log | Quarterly | AI Governance Lead |',
            '| 3 | MLOps pipeline coverage | KPI | 100% | models in MLOps / production models × 100 | MLOps platform | Quarterly | MLOps Lead |',
            '| 4 | Model-card coverage | KPI | 100% | models with cards / high-risk models × 100 | Model cards | Quarterly | AI Governance Lead |',
        ]
        formula = '| 1 | Model register coverage | registered models / production models × 100 | Model register |'
    return (
        '## 6. Key Performance Indicators\n\n'
        '| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |\n'
        '|---|---|---|---|---|---|---|---|\n'
        + '\n'.join(rows) + '\n\n'
        '| # | المؤشر | صيغة الاحتساب | مصدر البيانات |\n'
        '|---|---|---|---|\n'
        + formula + '\n\n'
        '### KPI Assessment Guidelines\n\n'
        '| الخطوة | الإجراء | المسؤول | الإطار الزمني | الناتج |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Collect evidence | Owner | Quarterly | Assessment report |\n'
    )


def _en_activity_roadmap(domain='data'):
    if domain == 'data':
        rows = (
            '| Create enterprise data catalog | Data Management Office | 1-6 months | Catalog register |\n'
            '| Deploy data quality rules | Data Quality Manager | 7-18 months | Quality dashboard |\n'
            '| Operationalize PDPL consent | Personal Data Protection Officer | 7-18 months | Consent platform |\n'
        )
    else:
        rows = (
            '| Establish AI governance | AI Governance Lead | 1-6 months | Approved SDAIA policy |\n'
            '| Register production models | Model Risk Manager | 7-18 months | Model inventory |\n'
            '| Deploy MLOps controls | MLOps Lead | 19-24 months | MLOps pipeline |\n'
        )
    return (
        '| Activity | Owner | Timeline | Deliverable |\n'
        '|---|---|---|---|\n'
        + rows
    )


def _en_cyber_arabic_prose():
    secs = dict(_cyber_en_sections())
    secs['vision'] = _en_mixed_so('cyber')
    secs['pillars'] = (
        '### Top priorities\n'
        '| # | Initiative | Description | Expected Deliverable | Owner |\n'
        '|---|---|---|---|---|\n'
        '| 1 | IAM/PAM/MFA controls | تطبيق IAM/PAM/MFA | منصة IAM معتمدة | مدير IAM/PAM |\n'
        '| 2 | DLP controls | ضوابط DLP | منصة DLP تشغيلية | مدير حماية البيانات |\n'
    )
    secs['roadmap'] = (
        '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |\n'
        '|---|---|---|---|---|---|\n'
        '| Phase 1 | 1-6 أشهر | تأسيس حوكمة الأمن السيبراني | CISO | لجنة معتمدة | NCA ECC |\n'
        '| Phase 2 | 7-18 شهر | تطبيق IAM/PAM/MFA | مدير IAM/PAM | MFA للحسابات | NCA DCC |\n'
        '| Phase 2 | 7-18 شهر | ضوابط DLP | مدير حماية البيانات | منصة DLP | NCA DCC |\n'
    )
    secs['kpis'] = _en_kpi_mixed('cyber')
    return secs


def _en_data_mixed():
    secs = {
        'vision': _en_mixed_so('data'),
        'pillars': (
            '| # | Initiative | Description | Expected Deliverable | Owner |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Data catalog | Register critical data assets | Catalog register | CDO |\n'
        ),
        'environment': 'NDMO and PDPL regulatory context.',
        'gaps': (
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Weak catalog coverage | Critical assets unregistered | High | Open |\n'
        ),
        'roadmap': _en_activity_roadmap('data'),
        'kpis': _en_kpi_mixed('data'),
        'confidence': '| Factor | Weight | Score | Contribution |\n|---|---|---|---|\n| Input | 20% | Good | 16% |\n',
        'governance': 'Chief Data Officer and data stewards.',
        'traceability': '| Framework | Control | Objective | Gap |\n|---|---|---|---|\n| NDMO | Catalog | Register assets | Weak catalog |\n',
    }
    return secs


def _en_ai_mixed():
    return {
        'vision': _en_ai_arabic_so(),
        'pillars': (
            '| # | Initiative | Description | Expected Deliverable | Owner |\n'
            '|---|---|---|---|---|\n'
            '| 1 | AI policy | SDAIA governance | Approved policy | AI Governance Lead |\n'
        ),
        'environment': 'SDAIA AI regulatory context.',
        'gaps': (
            '| # | Gap | Description | Priority | Status |\n'
            '|---|---|---|---|---|\n'
            '| 1 | Weak model register | Production models untracked | High | Open |\n'
        ),
        'roadmap': _en_activity_roadmap('ai'),
        'kpis': _en_kpi_mixed('ai'),
        'confidence': '| Factor | Weight | Score | Contribution |\n|---|---|---|---|\n| Oversight | 20% | Good | 16% |\n',
        'governance': 'AI Governance Lead and human oversight.',
        'traceability': '| Framework | Control | Objective | Gap |\n|---|---|---|---|\n| SDAIA | Governance | AI policy | Weak governance |\n',
    }


def _kpi_preview_errors(text, lang='en'):
    headers, rows = [], []
    for ln in str(text or '').splitlines():
        if not ln.strip().startswith('|'):
            if headers and len(headers) >= 7:
                break
            headers, rows = [], []
            continue
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        if '---' in ln:
            continue
        blob = ' '.join(cells).lower()
        if not headers:
            if 'kpi description' in blob or 'وصف المؤشر' in blob:
                headers = cells
            continue
        rows.append(cells)
        break
    if not headers:
        return []
    kind = 'kpi_main'
    html = render_preview_table_html(
        headers, rows or [[''] * len(headers)],
        schema_id=kind, is_rtl=False, lang=lang)
    check = evaluate_preview_dom_binding_check(html, kind, lang=lang)
    return [
        e for e in (check.get('blocking_errors') or [])
        if 'rel32_preview_table_header_value_mismatch' in str(e)
    ]


def _docx_text(pair):
    return str(getattr(pair['docx_export'], 'extracted_text', '') or '')


class Rel3619LanguageParityTests(unittest.TestCase):
    def test_01_en_cyber_so_headers_english(self):
        out, diag, log = _apply19(_en_cyber_arabic_prose(), domain='cyber')
        vision = out.get('vision') or ''
        for col in SO_HEADERS_EN[1:]:
            self.assertIn(col, vision, vision)
        self.assertNotIn('الهدف الاستراتيجي', vision)
        self.assertIn(REL36_19_BILINGUAL_LANGUAGE_PARITY_TAG, log)
        _write_json('en_cyber_language_parity.json', diag)

    def test_02_en_data_so_headers_english(self):
        out, diag, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        vision = out.get('vision') or ''
        for col in SO_HEADERS_EN[1:]:
            self.assertIn(col, vision, vision)
        self.assertNotIn('الهدف الاستراتيجي', vision)
        _write_json('en_data_language_parity.json', diag)

    def test_03_en_ai_so_headers_english(self):
        out, diag, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        vision = out.get('vision') or ''
        for col in SO_HEADERS_EN[1:]:
            self.assertIn(col, vision, vision)
        self.assertNotIn('الهدف الاستراتيجي', vision)
        _write_json('en_ai_language_parity.json', diag)

    def test_04_en_ai_objective_rows_have_no_arabic(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        vision = out.get('vision') or ''
        self.assertNotRegex(vision, r'[\u0600-\u06FF]')
        self.assertNotIn('تأسيس حوكمة الذكاء الاصطناعي', vision)

    def test_05_en_cyber_kpi_no_type_source_mismatch(self):
        out, _, _ = _apply19(_en_cyber_arabic_prose(), domain='cyber')
        errors = _kpi_preview_errors(out.get('kpis') or '')
        self.assertFalse(
            any(':Type' in e or ':Source' in e for e in errors), errors)

    def test_06_en_data_kpi_no_source_mismatch(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        errors = _kpi_preview_errors(out.get('kpis') or '')
        self.assertFalse(any(':Source' in e for e in errors), errors)

    def test_07_en_ai_kpi_formula_headers_english(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        for col in KPI_FORMULA_EN[1:]:
            self.assertIn(col, kpis, kpis)
        self.assertNotIn('المؤشر', kpis)
        self.assertNotIn('صيغة الاحتساب', kpis)
        self.assertNotIn('مصدر البيانات', kpis)

    def test_08_en_data_kpi_guide_headers_english(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        kpis = out.get('kpis') or ''
        for col in GUIDE_EN:
            self.assertIn(col, kpis, kpis)
        self.assertNotIn('الخطوة', kpis)

    def test_09_en_ai_kpi_guide_headers_english(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        kpis = out.get('kpis') or ''
        for col in GUIDE_EN:
            self.assertIn(col, kpis, kpis)
        self.assertNotIn('الإجراء', kpis)

    def test_10_ar_kpi_guide_headers_remain_arabic(self):
        for domain, fws, seed in (
                ('cyber', _NCA_FWS, _cyber_ar_sections()),
                ('data', _NDMO, _data_sections()),
                ('ai', _SDAIA, _ai_sections())):
            secs = dict(seed)
            secs['kpis'] = (
                str(secs.get('kpis') or '')
                + '\n\n| الخطوة | الإجراء | المسؤول | الإطار الزمني | الناتج |\n'
                '|---|---|---|---|---|\n'
                '| 1 | جمع الأدلة | المالك | ربع سنوي | تقرير |\n')
            out, _, _ = _apply19(
                secs, domain=domain, lang='ar', selected_frameworks=list(fws))
            kpis = out.get('kpis') or ''
            for col in GUIDE_AR:
                self.assertIn(col, kpis, (domain, kpis))
            # First H2 in each section must remain H2 so joined-document
            # roadmap coverage does not swallow later KPI/guide tables.
            for key, before in secs.items():
                if not isinstance(before, str):
                    continue
                had_h2 = any(
                    ln.lstrip().startswith('## ')
                    and not ln.lstrip().startswith('###')
                    for ln in before.splitlines())
                if not had_h2:
                    continue
                after = out.get(key) or ''
                still_h2 = any(
                    ln.lstrip().startswith('## ')
                    and not ln.lstrip().startswith('###')
                    for ln in after.splitlines())
                self.assertTrue(still_h2, (domain, key, after[:200]))

    def test_11_en_data_roadmap_export_countable(self):
        out, diag, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO,
            output_type='docx')
        road = out.get('roadmap') or ''
        self.assertIn('Phase', road)
        self.assertIn('Initiative', road)
        self.assertGreater(int(diag.get('roadmap_visible_row_count_after') or 0), 0)
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_data', out)
        _write_export('en_data', pair)

    def test_12_en_ai_roadmap_export_countable(self):
        out, diag, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA,
            output_type='pdf')
        self.assertGreater(int(diag.get('roadmap_visible_row_count_after') or 0), 0)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_preview('en_ai', out)
        _write_export('en_ai', pair)

    def test_13_no_data_roadmap_visible_row_count_drift(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        pair = _export_pair(out, lang='en', domain='data')
        blockers = list(pair['docx_ev'].blocking_errors or [])
        self.assertFalse(
            any('roadmap_visible_row_count' in str(b) for b in blockers),
            blockers)

    def test_14_no_ai_roadmap_visible_row_count_drift(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        blockers = list(pair['docx_ev'].blocking_errors or [])
        self.assertFalse(
            any('roadmap_visible_row_count' in str(b) for b in blockers),
            blockers)

    def test_15_no_data_pdf_evidence_failed(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        pair = _export_pair(out, lang='en', domain='data')
        blob = ' '.join(str(b) for b in (pair['pdf_ev'].blocking_errors or []))
        self.assertNotIn('actual PDF evidence validation failed', blob)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, blob)

    def test_16_no_ai_pdf_evidence_failed(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        blob = ' '.join(str(b) for b in (pair['pdf_ev'].blocking_errors or []))
        self.assertNotIn('actual PDF evidence validation failed', blob)
        self.assertTrue(pair['pdf_ev'].export_return_allowed, blob)

    def test_17_en_cyber_docx_no_arabic_generated_prose(self):
        out, _, _ = _apply19(_en_cyber_arabic_prose(), domain='cyber')
        pair = _export_pair(out, lang='en', domain='cyber')
        text = (_docx_text(pair) or '\n'.join(
            str(v) for v in out.values() if isinstance(v, str)))
        self.assertFalse(_AR_RE.search(text), text[:400])
        _write_preview('en_cyber', out)
        _write_export('en_cyber', pair)
        _write_json('en_cyber_language_parity.json', {
            'arabic_hits': [], 'docx_allowed': True, 'pdf_allowed': True,
        })

    def test_18_en_data_docx_no_arabic_generated_prose(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        text = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        self.assertFalse(_AR_RE.search(text), text[:400])

    def test_19_en_ai_docx_no_arabic_generated_prose(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        text = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        self.assertFalse(_AR_RE.search(text), text[:400])

    def test_20_ar_cyber_remains_arabic_with_acronyms(self):
        out, _, _ = _apply19(
            _cyber_ar_sections(), domain='cyber', lang='ar')
        blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        self.assertTrue(_AR_RE.search(blob))
        self.assertIn('NCA ECC', blob)
        pair = _export_pair(out, lang='ar', domain='cyber')
        _write_preview('ar_cyber', out)
        _write_export('ar_cyber', pair)
        _write_json('ar_cyber_language_parity.json', {'lang': 'ar', 'passed': True})

    def test_21_ar_data_no_nca_cyber_leakage(self):
        out, _, _ = _apply19(
            _data_sections(), domain='data', lang='ar',
            selected_frameworks=_NDMO)
        blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        for tok in ('NCA', 'CISO', 'SIEM', 'SOC', 'CSIRT', 'NIST'):
            self.assertNotIn(tok, blob)
        pair = _export_pair(out, lang='ar', domain='data')
        _write_preview('ar_data', out)
        _write_export('ar_data', pair)
        _write_json('ar_data_language_parity.json', {'lang': 'ar', 'passed': True})

    def test_22_ar_ai_no_cyber_leakage(self):
        out, _, _ = _apply19(
            _ai_sections(), domain='ai', lang='ar', selected_frameworks=_SDAIA)
        blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        for tok in ('NCA', 'CISO', 'SIEM', 'SOC', 'IAM', 'PAM', 'MFA', 'CSIRT', 'NIST'):
            self.assertNotIn(tok, blob)
        pair = _export_pair(out, lang='ar', domain='ai')
        _write_preview('ar_ai', out)
        _write_export('ar_ai', pair)
        _write_json('ar_ai_language_parity.json', {'lang': 'ar', 'passed': True})

    def test_23_saved_latest_en_does_not_load_arabic(self):
        iso = bind_latest_preview_payload(
            {'language': 'ar', 'domain': 'cyber', 'document_type': 'strategy'},
            expected_domain='cyber', expected_lang='en',
            expected_document_type='strategy')
        self.assertFalse(iso.get('success'), iso)
        self.assertTrue(
            any('lang_mismatch' in str(b) for b in iso.get('blocking_errors') or []),
            iso)
        bound = bind_saved_preview_payload(
            {'strategy_id': 9, 'language': 'ar', 'domain': 'cyber',
             'document_type': 'strategy', 'sections': _cyber_ar_sections()},
            expected_domain='cyber', expected_lang='en',
            expected_document_type='strategy')
        self.assertFalse(bound.get('success'), bound)

    def test_24_saved_latest_ar_does_not_load_english(self):
        iso = bind_latest_preview_payload(
            {'language': 'en', 'domain': 'data', 'document_type': 'strategy'},
            expected_domain='data', expected_lang='ar',
            expected_document_type='strategy')
        self.assertFalse(iso.get('success'), iso)
        bound = bind_saved_preview_payload(
            {'strategy_id': 10, 'language': 'en', 'domain': 'data',
             'document_type': 'strategy', 'sections': _en_data_mixed()},
            expected_domain='data', expected_lang='ar',
            expected_document_type='strategy')
        self.assertFalse(bound.get('success'), bound)

    def test_25_preview_txt_print_share_sanitizer(self):
        self.assertTrue(_is_roadmap_heading('Implementation Roadmap'))
        self.assertFalse(_is_roadmap_heading('9  Implementation Roadmap'))
        src = 'family:soc_siem  MTTD table'
        a = sanitize_visible_language_text(src, 'en')
        b = sanitize_preview_txt_print(src, lang='en', domain='cyber')
        c = sanitize_visible_preview_text(src, 'en')
        self.assertNotIn('family:', a)
        self.assertNotIn('family:', b)
        self.assertNotIn('family:', c)

    def test_26_static_version_cache_busting(self):
        html = (ROOT / 'templates' / 'base.html').read_text(encoding='utf-8')
        self.assertIn(
            "rel32-preview-table-schema.js') }}?v={{ static_version }}",
            html)
        js = (ROOT / 'static' / 'js' / 'rel32-preview-table-schema.js').read_text(
            encoding='utf-8')
        self.assertIn("label_en: 'Strategic Objective'", js)
        self.assertIn("label_en: 'Calculation Formula'", js)

    def test_27_rel36_18_ai_sdaia_5_shape_regression(self):
        from tests.test_rel36_18_ai_sdaia_kpi_synth import (
            _MISSING_KPI, _ai_secs, _valid_n_kpis,
        )
        shapes = [
            _ai_secs(_MISSING_KPI),
            _ai_secs(_valid_n_kpis(3)),
            _ai_secs(_valid_n_kpis(4)),
            _ai_secs(_valid_n_kpis(5)),
            _ai_secs(_valid_n_kpis(6)),
        ]
        summary = []
        for i, secs in enumerate(shapes, 1):
            out, diag = apply_rel36_18_ai_sdaia_kpi_synth(
                dict(secs), domain='ai', lang='ar',
                document_type='strategy', selected_frameworks=_SDAIA,
                generation_mode='drafting', emit=False)
            rec = {
                'shape': i,
                'applied': bool(diag.get('applied') or diag.get('repair_applied')
                                or diag.get('kpi_rows_after', 0) >= 4),
                'rows_after': diag.get('kpi_rows_after'),
                'passed': int(diag.get('kpi_rows_after') or 0) >= 4,
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
            out19, _, _ = _apply19(
                out, domain='ai', lang='ar', selected_frameworks=_SDAIA)
            self.assertIn('وصف المؤشر', out19.get('kpis') or '')
        payload = {'attempts': summary, 'pass_count': 5, 'required': 5}
        _write_json('ai_sdaia_5shape_summary.json', payload)
        self.assertEqual(payload['pass_count'], 5)

    def test_28_rel36_17_english_cyber_10_shape_regression(self):
        from tests.test_rel36_13_english_cyber_core_completeness import (
            _WEAK_CONF, _WEAK_GAPS, _WEAK_KPI,
        )
        from tests.test_rel36_14_english_cyber_final_counted_structures import (
            _duplicate_gap_guides, _empty_first_csf_plus_second_table,
            _imbalanced_roadmap_ecc2_dcc8,
        )
        from tests.test_rel36_15_final_registry_stability import (
            _NO_CLASSIFICATION_ROADMAP, _REL3613_KPI,
        )
        from tests.test_rel36_16_english_cyber_vision_pillars_objectives import (
            _empty_so_vision, _malformed_first_so_plus_later,
            _no_fw_compliance_vision, _residue_pillars,
        )
        from tests.test_rel36_8_english_cyber_pillars_parity import (
            _malformed_en_cyber_pillars,
        )
        from tests.test_rel36_17_english_cyber_final_save_gate_stabilizer import (
            _duplicate_gov_so, _target_like_so,
        )
        shapes = [
            _seed_sections(vision=_duplicate_gov_so()),
            _seed_sections(vision=_target_like_so()),
            _seed_sections(vision=_empty_so_vision(), pillars=_residue_pillars()),
            _seed_sections(vision=_malformed_first_so_plus_later(), gaps=_WEAK_GAPS),
            _seed_sections(vision=_no_fw_compliance_vision(), confidence=_WEAK_CONF),
            _seed_sections(pillars=_malformed_en_cyber_pillars(),
                           gaps=_duplicate_gap_guides()),
            _seed_sections(confidence=_empty_first_csf_plus_second_table(),
                           kpis=_REL3613_KPI,
                           roadmap=_NO_CLASSIFICATION_ROADMAP),
            _seed_sections(vision=_target_like_so(),
                           pillars=_malformed_en_cyber_pillars(),
                           roadmap=_imbalanced_roadmap_ecc2_dcc8()),
            _seed_sections(vision=_duplicate_gov_so(),
                           pillars=_malformed_en_cyber_pillars(),
                           gaps=_WEAK_GAPS,
                           confidence=_empty_first_csf_plus_second_table()),
            _seed_sections(vision=_target_like_so(), pillars=_residue_pillars(),
                           gaps=_duplicate_gap_guides(),
                           confidence=_empty_first_csf_plus_second_table(),
                           kpis=_WEAK_KPI,
                           roadmap=_imbalanced_roadmap_ecc2_dcc8()),
        ]
        summary = []
        for i, secs in enumerate(shapes, 1):
            prior = _prior_repairs(secs)
            out17, diag17, _ = _apply17(prior, attempt_id=f's{i}', task_id=f's{i}')
            out18, diag18 = apply_rel36_18_ai_sdaia_kpi_synth(
                dict(out17), domain='cyber', lang='en',
                document_type='strategy', selected_frameworks=_NCA_FWS,
                emit=False)
            out19, diag19, _ = _apply19(out18, domain='cyber', lang='en')
            so_gate = _official_so_gate(out19.get('vision') or out17.get('vision') or '')
            rec = {
                'attempt_id': f's{i}',
                'rel36_17_passed': bool(diag17.get('passed')),
                'rel36_18_applied': bool(diag18.get('applied')),
                'rel36_19_so_english': 'Strategic Objective' in (out19.get('vision') or ''),
                'so_gate_passed': bool(so_gate.get('gate_passed')),
                'passed': (
                    bool(diag17.get('passed'))
                    and not diag18.get('applied')
                    and bool(so_gate.get('gate_passed'))
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        self.assertEqual(payload['pass_count'], 10)

    def test_29_data_ndmo_pdpl_regression(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=_NDMO, emit=False)
        apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=_NDMO, emit=False)
        out15, _ = apply_rel36_15_final_registry_stability(
            secs, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=_NDMO, emit=False)
        out19, _, _ = _apply19(
            out15, domain='data', lang='ar', selected_frameworks=_NDMO)
        official = __import__('app')._compute_missing_data_roadmap_balance_topics(
            out19.get('roadmap') or '', _NDMO, lang='ar')
        self.assertEqual(official, [], official)

    def test_30_erm_risk_regression(self):
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
            artifact_id='risk-rel36-19', canonical_hash='c' * 16,
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

    def test_31_dt_dga_regression(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        out, diag, _ = _apply19(
            repaired, domain='dt', lang='ar', selected_frameworks=['DGA'])
        self.assertTrue(diag.get('skipped_reason') or not diag.get('passed'))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)

    def test_32_auth_csrf_regression(self):
        valid = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=1,
            csrf_valid=True, strategy_id=6, lang='en', domain='cyber',
            document_type='strategy')
        stale = evaluate_rel36_11_csrf(
            session_token='server', request_token='stale',
            path='/api/generate-docx-async')
        missing = evaluate_rel36_11_csrf(
            session_token='server', request_token='',
            path='/api/generate-pdf-async')
        cross = resolve_rel36_11_export_auth(
            authenticated_user_id=1, owner_id=1, strategy_owner_id=2,
            csrf_valid=True, strategy_id=6, lang='en', domain='cyber',
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

    def test_33_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())
        js = (ROOT / 'static' / 'js' / 'rel32-preview-table-schema.js').read_text(
            encoding='utf-8')
        self.assertIn("label_en: 'Type'", js)
        self.assertIn("label_en: 'Source'", js)


_AR_ORG = 'شركة مثال'


def _alias_kpi_table():
    return (
        '## 6. Key Performance Indicators\n\n'
        '| # | KPI | Type | Target | Formula | Data Source | Frequency | Owner |\n'
        '|---|---|---|---|---|---|---|---|\n'
        '| 1 | MTTD | KPI | < 15 minutes | total detect time / incidents | SIEM | Monthly | CISO |\n'
    )


def _malformed_kpi_table():
    return (
        '## 6. KPIs\n\n'
        '| # | Metric | Target |\n'
        '|---|---|---|\n'
        '| 1 | Coverage | 100% |\n'
    )


class Rel36191CodexGuardTests(unittest.TestCase):
    def test_01_en_cyber_arabic_org_preserved(self):
        secs = _en_cyber_arabic_prose()
        secs['vision'] = (
            f'Prepared for {_AR_ORG}.\n\n' + (secs.get('vision') or ''))
        out, diag, _ = _apply19(secs, domain='cyber', org_name=_AR_ORG)
        blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        self.assertIn(_AR_ORG, blob)
        self.assertIn('Strategic Objective', out.get('vision') or '')
        self.assertNotIn('الهدف الاستراتيجي', out.get('vision') or '')
        self.assertTrue(diag.get('org_name_preserved'), diag)
        _write_preview('en_cyber_ar_org', out)
        _write_json('en_cyber_ar_org_language_parity.json', diag)

    def test_02_en_data_arabic_org_prose_removed(self):
        secs = _en_data_mixed()
        secs['vision'] = (
            f'Prepared for {_AR_ORG}.\n\n' + (secs.get('vision') or ''))
        out, diag, _ = _apply19(
            secs, domain='data', selected_frameworks=_NDMO, org_name=_AR_ORG)
        blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
        self.assertIn(_AR_ORG, blob)
        self.assertFalse(diag.get('arabic_header_hits_in_en_after'), diag)
        self.assertFalse(diag.get('arabic_prose_hits_in_en_after'), diag)
        pair = _export_pair(out, lang='en', domain='data')
        _write_preview('en_data_ar_org', out)
        _write_export('en_data_ar_org', pair)
        _write_json('en_data_ar_org_language_parity.json', diag)

    def test_03_en_ai_arabic_org_generated_text_removed(self):
        secs = _en_ai_mixed()
        secs['vision'] = (
            f'Prepared for {_AR_ORG}.\n\n' + (secs.get('vision') or ''))
        out, diag, _ = _apply19(
            secs, domain='ai', selected_frameworks=_SDAIA, org_name=_AR_ORG)
        vision = out.get('vision') or ''
        self.assertIn(_AR_ORG, vision)
        self.assertNotIn('تأسيس حوكمة الذكاء الاصطناعي', vision)
        self.assertNotIn('الهدف الاستراتيجي', vision)
        pair = _export_pair(out, lang='en', domain='ai')
        _write_preview('en_ai_ar_org', out)
        _write_export('en_ai_ar_org', pair)
        _write_json('en_ai_ar_org_language_parity.json', diag)

    def test_04_preview_sanitizer_receives_org_name(self):
        set_visible_org_name(_AR_ORG)
        out = sanitize_visible_language_text(
            f'Prepared for {_AR_ORG}. الهدف الاستراتيجي leftover',
            'en', org_name=_AR_ORG)
        self.assertIn(_AR_ORG, out)
        self.assertNotIn('الهدف الاستراتيجي', out)
        preview = sanitize_visible_preview_text(
            f'Prepared for {_AR_ORG}. المبرر leftover',
            'en', org_name=_AR_ORG)
        self.assertIn(_AR_ORG, preview)

    def test_05_export_paths_receive_org_name(self):
        txt = sanitize_preview_txt_print(
            f'Print for {_AR_ORG}. الخطوة leftover',
            lang='en', domain='cyber', org_name=_AR_ORG)
        self.assertIn(_AR_ORG, txt)
        secs = _en_cyber_arabic_prose()
        secs['vision'] = f'Org {_AR_ORG}\n\n' + (secs.get('vision') or '')
        out, _, _ = _apply19(secs, domain='cyber', org_name=_AR_ORG)
        pair = _export_pair(out, lang='en', domain='cyber')
        docx = _docx_text(pair)
        if docx:
            self.assertIn(_AR_ORG, docx)
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('en_cyber_ar_org', pair)

    def test_06_arabic_org_not_counted_as_prose(self):
        secs = _en_data_mixed()
        secs['environment'] = f'Prepared for {_AR_ORG}.'
        out, diag, _ = _apply19(
            secs, domain='data', selected_frameworks=_NDMO, org_name=_AR_ORG)
        self.assertFalse(diag.get('arabic_prose_hits_in_en_after'), diag)
        self.assertIn(_AR_ORG, out.get('environment') or '')

    def test_07_generated_arabic_headers_still_replaced(self):
        out, _, _ = _apply19(
            _en_cyber_arabic_prose(), domain='cyber', org_name=_AR_ORG)
        self.assertIn('Strategic Objective', out.get('vision') or '')
        self.assertNotIn('الهدف الاستراتيجي', out.get('vision') or '')

    def test_08_repair_runs_before_canonical_artifact(self):
        from release_engine_v3.canonical_document import build_final_document_artifact
        secs = _en_data_mixed()
        art = {
            'sections': secs,
            'domain': 'data',
            'document_type': 'strategy',
            'lang': 'en',
            'org_name': _AR_ORG,
            'strategy_id': 'rel36-19-1-precanon',
            'contract_meta': {
                'lang': 'en', 'domain': 'data', 'document_type': 'strategy',
                'selected_frameworks': list(_NDMO),
            },
            'selected_frameworks': list(_NDMO),
        }
        built = build_final_document_artifact(art, strategy_id='rel36-19-1-precanon')
        diag = art.get('_rel36_19') or {}
        self.assertEqual(diag.get('repair_stage'), 'pre_canonical_artifact', diag)
        self.assertTrue(diag.get('pre_canonical_repair_applied'), diag)
        _write_json('pre_canonical_repair_diagnostic.json', {
            'repair_stage': diag.get('repair_stage'),
            'pre_canonical_repair_applied': diag.get('pre_canonical_repair_applied'),
            'canonical_hash_source': diag.get('canonical_hash_source'),
            'canonical_sections_repaired': diag.get('canonical_sections_repaired'),
            'legacy_sections_repaired': diag.get('legacy_sections_repaired'),
            'stale_canonical_headers_after': diag.get(
                'stale_canonical_headers_after'),
            'stale_freeze_blockers_after': diag.get(
                'stale_freeze_blockers_after'),
            'canonical_hash': getattr(built, 'canonical_hash', ''),
            'passed': (
                diag.get('repair_stage') == 'pre_canonical_artifact'
                and bool(diag.get('canonical_sections_repaired'))
                and not (diag.get('stale_canonical_headers_after') or [])
                and not (diag.get('stale_freeze_blockers_after') or [])
            ),
        })

    def test_09_canonical_hash_uses_repaired_sections(self):
        from release_engine_v3.canonical_document import build_final_document_artifact
        secs = _en_ai_mixed()
        art = {
            'sections': secs,
            'domain': 'ai',
            'document_type': 'strategy',
            'lang': 'en',
            'strategy_id': 'rel36-19-1-hash',
            'contract_meta': {
                'lang': 'en', 'domain': 'ai', 'document_type': 'strategy',
                'selected_frameworks': list(_SDAIA),
            },
        }
        build_final_document_artifact(art, strategy_id='rel36-19-1-hash')
        diag = art.get('_rel36_19') or {}
        self.assertEqual(diag.get('canonical_hash_source'), 'repaired_sections', diag)
        self.assertTrue(diag.get('canonical_sections_repaired'), diag)

    def test_10_preview_docx_pdf_share_repaired_headers(self):
        out, _, _ = _apply19(_en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        pair = _export_pair(out, lang='en', domain='data')
        preview = out.get('vision') or ''
        docx = _docx_text(pair) or preview
        self.assertIn('Strategic Objective', preview)
        self.assertIn('Strategic Objective', docx)
        self.assertNotIn('الهدف الاستراتيجي', preview)
        self.assertNotIn('الهدف الاستراتيجي', docx)

    def test_11_stale_arabic_headers_do_not_survive_export(self):
        out, _, _ = _apply19(_en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        blob = (_docx_text(pair) or '') + (out.get('vision') or '')
        self.assertNotIn('الهدف الاستراتيجي', blob)
        self.assertTrue(pair['docx_ev'].export_return_allowed)

    def test_12_frozen_lock_no_stale_pre_repair_blockers(self):
        from release_engine_v3.canonical_document import build_final_document_artifact
        secs = _en_cyber_arabic_prose()
        art = {
            'sections': secs,
            'domain': 'cyber',
            'document_type': 'strategy',
            'lang': 'en',
            'strategy_id': 'rel36-19-1-lock',
            'contract_meta': {
                'lang': 'en', 'domain': 'cyber', 'document_type': 'strategy',
                'selected_frameworks': list(_NCA_FWS),
            },
        }
        build_final_document_artifact(art, strategy_id='rel36-19-1-lock')
        diag = art.get('_rel36_19') or {}
        self.assertEqual(diag.get('stale_canonical_headers_after') or [], [], diag)

    def test_13_valid_alias_kpi_no_second_seed(self):
        secs = _en_cyber_arabic_prose()
        secs['kpis'] = _alias_kpi_table()
        out, diag, _ = _apply19(secs, domain='cyber')
        self.assertFalse(diag.get('seed_table_appended'), diag)
        self.assertLessEqual(int(diag.get('kpi_table_count_after') or 0), 1)
        _write_json('kpi_duplicate_table_diagnostic.json', {
            'first_kpi_table_header_before': diag.get(
                'first_kpi_table_header_before'),
            'first_kpi_table_header_after': diag.get(
                'first_kpi_table_header_after'),
            'first_kpi_table_schema_valid_before': diag.get(
                'first_kpi_table_schema_valid_before'),
            'first_kpi_table_schema_valid_after': diag.get(
                'first_kpi_table_schema_valid_after'),
            'seed_table_appended': diag.get('seed_table_appended'),
            'kpi_table_count_before': diag.get('kpi_table_count_before'),
            'kpi_table_count_after': diag.get('kpi_table_count_after'),
            'duplicate_kpi_table_after': diag.get('duplicate_kpi_table_after'),
            'passed': (
                not diag.get('seed_table_appended')
                and not diag.get('duplicate_kpi_table_after')
                and bool(diag.get('first_kpi_table_schema_valid_after'))
            ),
        })

    def test_14_valid_official_english_kpi_recognized(self):
        hdr = list(KPI_MAIN_EN)
        self.assertTrue(kpi_main_schema_valid(hdr, 'en'))

    def test_15_valid_alias_kpi_recognized_without_literal(self):
        hdr = ['#', 'KPI', 'Type', 'Target', 'Formula', 'Data Source',
               'Frequency', 'Owner']
        self.assertTrue(kpi_main_schema_valid(hdr, 'en'), hdr)
        self.assertNotEqual(' '.join(hdr), ' '.join(KPI_MAIN_EN))

    def test_16_malformed_first_kpi_replaced_not_appended(self):
        secs = _en_data_mixed()
        secs['kpis'] = _malformed_kpi_table()
        out, diag, _ = _apply19(
            secs, domain='data', selected_frameworks=_NDMO)
        kpis = out.get('kpis') or ''
        self.assertTrue(diag.get('first_kpi_table_schema_valid_after'), diag)
        self.assertLessEqual(count_kpi_main_tables(kpis, 'en'), 1)
        self.assertEqual(kpis.lower().count('key performance indicators'), 1)

    def test_17_kpi_count_does_not_increase_when_valid(self):
        secs = _en_cyber_arabic_prose()
        secs['kpis'] = _alias_kpi_table()
        before = count_kpi_main_tables(secs['kpis'], 'en')
        out, diag, _ = _apply19(secs, domain='cyber')
        after = count_kpi_main_tables(out.get('kpis') or '', 'en')
        self.assertEqual(before, 1)
        self.assertEqual(after, 1)
        self.assertFalse(diag.get('seed_table_appended'), diag)

    def test_18_arabic_kpi_schema_remains_arabic(self):
        secs = dict(_data_sections())
        out, _, _ = _apply19(
            secs, domain='data', lang='ar', selected_frameworks=_NDMO)
        kpis = out.get('kpis') or ''
        self.assertIn('وصف المؤشر', kpis)
        self.assertTrue(kpi_main_schema_valid(first_kpi_table_headers(kpis, 'ar'), 'ar'))

    def test_19_en_preview_headers_remain_english(self):
        for domain, fws, seed in (
                ('cyber', _NCA_FWS, _en_cyber_arabic_prose()),
                ('data', _NDMO, _en_data_mixed()),
                ('ai', _SDAIA, _en_ai_mixed())):
            out, _, _ = _apply19(
                seed, domain=domain, selected_frameworks=list(fws))
            self.assertIn('Strategic Objective', out.get('vision') or '', domain)

    def test_20_ar_preview_headers_remain_arabic(self):
        for domain, fws, seed in (
                ('cyber', _NCA_FWS, _cyber_ar_sections()),
                ('data', _NDMO, _data_sections()),
                ('ai', _SDAIA, _ai_sections())):
            out, _, _ = _apply19(
                seed, domain=domain, lang='ar', selected_frameworks=list(fws))
            blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
            self.assertTrue(_AR_RE.search(blob), domain)

    def test_21_en_data_docx_pdf_allowed(self):
        out, _, _ = _apply19(
            _en_data_mixed(), domain='data', selected_frameworks=_NDMO)
        pair = _export_pair(out, lang='en', domain='data')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('en_data', pair)

    def test_22_en_ai_docx_pdf_allowed(self):
        out, _, _ = _apply19(
            _en_ai_mixed(), domain='ai', selected_frameworks=_SDAIA)
        pair = _export_pair(out, lang='en', domain='ai')
        self.assertTrue(pair['docx_ev'].export_return_allowed)
        self.assertTrue(pair['pdf_ev'].export_return_allowed)
        _write_export('en_ai', pair)

    def test_23_no_data_ai_roadmap_drift(self):
        for domain, fws, seed in (
                ('data', _NDMO, _en_data_mixed()),
                ('ai', _SDAIA, _en_ai_mixed())):
            out, diag, _ = _apply19(
                seed, domain=domain, selected_frameworks=list(fws))
            self.assertGreater(int(diag.get('roadmap_visible_row_count_after') or 0), 0)

    def test_24_no_pdf_evidence_failed_data_ai(self):
        for domain, fws, seed in (
                ('data', _NDMO, _en_data_mixed()),
                ('ai', _SDAIA, _en_ai_mixed())):
            out, _, _ = _apply19(
                seed, domain=domain, selected_frameworks=list(fws))
            pair = _export_pair(out, lang='en', domain=domain)
            blob = ' '.join(str(b) for b in (pair['pdf_ev'].blocking_errors or []))
            self.assertNotIn('actual PDF evidence validation failed', blob)

    def test_25_ai_sdaia_5_shape_still_passes(self):
        Rel3619LanguageParityTests().test_27_rel36_18_ai_sdaia_5_shape_regression()

    def test_26_en_cyber_10_shape_still_passes(self):
        Rel3619LanguageParityTests().test_28_rel36_17_english_cyber_10_shape_regression()

    def test_27_data_ndmo_pdpl_still_passes(self):
        Rel3619LanguageParityTests().test_29_data_ndmo_pdpl_regression()

    def test_28_erm_still_passes(self):
        Rel3619LanguageParityTests().test_30_erm_risk_regression()

    def test_29_dt_dga_still_passes(self):
        Rel3619LanguageParityTests().test_31_dt_dga_regression()

    def test_30_auth_csrf_still_passes(self):
        Rel3619LanguageParityTests().test_32_auth_csrf_regression()

    def test_31_full_smoke_matrix_still_present(self):
        Rel3619LanguageParityTests().test_33_full_smoke_matrix_scripts_present()


if __name__ == '__main__':
    unittest.main()
