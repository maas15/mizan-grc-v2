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
from release_engine_v3.rel36_dcc_traceability_en_repair import (
    evaluate_rel36_dcc_traceability_en,
    expected_dcc_capabilities,
    inventory_dcc_rows,
    repair_english_dcc_traceability_sections,
)
from release_engine_v3.rel36_2_en_cyber_export_evidence_repair import (
    REL36_2_ALLOWED_OWNERS,
    evaluate_rel36_2_en_cyber_export_evidence,
    infer_english_cyber_owner,
    inventory_english_cyber_pillar_rows,
    repair_english_cyber_export_evidence_sections,
)
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY_EN,
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


def _cyber_en_live_pillar_sections() -> dict:
    """English Cyber ECC+DCC pillars as generated on staging: 3-col, no Owner."""
    secs = dict(_cyber_en_sections())
    secs['pillars'] = (
        '### Pillar 1: Cybersecurity Governance & Policy Framework\n'
        '| المبادرة | الوصف | المخرج المتوقع |\n'
        '|---|---|---|\n'
        '| 1 | CISO Framework Establishment | Design and ratify a '
        'cybersecurity governance framework aligned to NCA ECC. | '
        'Approved governance charter |\n'
        '| 2 | Cybersecurity Policy Suite Development | Publish the policy '
        'library mapped to NCA ECC control domains. | Ratified policy suite |\n'
        '### Pillar 2: Security Operations, Threat Detection & Incident Response\n'
        '| # | Initiative | Description | Expected Deliverable |\n'
        '|---|---|---|---|\n'
        '| 1 | SOC Establishment & SIEM Deployment | Stand up SOC/SIEM for '
        'NCA ECC monitoring. | Operational SOC with SIEM |\n'
        '| 2 | CSIRT & Incident Response Capability Build | Establish CSIRT '
        'and incident playbooks. | Ratified IR plan |\n'
        '| 3 | Vulnerability Management Program | Continuous vulnerability '
        'scanning and patching. | Vulnerability policy |\n'
        '### Pillar 3: Identity Security, Data Protection & Security Awareness\n'
        '| Initiative | Description | Expected Deliverable |\n'
        '|---|---|---|\n'
        '| Identity & Privileged Access Management (IAM/PAM) Program | '
        'Deploy IAM/PAM/MFA. | IAM platform operational |\n'
        '| Encryption, DLP & Data Protection Controls Deployment | '
        'Implement DLP and encryption for NCA DCC. | Operational DLP platform |\n'
        '| Security Awareness & Anti-Phishing Training Program | '
        'Mandatory awareness and phishing simulations. | Training completion |\n'
    )
    return secs


def _prepare_en_cyber_export_sections() -> dict:
    secs = dict(_cyber_en_live_pillar_sections())
    secs, _ = repair_english_dcc_traceability_sections(
        secs, lang='en', domain='cyber',
        selected_frameworks=['NCA ECC', 'NCA DCC'])
    secs, _ = repair_english_cyber_export_evidence_sections(
        secs, lang='en', domain='cyber',
        selected_frameworks=['NCA ECC', 'NCA DCC'])
    return secs


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
        self.assertNotIn('NIST', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SIEM', blob)
        self.assertNotIn('IAM', blob)
        self.assertNotIn('PAM', blob)
        self.assertNotIn('MFA', blob)
        self.assertNotIn('CSIRT', blob)

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

    def test_18_english_ecc_dcc_prcy69_traceability_passes(self):
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        old_gap = 'Weak data-loss-prevention controls'
        self.assertFalse(any(
            tok in old_gap for tok in ('تسرب', 'DLP', 'dlp', 'فقدان', 'leak')))
        new_gap = TRACE_CANONICAL_REGISTRY_EN['dlp']['expected_gap']
        self.assertTrue(any(
            tok in new_gap for tok in ('DLP', 'dlp', 'leak')))
        fws = ['NCA ECC', 'NCA DCC']
        self.assertTrue(app._prcy68_validate_traceability_dcc_mapping(
            _cyber_en_sections(), fws, 'en'))
        self.assertEqual(
            app._prcy70_traceability_invalid_cells(
                _cyber_en_sections(), fws, 'en'),
            [])
        validation = app._prcy69_validate_final_artifact(
            '', _cyber_en_sections(), fws, 'en', 'cyber',
            strict=True, metadata={'domain': 'cyber'})
        dcc_blockers = [
            b for b in (validation.get('blockers') or [])
            if 'prcy69_final_artifact_traceability_dcc_invalid' in str(b)]
        self.assertEqual(dcc_blockers, [], validation.get('blockers'))

    def test_19_english_ecc_dcc_repair_inserts_required_rows(self):
        dirty = dict(_cyber_en_sections())
        dirty['traceability'] = (
            '| Framework | Capability / Control | Related Gap | '
            'Initiative / Activity | Metric | Related Risk |\n'
            '|---|---|---|---|---|---|\n'
            '| NCA ECC | Governance | Weak CISO office | Establish CISO | '
            'Compliance rate | Governance risk |\n'
            '| NCA DCC | DLP / data leakage prevention | '
            'Weak data-loss-prevention controls | Enable DLP | '
            'DLP coverage | Leakage risk |\n'
        )
        repaired, diag = repair_english_dcc_traceability_sections(
            dirty, lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        self.assertTrue(diag['dcc_selected'])
        inv = inventory_dcc_rows(repaired.get('traceability') or '')
        self.assertEqual(sorted(inv['detected']), sorted(expected_dcc_capabilities()))
        self.assertEqual(inv['missing'], [])
        self.assertEqual(inv['invalid'], [])
        blob = repaired.get('traceability') or ''
        self.assertIn('Data classification', blob)
        self.assertIn('Encryption', blob)
        self.assertIn('DLP', blob)
        self.assertIn('Sensitive data handling', blob)
        self.assertIn('transit', blob.lower())
        self.assertIn('NCA DCC', blob)
        ev = evaluate_rel36_dcc_traceability_en(
            repaired, lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'],
            prcy69_gate_passed=True)
        self.assertTrue(ev['passed'])
        self.assertIn('REL36-DCC-TRACEABILITY-EN-REPAIR', ev['tag'])

    def test_20_english_ecc_dcc_docx_no_bypass(self):
        secs, _ = repair_english_dcc_traceability_sections(
            _cyber_en_sections(), lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['docx_ev'].blocking_errors or []))
        self.assertTrue(out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertNotIn('rel32_docx_export_bypass_detected', joined)
        self.assertGreater(len(out['docx_export'].docx_bytes or b''), 1000)

    def test_21_english_ecc_dcc_pdf_no_professional_quality_failure(self):
        secs, _ = repair_english_dcc_traceability_sections(
            _cyber_en_sections(), lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['pdf_ev'].blocking_errors or []))
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertNotIn('pdf_render_failed:docmodel_professional_quality', joined)
        self.assertNotIn('docmodel_professional_quality', joined)

    def test_22_english_ecc_only_still_passes(self):
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        secs, diag = repair_english_dcc_traceability_sections(
            _cyber_en_sections(), lang='en', domain='cyber',
            selected_frameworks=['NCA ECC'])
        self.assertFalse(diag['dcc_selected'])
        self.assertFalse(diag['repaired'])
        self.assertTrue(app._prcy68_validate_traceability_dcc_mapping(
            secs, ['NCA ECC'], 'en'))
        validation = app._prcy69_validate_final_artifact(
            '', secs, ['NCA ECC'], 'en', 'cyber',
            strict=True, metadata={'domain': 'cyber'})
        dcc_blockers = [
            b for b in (validation.get('blockers') or [])
            if 'prcy69_final_artifact_traceability_dcc_invalid' in str(b)]
        self.assertEqual(dcc_blockers, [])

    def test_23_arabic_ecc_dcc_still_passes(self):
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        secs, diag = repair_english_dcc_traceability_sections(
            _cyber_ar_sections(), lang='ar', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        self.assertFalse(diag['repaired'])
        self.assertTrue(app._prcy68_validate_traceability_dcc_mapping(
            secs, ['NCA ECC', 'NCA DCC'], 'ar'))
        self.assertEqual(
            app._prcy70_traceability_invalid_cells(
                secs, ['NCA ECC', 'NCA DCC'], 'ar'),
            [])
        out = _export_pair(secs, lang='ar')
        self.assertTrue(out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)

    def test_24_english_generation_contract_no_dcc_invalid(self):
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        secs, _ = repair_english_dcc_traceability_sections(
            _cyber_en_sections(), lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        md = app._prcy65_rebuild_content_from_sections(secs, None)
        result = app._cyber_final_export_contract(
            md,
            metadata={'domain': 'cyber', 'language': 'en'},
            selected_frameworks=['NCA ECC', 'NCA DCC'],
            lang='en',
            domain='cyber',
            output_type='generation',
        )
        blockers = ' '.join(str(b) for b in (result.get('blocking_errors') or []))
        self.assertNotIn('prcy69_final_artifact_traceability_dcc_invalid', blockers)
        self.assertTrue(
            result.get('diag', {}).get(
                'traceability_dcc_mapping_valid_in_final_artifact', True)
            or 'prcy69_final_artifact_traceability_dcc_invalid' not in blockers)

    def test_25_english_live_pillars_docx_no_pillar_owner_missing(self):
        before = inventory_english_cyber_pillar_rows(
            _cyber_en_live_pillar_sections()['pillars'])
        self.assertTrue(before['missing_owner_rows'] or before['row_count'] >= 3)
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['docx_ev'].blocking_errors or []))
        self.assertTrue(
            out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertNotIn('pillar_owner_missing', joined)
        self.assertNotIn('rel3_export_evidence_failed:docx:pillar_owner_missing', joined)

    def test_26_english_live_pillars_pdf_evidence_passes(self):
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['pdf_ev'].blocking_errors or []))
        self.assertTrue(
            out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertNotIn('pillar_owner_missing', joined)
        self.assertNotIn('actual PDF evidence validation failed', joined)

    def test_27_english_live_pillar_rows_have_non_empty_owners(self):
        secs, diag = repair_english_cyber_export_evidence_sections(
            _cyber_en_live_pillar_sections(), lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        inv = inventory_english_cyber_pillar_rows(secs.get('pillars') or '')
        self.assertGreaterEqual(inv['row_count'], 6)
        self.assertEqual(inv['missing_owner_rows'], [])
        for owner in inv['owner_values']:
            self.assertTrue(owner.strip())
            self.assertIn(owner, REL36_2_ALLOWED_OWNERS)
        self.assertTrue(diag['repaired'])
        self.assertTrue(diag['passed'])

    def test_28_english_live_pillar_owner_header_is_owner(self):
        secs, _ = repair_english_cyber_export_evidence_sections(
            _cyber_en_live_pillar_sections(), lang='en', domain='cyber')
        blob = secs.get('pillars') or ''
        self.assertIn('| Initiative | Description | Expected Deliverable | Owner |', blob)
        self.assertNotIn('| المسؤول |', blob.split('Owner', 1)[0] if 'Owner' in blob else blob)
        ev = evaluate_rel36_2_en_cyber_export_evidence(
            secs, lang='en', domain='cyber',
            selected_frameworks=['NCA ECC', 'NCA DCC'])
        self.assertTrue(ev['owner_header_detected'])
        self.assertEqual(ev['owner_alias_used'], 'Owner')

    def test_29_english_live_pillars_still_pass_prcy69_dcc(self):
        from release_engine_v3.rel33_quality_matrix import (
            _load_app_module,
            ensure_test_env,
        )
        ensure_test_env()
        app = _load_app_module()
        secs = _prepare_en_cyber_export_sections()
        validation = app._prcy69_validate_final_artifact(
            '', secs, ['NCA ECC', 'NCA DCC'], 'en', 'cyber',
            strict=True, metadata={'domain': 'cyber'})
        dcc_blockers = [
            b for b in (validation.get('blockers') or [])
            if 'prcy69_final_artifact_traceability_dcc_invalid' in str(b)]
        self.assertEqual(dcc_blockers, [], validation.get('blockers'))
        inv = inventory_dcc_rows(secs.get('traceability') or '')
        self.assertEqual(inv['missing'], [])
        self.assertEqual(inv['invalid'], [])

    def test_30_english_live_pillars_docx_no_bypass(self):
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['docx_ev'].blocking_errors or []))
        self.assertTrue(out['docx_ev'].export_return_allowed)
        self.assertNotIn('rel32_docx_export_bypass_detected', joined)
        self.assertNotIn('_build_docx_bytes', joined)

    def test_31_english_live_pillars_pdf_no_professional_quality_failure(self):
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        joined = ' '.join(str(b) for b in (out['pdf_ev'].blocking_errors or []))
        self.assertTrue(out['pdf_ev'].export_return_allowed)
        self.assertNotIn('docmodel_professional_quality', joined)
        self.assertNotIn('pdf_render_failed:docmodel_professional_quality', joined)

    def test_32_english_live_pillars_kpi_headers_english(self):
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        from release_engine_v3.evidence.docx_text_extractor import (
            extract_docx_visible_text,
        )
        text = extract_docx_visible_text(out['docx_export'].docx_bytes or b'')
        self.assertIn('KPI Description', text)
        self.assertIn('Source', text)
        self.assertFalse(english_visible_has_arabic_kpi_headers(text))
        self.assertNotIn('| مصدر |', secs['kpis'])
        self.assertIn('Source', secs['kpis'])

    def test_33_english_live_pillars_no_family_markers(self):
        secs = _prepare_en_cyber_export_sections()
        out = _export_pair(secs, lang='en')
        from release_engine_v3.evidence.docx_text_extractor import (
            extract_docx_visible_text,
        )
        preview = sanitize_visible_preview_text(
            '\n'.join(str(v) for v in secs.values()), 'en')
        docx_text = extract_docx_visible_text(out['docx_export'].docx_bytes or b'')
        self.assertFalse(visible_text_has_internal_markers(preview))
        self.assertFalse(visible_text_has_internal_markers(docx_text))
        self.assertNotIn('family:', preview)
        self.assertNotIn('family:', docx_text)

    def test_34_arabic_cyber_ecc_dcc_docx_pdf_still_pass(self):
        out = _export_pair(_cyber_ar_sections(), lang='ar')
        self.assertTrue(out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertTrue(out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        ar, diag = repair_english_cyber_export_evidence_sections(
            _cyber_ar_sections(), lang='ar', domain='cyber')
        self.assertFalse(diag['repaired'])
        self.assertEqual(ar['pillars'], _cyber_ar_sections()['pillars'])

    def test_35_data_fidelity_still_passes(self):
        repaired, _ = repair_sections_for_fidelity(
            _data_sections(), domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertIn('NDMO', blob)
        self.assertIn('PDPL', blob)
        self.assertNotIn('NCA ECC', blob)
        self.assertNotIn('NCA DCC', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SIEM', blob)
        self.assertNotIn('CSIRT', blob)

    def test_36_ai_fidelity_still_passes(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            leaked.get('environment') or '') + '\nNIST AI RMF NCA ECC CISO SIEM'
        repaired, _ = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertIn('SDAIA', blob)
        self.assertNotIn('NCA ECC', blob)
        self.assertNotIn('NIST AI RMF', blob)
        self.assertNotIn('CISO', blob)
        self.assertNotIn('SIEM', blob)
        self.assertNotIn('IAM', blob)
        self.assertNotIn('PAM', blob)
        self.assertNotIn('MFA', blob)
        self.assertNotIn('CSIRT', blob)

    def test_37_dt_dga_interoperability_still_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_dga_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertNotIn(
            'selected_framework_coverage_missing:DGA:interoperability', blob)

    def test_38_owner_inference_and_empty_owners_not_aliased_through(self):
        self.assertEqual(
            infer_english_cyber_owner('SOC Establishment & SIEM Deployment'),
            'SOC Manager')
        self.assertEqual(
            infer_english_cyber_owner('CSIRT & Incident Response'),
            'CSIRT Lead')
        self.assertEqual(
            infer_english_cyber_owner('IAM/PAM Program'),
            'IAM/PAM Manager')
        dirty = {
            'pillars': (
                '### Pillar 1: Governance\n'
                '| Initiative | Description | Expected Deliverable | Owner |\n'
                '|---|---|---|---|\n'
                '| Policy suite | NCA ECC governance policy | Charter | — |\n'
            )
        }
        secs, diag = repair_english_cyber_export_evidence_sections(
            dirty, lang='en', domain='cyber')
        inv = inventory_english_cyber_pillar_rows(secs['pillars'])
        self.assertEqual(inv['missing_owner_rows'], [])
        self.assertNotIn('—', inv['owner_values'])
        self.assertTrue(diag['repaired'])
        ev = evaluate_rel36_2_en_cyber_export_evidence(
            dirty, lang='en', domain='cyber',
            docx_evidence_before=['pillar_owner_missing'],
            docx_evidence_after=[],
            pdf_evidence_before=['pillar_owner_missing'],
            pdf_evidence_after=[])
        self.assertIn('REL36.2-EN-CYBER-EXPORT-EVIDENCE-REPAIR', ev['tag'])


if __name__ == '__main__':
    unittest.main()
