"""REL36.8 — English Cyber pillars section parity before REL2 save gates."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_8_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.pillar_model import finalize_pillars
from release_engine.rel23_finalize import (
    apply_rel23_cyber_finalize,
    rel23_blocking_errors,
)
from release_engine.section_parity import evaluate_section_parity
from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel33_quality_matrix import REL33_TYPE_FIXTURES_AR
from release_engine_v3.rel35_domain_framework_fidelity import (
    detect_visible_frameworks,
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
)
from release_engine_v3.rel36_5_actual_server_export_evidence_hook import (
    REL36_5_ACTUAL_SERVER_EXPORT_EVIDENCE_HOOK_TAG,
    apply_rel36_5_to_evidence_blob,
)
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_7_data_pdpl_roadmap_balance import (
    apply_rel36_7_data_pdpl_roadmap_balance,
    missing_families,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    REL36_8_EN_CYBER_PILLARS_PARITY_TAG,
    REL36_8_FAMILY_HEADINGS,
    REL36_8_PILLAR_HEADER,
    REL36_8_SECTION_HEADING,
    apply_rel36_8_en_cyber_pillars_parity,
    emit_rel36_8_en_cyber_pillars_parity,
    evaluate_rel36_8_en_cyber_pillars_parity,
    render_canonical_english_cyber_pillars,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_7_data_roadmap_balance import (
    _DATA_GENERATED_ROADMAP_MISSING_THREE,
    _data_generated_missing_three,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_en_sections,
    _export_pair,
)

_NCA_FWS = [
    'NCA ECC (Essential Cybersecurity Controls)',
    'NCA DCC (Data Cybersecurity Controls)',
]


def _malformed_en_cyber_pillars() -> str:
    """Glued headings, 3-column Program|Outcome tables, mixed cards, family:*."""
    return (
        '### Cybersecurity Governance & Operating Model | Program | Outcome | Lead |\n'
        '|---|---|---|\n'
        '| Policy suite | Approved library | CISO |\n'
        '| Committee charter | Active committee | CISO |\n'
        'family:governance_ciso extra residue\n'
        '### Protection, Detection & Response\n'
        '| Program | Outcome | Lead |\n'
        '|---|---|---|\n'
        '| SOC/SIEM operations | 24x7 SOC | SOC Manager |\n'
        '| CSIRT capability | Ready CSIRT | CSIRT Lead |\n'
        '| Continuous monitoring | SIEM coverage | CISO |\n'
        '### Identity & Data Protection — NCA DCC\n'
        '| Program | Outcome |\n'
        '|---|---|\n'
        '| IAM/PAM/MFA controls | MFA coverage |\n'
        '| Data classification | Classified register |\n'
        '| DLP controls | Operational DLP |\n'
        '### Resilience & Continuity\n'
        'Backup, DR and BCP testing owned by Business Continuity Manager.\n'
    )


def _malformed_sections() -> dict:
    secs = dict(_cyber_en_sections())
    secs['pillars'] = _malformed_en_cyber_pillars()
    return secs


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _backend():
    return _app()._rel2_backend_callables()


def _apply(sections=None, **kwargs):
    secs = dict(sections or _malformed_sections())
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_8_en_cyber_pillars_parity(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            repair_stage='pre_rel2_gates',
            **kwargs,
        )
    return out, diag, buf.getvalue()


class Rel368NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.secs, self.diag, self.log = _apply()
        self.pillars = str(self.secs.get('pillars') or '')

    def test_01_malformed_section_is_normalized_before_rel2_gates(self):
        self.assertTrue(self.diag.get('repair_applied'), self.diag)
        self.assertNotIn('| Program | Outcome |', self.pillars)
        self.assertNotIn('family:', self.pillars)
        self.assertFalse(
            any(
                ln.startswith('###') and '|' in ln
                for ln in self.pillars.splitlines()
            ),
            self.pillars,
        )

    def test_02_canonical_english_heading_and_four_column_table(self):
        self.assertIn(REL36_8_SECTION_HEADING, self.pillars)
        for heading in REL36_8_FAMILY_HEADINGS:
            self.assertIn(heading, self.pillars)
        header = '| ' + ' | '.join(REL36_8_PILLAR_HEADER) + ' |'
        self.assertIn(header, self.pillars)
        self.assertGreaterEqual(self.pillars.count('|---|---|---|---|'), 4)

    def test_03_every_initiative_row_has_non_empty_owner(self):
        owners = []
        for ln in self.pillars.splitlines():
            if not ln.strip().startswith('|') or '---' in ln:
                continue
            cells = [c.strip() for c in ln.strip('|').split('|')]
            if cells and cells[0] in ('Initiative', '#'):
                continue
            if len(cells) >= 4:
                owners.append(cells[3])
        self.assertGreaterEqual(len(owners), 12, owners)
        self.assertTrue(all(o and o not in ('—', '-', '') for o in owners), owners)

    def test_04_rel2_pillars_failed_cleared_after_repair(self):
        self.assertEqual(
            self.diag.get('rel2_pillars_blockers_after'), [], self.diag)
        out, pil = finalize_pillars(
            dict(self.secs), lang='en', domain='cyber',
            backend={**_backend(), 'selected_frameworks': _NCA_FWS})
        self.assertTrue(pil.get('rendered_table_valid'), pil)
        self.assertEqual(pil.get('blocking_error_if_any') or '', '')

    def test_05_rel2_section_parity_failed_pillars_cleared(self):
        self.assertEqual(
            self.diag.get('rel2_section_parity_blockers_after'), [], self.diag)
        art = {
            'sections': self.secs,
            'final_markdown': self.pillars,
            'domain': 'cyber',
            'contract_meta': {
                'lang': 'en', 'domain': 'cyber',
                'selected_frameworks': _NCA_FWS,
            },
        }
        parity = evaluate_section_parity(art, _backend(), lang='en')
        self.assertTrue(parity.get('parity_passed'), parity)
        self.assertNotEqual(
            parity.get('blocking_error_if_any'),
            'rel2_section_parity_failed:pillars')

    def test_06_pillars_present_in_all_parity_channels(self):
        for key in (
                'pillars_present_final_after',
                'pillars_present_preview_after',
                'pillars_present_docx_after',
                'pillars_present_pdf_after'):
            self.assertTrue(self.diag.get(key), (key, self.diag))
        self.assertEqual(self.diag.get('missing_sections_docx_after'), [])
        self.assertEqual(self.diag.get('missing_sections_pdf_after'), [])

    def test_07_diagnostic_passed_true(self):
        self.assertTrue(self.diag.get('passed'), self.diag)
        self.assertIn(REL36_8_EN_CYBER_PILLARS_PARITY_TAG, self.log)
        for key in (
                'domain', 'lang', 'document_type', 'selected_frameworks',
                'task_id', 'repair_stage', 'pillar_heading_before',
                'pillar_heading_after', 'pillar_tables_before',
                'pillar_tables_after', 'pillar_rows_before',
                'pillar_rows_after', 'rendered_table_valid_before',
                'rendered_table_valid_after', 'pillars_present_final_before',
                'pillars_present_final_after', 'pillars_present_preview_before',
                'pillars_present_preview_after', 'pillars_present_docx_before',
                'pillars_present_docx_after', 'pillars_present_pdf_before',
                'pillars_present_pdf_after', 'missing_sections_docx_before',
                'missing_sections_docx_after', 'missing_sections_pdf_before',
                'missing_sections_pdf_after', 'rel2_pillars_blockers_before',
                'rel2_pillars_blockers_after',
                'rel2_section_parity_blockers_before',
                'rel2_section_parity_blockers_after', 'repair_applied',
                'passed'):
            self.assertIn(key, self.diag)
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel36_8_en_cyber_pillars_parity(self.diag)
        self.assertIn(REL36_8_EN_CYBER_PILLARS_PARITY_TAG, buf.getvalue())
        payload = evaluate_rel36_8_en_cyber_pillars_parity(
            domain='cyber', lang='en', document_type='strategy',
            selected_frameworks=_NCA_FWS,
            before_text=_malformed_en_cyber_pillars(),
            after_text=self.pillars,
            before_parity={
                'pillars_present_final': True,
                'pillars_present_preview': True,
                'pillars_present_docx': False,
                'pillars_present_pdf': False,
                'missing_sections_docx': ['pillars'],
                'missing_sections_pdf': ['pillars'],
                'rel2_section_parity_blockers': [
                    'rel2_section_parity_failed:pillars'],
            },
            after_parity={
                'pillars_present_final': True,
                'pillars_present_preview': True,
                'pillars_present_docx': True,
                'pillars_present_pdf': True,
                'missing_sections_docx': [],
                'missing_sections_pdf': [],
                'rel2_section_parity_blockers': [],
            },
            repair_applied=True,
        )
        self.assertTrue(payload['passed'], payload)
        self.assertEqual(payload['missing_sections_docx_after'], [])
        self.assertEqual(payload['missing_sections_pdf_after'], [])


class Rel368SaveAndExportTests(unittest.TestCase):
    def test_08_first_repaired_attempt_can_save(self):
        dirty = _malformed_sections()
        art = {
            'sections': dirty,
            'final_markdown': dirty.get('pillars') or '',
            'domain': 'cyber',
            'task_id': 'rel36-8-save',
            'contract_meta': {
                'lang': 'en',
                'domain': 'cyber',
                'document_type': 'strategy',
                'selected_frameworks': _NCA_FWS,
            },
            'selected_frameworks': _NCA_FWS,
        }
        buf = io.StringIO()
        with redirect_stdout(buf):
            merged, repairs, diags = apply_rel23_cyber_finalize(
                art, domain='cyber', lang='en', backend=_backend())
        blockers = rel23_blocking_errors(diags)
        self.assertFalse(
            any(str(b).startswith('rel2_pillars_failed') for b in blockers),
            blockers)
        self.assertNotIn('rel2_section_parity_failed:pillars', blockers)
        self.assertIn('rel36_8:en_cyber_pillars_parity', repairs)
        self.assertTrue((diags.get('rel36_8') or {}).get('passed'), diags.get('rel36_8'))
        self.assertIn(REL36_8_SECTION_HEADING, merged.get('sections', {}).get('pillars', ''))
        self.assertIn(REL36_8_EN_CYBER_PILLARS_PARITY_TAG, buf.getvalue())

    def test_09_english_cyber_docx_pdf_still_allowed(self):
        secs, _, _ = _apply()
        out = _export_pair(secs, lang='en', domain='cyber')
        self.assertTrue(
            out['docx_ev'].export_return_allowed, out['docx_ev'].blocking_errors)
        self.assertTrue(
            out['pdf_ev'].export_return_allowed, out['pdf_ev'].blocking_errors)
        self.assertGreater(len(out['docx_export'].docx_bytes or b''), 100)
        self.assertGreater(len(out['pdf_export'].pdf_bytes or b''), 100)

    def test_10_export_evidence_hook_still_matches_repaired(self):
        secs, _, _ = _apply()
        blob = secs.get('pillars') or ''
        repaired, diag = apply_rel36_5_to_evidence_blob(
            blob,
            export_type='docx',
            lang='en',
            domain='cyber',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            strategy_id='rel36-8',
        )
        self.assertTrue(diag.get('evidence_input_matches_repaired'), diag)
        repaired_pdf, pdf_diag = apply_rel36_5_to_evidence_blob(
            blob,
            export_type='pdf',
            lang='en',
            domain='cyber',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            strategy_id='rel36-8',
        )
        self.assertTrue(pdf_diag.get('evidence_input_matches_repaired'), pdf_diag)
        out = _export_pair(secs, lang='en', domain='cyber')
        joined = ' '.join(
            str(b) for b in list(out['docx_ev'].blocking_errors or [])
            + list(out['pdf_ev'].blocking_errors or []))
        self.assertNotIn('pillar_owner_missing', joined)
        self.assertNotIn('actual PDF evidence validation failed', joined)
        self.assertTrue(repaired)
        self.assertTrue(repaired_pdf)


class Rel368RegressionTests(unittest.TestCase):
    def test_11_data_ndmo_pdpl_roadmap_balance_still_passes(self):
        secs, diag = apply_rel36_7_data_pdpl_roadmap_balance(
            _data_generated_missing_three(),
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(missing_families(secs.get('roadmap') or ''), [])
        self.assertTrue(diag.get('passed'), diag)
        app = _app()
        missing = app._compute_missing_data_roadmap_balance_topics(
            secs.get('roadmap') or '', ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(missing, [], missing)
        blob = '\n'.join(str(v) for v in secs.values())
        for tok in (
                'NCA ECC', 'CISO', 'SIEM', 'CSIRT', 'NIST CSF', 'NIST AI RMF'):
            self.assertNotIn(tok, blob)

    def test_12_erm_risk_isolation_still_passes(self):
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        diag = evaluate_rel36_6_erm_risk_domain_isolation(
            route='erm:risk:ar',
            domain='erm',
            document_type='risk',
            lang='ar',
            risk_id=2,
            strategy_id='',
            source_artifact_type='risk',
            loaded_artifact_type='risk',
            loaded_domain='erm',
            loaded_document_type='risk',
            content=_CLEAN_RISK_MD,
        )
        self.assertTrue(diag.get('passed'), diag)
        tree = RenderTree(
            artifact_id='risk-rel36-8', canonical_hash='c' * 16,
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
        self.assertNotIn('rel33_domain_contamination',
                         ' '.join(docx.blocking_errors + pdf.blocking_errors))

    def test_13_ai_sdaia_has_no_nist_nca_leakage(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF '
            'and NCA ECC CISO SIEM CSIRT.'
        )
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        fw = detect_visible_frameworks(blob)
        self.assertIn('SDAIA', fw)
        for tok in (
                'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
                'NCA ECC', 'CISO', 'SIEM', 'CSIRT'):
            self.assertNotIn(tok, blob)
        self.assertNotIn(
            'rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_14_dt_dga_interoperability_still_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_15_does_not_rewrite_data_or_arabic_cyber(self):
        data = dict(_data_sections())
        data['roadmap'] = _DATA_GENERATED_ROADMAP_MISSING_THREE
        out, diag = apply_rel36_8_en_cyber_pillars_parity(
            data, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(diag.get('action_taken'), 'skipped')
        self.assertEqual(out.get('roadmap'), data.get('roadmap'))
        ar = dict(_cyber_en_sections())
        ar['pillars'] = '## 2. الركائز الاستراتيجية\n### حوكمة ونموذج التشغيل\n'
        out_ar, diag_ar = apply_rel36_8_en_cyber_pillars_parity(
            ar, domain='cyber', lang='ar', document_type='strategy',
            selected_frameworks=_NCA_FWS)
        self.assertEqual(diag_ar.get('action_taken'), 'skipped')
        self.assertIn('الركائز', out_ar.get('pillars') or '')

    def test_canonical_renderer_is_detector_safe(self):
        text = render_canonical_english_cyber_pillars(_malformed_en_cyber_pillars())
        self.assertIn(REL36_8_SECTION_HEADING, text)
        self.assertNotIn('family:', text)
        self.assertIn('| Initiative | Description | Expected Deliverable | Owner |', text)


if __name__ == '__main__':
    unittest.main()
