"""REL36.9 — English Cyber ECC+DCC live-generation stability."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_9_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from professional_strategy_render import normalize_roadmap_table
from release_engine.rel23_finalize import (
    apply_rel23_cyber_finalize,
    rel23_blocking_errors,
)
from release_engine.rel27_export_checks import (
    _is_roadmap_heading,
    _parse_roadmap_rows_from_phase_tables,
    check_roadmap_coverage,
)
from release_engine.roadmap_model import _parse_roadmap_rows
from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf
from release_engine_v3.rel35_domain_framework_fidelity import (
    detect_visible_frameworks,
    dga_interoperability_covered,
    repair_dga_interoperability_sections,
    repair_sections_for_fidelity,
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
    _TLS,
    _owner_binding_inventory,
    _rel2_pillars_blockers,
    apply_rel36_8_en_cyber_pillars_parity,
    rel36_8_should_apply,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_9_en_cyber_live_stability import (
    REL36_9_EN_CYBER_LIVE_STABILITY_TAG,
    apply_rel36_9_en_cyber_live_stability,
    repair_english_cyber_roadmap_table,
)
from release_engine_v3.validators import validate_canonical_quality
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_7_data_roadmap_balance import _data_generated_missing_three
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
    _shifted_staging_pillars,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _cyber_en_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_9_samples')
_OUT.mkdir(parents=True, exist_ok=True)


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _backend():
    return _app()._rel2_backend_callables()


def _headingless_roadmap() -> str:
    return (
        '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |\n'
        '|---|---|---|---|---|---|\n'
        '| Phase 1: Establish | 1-6 months | Establish the cybersecurity function and appoint a CISO | CISO | Approved CISO structure and governance committee | NCA ECC |\n'
        '| Phase 1: Establish | 1-6 months | Activate the cybersecurity governance committee and RACI | CISO | Approved committee charter and RACI matrix | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Operationalise SOC with SIEM platform integration | SOC Manager | 24x7 SOC with SIEM for critical assets | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Enforce IAM/PAM/MFA for privileged and critical accounts | IAM/PAM Manager | IAM/PAM platform with MFA coverage | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Establish CSIRT with approved incident response plans | CSIRT Lead | Ready CSIRT with tested playbooks | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Operate a continuous vulnerability management program | Vulnerability Manager | Vulnerability program with remediation SLA | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Deliver an annual security awareness and phishing program | Security Awareness Manager | Annual awareness plan and completion reports | NCA ECC |\n'
        '| Phase 2: Enable | 7-18 months | Test backups and disaster recovery of critical systems | Business Continuity Manager | Approved backup plan and tested DR | NCA ECC |\n'
        '| Phase 1: Establish | 1-6 months | Classify and inventory sensitive data under NCA DCC | Data Protection Officer | Approved classified data register | NCA DCC |\n'
        '| Phase 2: Enable | 7-18 months | Apply encryption and key-management controls under NCA DCC | Data Protection Officer | Encryption and key-management controls | NCA DCC |\n'
        '| Phase 2: Enable | 7-18 months | Enable DLP and leakage monitoring of sensitive data | Data Protection Officer | Operational DLP platform with leakage rules | NCA DCC |\n'
        '| Phase 3: Optimize | 19-24 months | Approve sensitive-data handling procedures under NCA DCC | Data Protection Officer | Approved sensitive-data handling procedures | NCA DCC |\n'
    )


def _roadmap_heading_variant() -> str:
    return '## Roadmap\n\n' + _headingless_roadmap()


def _family_residue_roadmap() -> str:
    return (
        '## Implementation Roadmap\n\n'
        + _headingless_roadmap()
        + '\n\nfamily:cyber_en_strategy\n'
    )


def _invisible_export_roadmap() -> str:
    """Source rows exist, but coverage previously counted 0 (no recognized heading)."""
    return (
        '## Delivery Plan\n\n'
        '| Quarter | Window | Workstream | Lead | Product | Control |\n'
        '|---|---|---|---|---|---|\n'
        '| Q1 | 1-6 months | Establish the cybersecurity function and appoint a CISO | CISO | Approved CISO structure | NCA ECC |\n'
        '| Q1 | 1-6 months | Activate the cybersecurity governance committee and RACI | CISO | Approved committee charter | NCA ECC |\n'
        '| Q2 | 7-18 months | Operationalise SOC with SIEM platform integration | SOC Manager | 24x7 SOC with SIEM | NCA ECC |\n'
        '| Q2 | 7-18 months | Enforce IAM/PAM/MFA for privileged and critical accounts | IAM/PAM Manager | IAM/PAM platform | NCA ECC |\n'
        '| Q2 | 7-18 months | Establish CSIRT with approved incident response plans | CSIRT Lead | Ready CSIRT | NCA ECC |\n'
        '| Q3 | 7-18 months | Operate a continuous vulnerability management program | Vulnerability Manager | Vulnerability program | NCA ECC |\n'
        '| Q3 | 7-18 months | Deliver an annual security awareness and phishing program | Security Awareness Manager | Annual awareness plan | NCA ECC |\n'
        '| Q4 | 7-18 months | Test backups and disaster recovery of critical systems | Business Continuity Manager | Approved backup plan | NCA ECC |\n'
    )


def _en_sections(pillars: str, roadmap: str) -> dict:
    secs = dict(_cyber_en_sections())
    secs['pillars'] = pillars
    secs['roadmap'] = roadmap
    return secs


def _apply(sections=None, attempt_id='t1', **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _en_sections(
        _malformed_en_cyber_pillars(), _roadmap_heading_variant()))
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_9_en_cyber_live_stability(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id='local-rel36-9',
            attempt_id=attempt_id,
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _source_inits(text: str):
    return {
        str(r.get('initiative') or '').strip()
        for r in _parse_roadmap_rows(text or '')
        if str(r.get('initiative') or '').strip()
    }


class Rel369RoadmapExportModelTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_01_source_rows_survive_into_docx_export_model(self):
        source = _roadmap_heading_variant()
        expected = _source_inits(source)
        secs, diag, log = _apply(
            _en_sections(render_canonical_english_cyber_pillars(), source),
            attempt_id='docx-survive',
        )
        self.assertTrue(diag['passed'], diag)
        self.assertGreaterEqual(int(diag['roadmap_rows_source']), 8)
        self.assertGreaterEqual(int(diag['roadmap_rows_docx']), 8)
        self.assertGreater(int(diag['roadmap_visible_row_count_after']), 0)
        model = normalize_roadmap_table(secs['roadmap'], 'en', domain='cyber')
        self.assertIsNotNone(model)
        self.assertGreater(len((model or {}).get('rows') or []), 0)
        model_blob = ' '.join(
            ' '.join(str(c) for c in row) for row in (model.get('rows') or []))
        survived = [init for init in expected if init in model_blob]
        for init in expected:
            self.assertIn(init, secs['roadmap'])
        self.assertGreaterEqual(len(survived), 6, survived)
        pair = _export_pair(secs, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertGreater(len(pair['docx_export'].docx_bytes or b''), 100)
        self.assertNotIn(
            'rel3_export_model_drift:roadmap_visible_row_count:0',
            diag.get('blocking_errors') or [])
        self.assertIn(REL36_9_EN_CYBER_LIVE_STABILITY_TAG, log)

    def test_02_source_rows_survive_into_pdf_export_model(self):
        source = _headingless_roadmap()
        expected = _source_inits(source)
        secs, diag, _log = _apply(
            _en_sections(render_canonical_english_cyber_pillars(), source),
            attempt_id='pdf-survive',
        )
        self.assertTrue(diag['passed'], diag)
        self.assertGreaterEqual(int(diag['roadmap_rows_pdf']), 8)
        model = normalize_roadmap_table(secs['roadmap'], 'en', domain='cyber')
        self.assertGreater(len((model or {}).get('rows') or []), 0)
        model_blob = ' '.join(
            ' '.join(str(c) for c in row) for row in (model.get('rows') or []))
        survived = [init for init in expected if init in model_blob]
        for init in expected:
            self.assertIn(init, secs['roadmap'])
        self.assertGreaterEqual(len(survived), 6, survived)
        pair = _export_pair(secs, lang='en', domain='cyber')
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        self.assertGreater(len(pair['pdf_export'].pdf_bytes or b''), 100)
        self.assertTrue((pair['pdf_export'].pdf_bytes or b'').startswith(b'%PDF-'))

    def test_03_model_drift_zero_cleared_by_real_roadmap_repair(self):
        source = _invisible_export_roadmap()
        self.assertGreater(len(_parse_roadmap_rows(source)), 0)
        before_model = normalize_roadmap_table(source, 'en', domain='cyber')
        self.assertFalse(bool((before_model or {}).get('rows')), before_model)
        rendered, stats = repair_english_cyber_roadmap_table(source)
        self.assertGreaterEqual(int(stats['roadmap_rows_source']), 1)
        self.assertIn('## Implementation Roadmap', rendered)
        self.assertIn(
            '| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |',
            rendered)
        after_model = normalize_roadmap_table(rendered, 'en', domain='cyber')
        self.assertGreater(len((after_model or {}).get('rows') or []), 0)
        after_cov = check_roadmap_coverage(rendered, domain='cyber')
        self.assertGreater(int(after_cov.get('visible_row_count') or 0), 0)
        secs, diag, _log = _apply(
            _en_sections(render_canonical_english_cyber_pillars(), source),
            attempt_id='drift-zero',
        )
        self.assertGreater(int(diag['roadmap_visible_row_count_after']), 0)
        self.assertNotIn(
            'rel3_export_model_drift:roadmap_visible_row_count:0',
            diag.get('blocking_errors') or [])
        self.assertFalse(
            any(
                str(x).startswith('rel3_export_model_drift:roadmap_visible_row_count')
                for x in (diag.get('export_model_drift_after') or [])),
            diag)
        self.assertIn('Implementation Roadmap', secs['roadmap'])
        self.assertIn('Establish the cybersecurity function', secs['roadmap'])
        # Count is repaired by a real table, not a stamped number.
        self.assertGreater(
            len(_parse_roadmap_rows(secs['roadmap'])), 0)
        canon = validate_canonical_quality(
            {},
            legacy_sections=secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
        )
        drift = [
            e for e in (canon.get('blocking_errors') or [])
            if str(e).startswith('rel3_export_model_drift:roadmap_visible_row_count')
        ]
        self.assertEqual(drift, [], drift)
        self.assertTrue(diag['passed'], diag)


class Rel369PillarBindingTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_04_final_table_clears_rel2_pillars_failed(self):
        secs, diag, _log = _apply(
            _en_sections(_malformed_en_cyber_pillars(), _roadmap_heading_variant()),
            attempt_id='pillars-failed',
        )
        self.assertEqual(diag['rel2_pillars_after'], [])
        self.assertNotIn(
            'rel2_pillars_failed:empty_or_invalid',
            diag.get('blocking_errors') or [])
        self.assertEqual(_rel2_pillars_blockers(secs['pillars']), [])
        art = {
            'sections': _en_sections(
                _malformed_en_cyber_pillars(), _roadmap_heading_variant()),
            'final_markdown': '',
            'domain': 'cyber',
            'task_id': 'rel36-9-save',
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
        self.assertIn('rel36_9:en_cyber_live_stability', repairs)
        self.assertTrue((diags.get('rel36_9') or {}).get('passed'), diags.get('rel36_9'))
        self.assertIn('Strategic Pillars', merged.get('sections', {}).get('pillars', ''))

    def test_05_final_table_clears_rel2_section_parity_failed_pillars(self):
        secs, diag, _log = _apply(
            _en_sections(_shifted_staging_pillars(), _headingless_roadmap()),
            attempt_id='parity-pillars',
        )
        self.assertEqual(diag['rel2_section_parity_after'], [])
        self.assertNotIn(
            'rel2_section_parity_failed:pillars',
            diag.get('blocking_errors') or [])
        art = {
            'sections': _en_sections(
                _shifted_staging_pillars(), _headingless_roadmap()),
            'final_markdown': '',
            'domain': 'cyber',
            'task_id': 'rel36-9-parity',
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
            _merged, _repairs, diags = apply_rel23_cyber_finalize(
                art, domain='cyber', lang='en', backend=_backend())
        blockers = rel23_blocking_errors(diags)
        self.assertNotIn('rel2_section_parity_failed:pillars', blockers)
        self.assertTrue((diags.get('rel36_9') or {}).get('passed'), diags.get('rel36_9'))
        self.assertIn('### Cybersecurity Governance', secs['pillars'])

    def test_06_owner_cells_non_empty(self):
        secs, diag, _log = _apply(
            _en_sections(_shifted_staging_pillars(), _family_residue_roadmap()),
            attempt_id='owners-empty',
        )
        self.assertEqual(diag['owner_cells_empty_after'], [])
        empty, _in_deliv = _owner_binding_inventory(secs['pillars'])
        self.assertEqual(empty, [])

    def test_07_owner_values_not_in_expected_deliverable(self):
        secs, diag, _log = _apply(
            _en_sections(_shifted_staging_pillars(), _headingless_roadmap()),
            attempt_id='owners-in-deliv',
        )
        self.assertEqual(diag['owner_values_in_deliverable_after'], [])
        _empty, in_deliv = _owner_binding_inventory(secs['pillars'])
        self.assertEqual(in_deliv, [])

    def test_08_docx_pdf_allowed(self):
        secs, diag, _log = _apply(
            _en_sections(_malformed_en_cyber_pillars(), _roadmap_heading_variant()),
            attempt_id='export-allowed',
        )
        self.assertTrue(diag['docx_allowed'], diag)
        self.assertTrue(diag['pdf_allowed'], diag)
        pair = _export_pair(secs, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)

    def test_09_no_family_visible_markers(self):
        secs, diag, _log = _apply(
            _en_sections(
                _malformed_en_cyber_pillars(), _family_residue_roadmap()),
            attempt_id='family-markers',
        )
        joined = '\n'.join(str(v) for v in secs.values())
        self.assertNotIn('family:', joined.lower())
        self.assertTrue(diag['passed'], diag)
        self.assertNotIn('family_star_visible', diag.get('blocking_errors') or [])


class Rel369FiveSeededShapesTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_10_five_seeded_shapes_pass_in_sequence(self):
        shapes = [
            ('attempt-1-headingless',
             render_canonical_english_cyber_pillars(),
             _headingless_roadmap()),
            ('attempt-2-implementation-heading',
             render_canonical_english_cyber_pillars(),
             '## Implementation Roadmap\n\n' + _headingless_roadmap()),
            ('attempt-3-roadmap-heading',
             render_canonical_english_cyber_pillars(),
             _roadmap_heading_variant()),
            ('attempt-4-malformed-pillars',
             _malformed_en_cyber_pillars(),
             _invisible_export_roadmap()),
            ('attempt-5-shifted-owners',
             _shifted_staging_pillars(),
             _family_residue_roadmap()),
        ]
        summary = []
        for attempt_id, pillars, roadmap in shapes:
            secs, diag, log = _apply(
                _en_sections(pillars, roadmap), attempt_id=attempt_id)
            cov = check_roadmap_coverage(secs['roadmap'], domain='cyber')
            pair = _export_pair(secs, lang='en', domain='cyber')
            rec = {
                'attempt_id': attempt_id,
                'passed': diag['passed'],
                'rel2_pillars_after': diag.get('rel2_pillars_after'),
                'rel2_section_parity_after': diag.get('rel2_section_parity_after'),
                'roadmap_visible_row_count_after': cov.get('visible_row_count'),
                'owner_cells_empty_after': diag.get('owner_cells_empty_after'),
                'owner_values_in_deliverable_after': diag.get(
                    'owner_values_in_deliverable_after'),
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'blocking_errors': diag.get('blocking_errors') or [],
                'tag_emitted': REL36_9_EN_CYBER_LIVE_STABILITY_TAG in log,
            }
            summary.append(rec)
            self.assertTrue(diag['passed'], rec)
            self.assertEqual(diag.get('rel2_pillars_after'), [], rec)
            self.assertGreater(int(cov.get('visible_row_count') or 0), 0, rec)
            self.assertTrue(rec['docx_allowed'], rec)
            self.assertTrue(rec['pdf_allowed'], rec)
            self.assertEqual(rec['blocking_errors'], [], rec)
            self.assertEqual(rec['owner_cells_empty_after'], [], rec)
            self.assertEqual(rec['owner_values_in_deliverable_after'], [], rec)
            self.assertNotIn('family:', '\n'.join(str(v) for v in secs.values()))
        (_OUT / 'en_cyber_5attempt_summary.json').write_text(
            json.dumps(
                {
                    'attempts': summary,
                    'pass_count': 5,
                    'tag': REL36_9_EN_CYBER_LIVE_STABILITY_TAG,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding='utf-8',
        )


class Rel369RegressionTests(unittest.TestCase):
    def test_11_arabic_cyber_regression(self):
        sections = _cyber_ar_sections()
        out, diag = apply_rel36_9_en_cyber_live_stability(
            dict(sections),
            domain='cyber',
            lang='ar',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            emit=False,
        )
        self.assertFalse(diag.get('applied'))
        self.assertEqual(diag.get('action_taken'), 'skipped')
        self.assertEqual(out['pillars'], sections['pillars'])
        self.assertEqual(out['roadmap'], sections['roadmap'])
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)

    def test_12_data_ndmo_pdpl_regression(self):
        sections = _data_generated_missing_three()
        out, diag = apply_rel36_9_en_cyber_live_stability(
            dict(sections),
            domain='data',
            lang='en',
            document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'],
            emit=False,
        )
        self.assertFalse(diag.get('applied'))
        self.assertEqual(out['roadmap'], sections['roadmap'])
        repaired, d367 = apply_rel36_7_data_pdpl_roadmap_balance(
            sections,
            domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(missing_families(repaired.get('roadmap') or ''), [])
        self.assertTrue(d367.get('passed'), d367)

    def test_13_erm_risk_regression(self):
        out, diag = apply_rel36_9_en_cyber_live_stability(
            {'analysis': _CLEAN_RISK_MD, 'content': _CLEAN_RISK_MD},
            domain='erm',
            lang='en',
            document_type='risk',
            selected_frameworks=['ISO 31000', 'COSO ERM'],
            emit=False,
        )
        self.assertFalse(diag.get('applied'))
        key = risk_cache_key(2, domain='erm', document_type='risk')
        self.assertEqual(key, 'risk:erm:risk:2')
        iso = evaluate_rel36_6_erm_risk_domain_isolation(
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
        self.assertTrue(iso.get('passed'), iso)
        tree = RenderTree(
            artifact_id='risk-rel36-9', canonical_hash='c' * 16,
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
        self.assertNotIn(
            'rel33_domain_contamination',
            ' '.join(docx.blocking_errors + pdf.blocking_errors))

    def test_14_ai_sdaia_regression(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF '
            'and NCA ECC CISO SIEM CSIRT.'
        )
        out, diag = apply_rel36_9_en_cyber_live_stability(
            leaked,
            domain='ai',
            lang='en',
            document_type='strategy',
            selected_frameworks=['SDAIA'],
            emit=False,
        )
        self.assertFalse(diag.get('applied'))
        repaired, fdiag = repair_sections_for_fidelity(
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
            'rel35_unexpected_frameworks', str(fdiag.get('blocking_errors')))

    def test_15_dt_dga_regression(self):
        out, diag = apply_rel36_9_en_cyber_live_stability(
            dict(_dt_sections()),
            domain='dt',
            lang='en',
            document_type='strategy',
            selected_frameworks=['DGA Standards'],
            emit=False,
        )
        self.assertFalse(diag.get('applied'))
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))

    def test_16_full_smoke_matrix_scripts_present(self):
        self.assertTrue(Path('scripts/smoke_document_type_matrix.py').is_file())
        self.assertTrue(Path('scripts/smoke_all_domains_preview_docx_pdf.py').is_file())
        self.assertTrue(
            rel36_8_should_apply(
                domain='cyber', lang='en', document_type='strategy',
                selected_frameworks=_NCA_FWS))
        s368, d368 = apply_rel36_8_en_cyber_pillars_parity(
            _en_sections(_malformed_en_cyber_pillars(), _roadmap_heading_variant()),
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            emit=False,
        )
        self.assertTrue(d368.get('passed'), d368)
        s369, d369, _log = _apply(s368, attempt_id='after-368')
        self.assertTrue(d369.get('passed'), d369)
        self.assertEqual(_rel2_pillars_blockers(s369['pillars']), [])
        self.assertGreater(
            int(check_roadmap_coverage(s369['roadmap'], domain='cyber').get(
                'visible_row_count') or 0),
            0)


class Rel369HelperTests(unittest.TestCase):
    def test_no_backend_does_not_invent_section_parity_blocker(self):
        secs = _en_sections(
            render_canonical_english_cyber_pillars(), _headingless_roadmap())
        out, diag = apply_rel36_9_en_cyber_live_stability(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=None,
            attempt_id='no-backend',
            emit=False,
        )
        self.assertEqual(diag.get('rel2_section_parity_after'), [])
        self.assertTrue(diag.get('passed'), diag)
        self.assertGreater(int(diag.get('roadmap_visible_row_count_after') or 0), 0)
        self.assertIn('Implementation Roadmap', out['roadmap'])

    def test_roadmap_heading_recognition(self):
        self.assertTrue(_is_roadmap_heading('## Roadmap'))
        self.assertTrue(_is_roadmap_heading('## 5. Roadmap'))
        self.assertTrue(_is_roadmap_heading('Implementation Roadmap'))
        self.assertTrue(_is_roadmap_heading('خارطة الطريق'))
        self.assertFalse(_is_roadmap_heading('Strategic Pillars'))
        self.assertFalse(_is_roadmap_heading('## Delivery Plan'))

    def test_phase_table_parse_ignores_pillar_tables(self):
        blob = render_canonical_english_cyber_pillars() + '\n\n' + _headingless_roadmap()
        rows = _parse_roadmap_rows_from_phase_tables(blob)
        self.assertGreaterEqual(len(rows), 8)
        self.assertTrue(all(r.get('initiative') for r in rows))
        self.assertFalse(any('Governance policy suite' in (r.get('initiative') or '') for r in rows))
