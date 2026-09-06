"""REL36.16 — English Cyber vision / pillars / objective pre-save repair."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_16_')
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
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    _TLS,
    _rel2_pillars_blockers,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    apply_rel36_10_data_catalog_roadmap_balance,
)
from release_engine_v3.rel36_11_en_cyber_export_stability import (
    evaluate_rel36_11_csrf,
    resolve_rel36_11_export_auth,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    apply_rel36_13_en_cyber_core_completeness,
)
from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
    apply_rel36_14_en_cyber_final_counted_structures,
)
from release_engine_v3.rel36_15_final_registry_stability import (
    apply_rel36_15_final_registry_stability,
    official_cyber_missing_families,
)
from release_engine_v3.rel36_16_en_cyber_vision_pillars_objectives import (
    REL36_16_EN_CYBER_VISION_PILLARS_OBJECTIVE_STABILITY_TAG,
    apply_rel36_16_en_cyber_vision_pillars_objectives,
    evaluate_rel36_16_en_cyber_vision_pillars_objectives,
    repair_first_strategic_objectives_table,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _data_sections,
    _dt_sections,
)
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
)
from tests.test_rel36_9_english_cyber_live_stability import (
    _en_sections,
    _headingless_roadmap,
    _residue_en_cyber_vision,
)
from tests.test_rel36_13_english_cyber_core_completeness import (
    _WEAK_CONF,
    _WEAK_ENV,
    _WEAK_GAPS,
    _WEAK_KPI,
    _WEAK_VISION,
)
from tests.test_rel36_14_english_cyber_final_counted_structures import (
    _duplicate_gap_guides,
    _empty_first_csf_plus_second_table,
    _imbalanced_roadmap_ecc2_dcc8,
)
from tests.test_rel36_15_final_registry_stability import (
    _DATA_MISSING_LIFECYCLE,
    _NO_CLASSIFICATION_ROADMAP,
    _REL3613_KPI,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_16_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_16_samples'
_QA.mkdir(parents=True, exist_ok=True)

_CUSTOM_OBJECTIVE = 'Publish a board cyber-risk dashboard for residual risk'


def _residue_pillars() -> str:
    base = render_canonical_english_cyber_pillars()
    return (
        '## 2. Strategic Pillars\n\n'
        'Please include each owner in every initiative row.\n'
        'Ensure that the following controls are implemented for NCA ECC.\n'
        '[insert pillar description here]\n'
        'TBD: finish this section\n'
        'System: draft three sections for the model.\n\n'
        + base.replace('## 2. Strategic Pillars\n', '', 1)
    )


def _empty_so_vision() -> str:
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Protect the organization from cyber risk.\n\n'
        '### Strategic Objectives\n\n'
        '| # | Objective | Target Metric | Justification | Timeframe |\n'
        '|---|---|---|---|---|\n'
    )


def _malformed_first_so_plus_later() -> str:
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Protect digital services for the organization.\n\n'
        '| # | Objective | Target Metric | Justification | Timeframe |\n'
        '|---|---|---|---|---|\n'
        '| 1 | TBD | TBD | TBD | TBD |\n'
        '| 2 | Placeholder | n/a | n/a | soon |\n\n'
        '### Later ignored notes\n\n'
        '| Initiative | Owner | Output |\n'
        '|---|---|---|\n'
        '| Implement NCA ECC baseline controls and achieve compliance | '
        'CISO | ECC pack |\n'
        '| Protect data under NCA DCC and achieve DCC compliance | '
        'Data Protection Officer | DCC pack |\n'
    )


def _no_fw_compliance_vision() -> str:
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Build a resilient cybersecurity operating model for digital services.\n\n'
        '### Strategic Objectives\n\n'
        '| # | Objective | Target Metric | Justification | Timeframe |\n'
        '|---|---|---|---|---|\n'
        '| 1 | Establish the CISO office | Approved CISO charter | '
        'Governance function | 6 months |\n'
        '| 2 | Operate SOC/SIEM detection | 24x7 SOC coverage | '
        'Detection capability | 12 months |\n'
        '| 3 | Enforce IAM/PAM/MFA | MFA coverage 100% | '
        'Identity assurance | 12 months |\n'
        '| 4 | Test backup and disaster recovery | Annual DR test | '
        'Resilience readiness | 18 months |\n'
    )


def _preserved_valid_vision() -> str:
    return (
        '## 1. Vision and Strategic Objectives\n\n'
        'Build a sustainable cybersecurity operating model for the organization.\n\n'
        '### Strategic Objectives\n\n'
        '| # | Objective | Target Metric | Justification | Timeframe |\n'
        '|---|---|---|---|---|\n'
        f'| 1 | {_CUSTOM_OBJECTIVE} | Monthly pack | Board reporting | 6 months |\n'
        '| 2 | Operate SOC/SIEM detection for critical assets | 24x7 SOC | '
        'Detection | 12 months |\n'
        '| 3 | Enforce IAM/PAM/MFA for privileged accounts | MFA 100% | '
        'Identity | 12 months |\n'
        '| 4 | Test backup and disaster recovery | Annual DR test | '
        'Resilience | 18 months |\n'
    )


def _app():
    from release_engine_v3.rel33_quality_matrix import (
        _load_app_module,
        ensure_test_env,
    )
    ensure_test_env()
    return _load_app_module()


def _backend():
    return _app()._rel2_backend_callables()


def _write_export(path_stem: str, pair: dict) -> None:
    docx = pair['docx_export'].docx_bytes or b''
    pdf = pair['pdf_export'].pdf_bytes or b''
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f'{path_stem}.docx').write_bytes(docx)
        (dest / f'{path_stem}.pdf').write_bytes(pdf)


def _write_json(name: str, payload: dict) -> Path:
    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    for dest in (_OUT, _QA):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / name).write_text(text, encoding='utf-8')
    return _OUT / name


def _seed_sections(*, vision=None, environment=None, gaps=None,
                   roadmap=None, confidence=None, kpis=None,
                   pillars=None) -> dict:
    secs = _en_sections(
        pillars or render_canonical_english_cyber_pillars(),
        roadmap if roadmap is not None else _headingless_roadmap(),
        vision if vision is not None else _WEAK_VISION,
    )
    if environment is not None:
        secs['environment'] = environment
    if gaps is not None:
        secs['gaps'] = gaps
    if confidence is not None:
        secs['confidence'] = confidence
    if kpis is not None:
        secs['kpis'] = kpis
    return secs


def _prior_repairs(sections):
    out13, _ = apply_rel36_13_en_cyber_core_completeness(
        sections, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    out14, _ = apply_rel36_14_en_cyber_final_counted_structures(
        out13, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    out15, _ = apply_rel36_15_final_registry_stability(
        out14, domain='cyber', lang='en', document_type='strategy',
        selected_frameworks=_NCA_FWS, emit=False)
    return out15


def _apply16(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _seed_sections(
        environment=_WEAK_ENV, gaps=_WEAK_GAPS,
        confidence=_WEAK_CONF, kpis=_REL3613_KPI,
        roadmap=_NO_CLASSIFICATION_ROADMAP))
    domain = kwargs.pop('domain', 'cyber')
    lang = kwargs.pop('lang', 'en')
    fws = kwargs.pop('selected_frameworks', _NCA_FWS)
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_16_en_cyber_vision_pillars_objectives(
            secs,
            domain=domain,
            lang=lang,
            document_type='strategy',
            selected_frameworks=fws,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-16'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            generation_mode=kwargs.pop('generation_mode', 'drafting'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _residue_tags(sections, prefix):
    return [
        t for t, _ in _app().detect_arabic_prompt_residue(sections, 'en') or []
        if str(t).startswith(prefix)
    ]


class Rel3616ResidueAndObjectivesTests(unittest.TestCase):
    def test_01_pillars_prompt_residue_removed_before_save(self):
        secs = _seed_sections(pillars=_residue_pillars(), vision=_WEAK_VISION)
        before = _residue_tags({'pillars': secs['pillars']}, 'pillars_')
        self.assertIn('pillars_contains_prompt_residue', before, before)
        out, diag, log = _apply16(secs)
        after = _residue_tags({'pillars': out.get('pillars') or ''}, 'pillars_')
        self.assertEqual(after, [], after)
        self.assertEqual(diag.get('pillars_residue_after'), [], diag)
        self.assertNotIn('pillars_contains_prompt_residue',
                         diag.get('prompt_residue_blockers_after') or [])
        self.assertIn('NCA ECC', out.get('pillars') or '')
        self.assertIn('CISO', out.get('pillars') or '')
        self.assertNotIn('family:', out.get('pillars') or '')
        self.assertIn(REL36_16_EN_CYBER_VISION_PILLARS_OBJECTIVE_STABILITY_TAG, log)
        _write_json('en_cyber_vision_pillars_objective_diagnostic.json', diag)

    def test_02_vision_prompt_residue_removed_before_save(self):
        secs = _seed_sections(vision=_residue_en_cyber_vision())
        before = _residue_tags({'vision': secs['vision']}, 'vision_')
        self.assertIn('vision_contains_prompt_residue', before, before)
        out, diag, _ = _apply16(secs)
        after = _residue_tags({'vision': out.get('vision') or ''}, 'vision_')
        self.assertEqual(after, [], after)
        self.assertEqual(diag.get('vision_residue_after'), [], diag)
        self.assertIn('NCA ECC', out.get('vision') or '')
        self.assertIn('NCA DCC', out.get('vision') or '')

    def test_03_zero_counted_objective_rows_rebuilt(self):
        secs = _seed_sections(vision=_empty_so_vision())
        self.assertEqual(_app().count_valid_objective_rows(secs['vision']), 0)
        out, diag, _ = _apply16(secs)
        self.assertGreaterEqual(diag.get('so_rows_after'), 4, diag)
        self.assertGreaterEqual(
            _app().count_valid_objective_rows(out.get('vision') or ''), 4)
        self.assertIn('| # | Objective |', out.get('vision') or '')
        self.assertTrue(diag.get('passed'), diag)

    def test_04_rows_inserted_into_first_counted_table(self):
        vision = _malformed_first_so_plus_later()
        self.assertEqual(_app().count_valid_objective_rows(vision), 0)
        repaired, stats = repair_first_strategic_objectives_table(
            vision, selected_frameworks=_NCA_FWS)
        self.assertGreaterEqual(stats.get('so_rows_after'), 4, stats)
        self.assertGreaterEqual(_app().count_valid_objective_rows(repaired), 4)
        import re as _re
        headers = [
            ln for ln in repaired.splitlines()
            if _re.match(
                r'^\|\s*#\s*\|\s*(?:Objective|الهدف)', ln.strip(), _re.I)
        ]
        self.assertGreaterEqual(len(headers), 1, headers)
        first_hdr = headers[0]
        self.assertIn('Target Metric', first_hdr)
        self.assertIn('Justification', first_hdr)
        self.assertIn('Timeframe', first_hdr)
        first_block = repaired.split('### Later')[0]
        self.assertNotIn('| 1 | TBD |', first_block)
        self.assertGreaterEqual(_app().count_valid_objective_rows(first_block), 4)

    def test_05_ecc_selected_framework_objective_present(self):
        secs = _seed_sections(vision=_no_fw_compliance_vision())
        missing = _app()._compute_missing_compliance_objective(
            secs, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertIn('ECC', missing, missing)
        out, diag, _ = _apply16(secs)
        missing_after = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertNotIn('ECC', missing_after, missing_after)
        self.assertTrue(diag.get('ecc_objective_present_after'), diag)
        blob = out.get('vision') or ''
        self.assertTrue(
            'NCA ECC' in blob or 'Essential Cybersecurity Controls' in blob, blob)

    def test_06_dcc_selected_framework_objective_present(self):
        secs = _seed_sections(vision=_no_fw_compliance_vision())
        missing = _app()._compute_missing_compliance_objective(
            secs, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertIn('DCC', missing, missing)
        out, diag, _ = _apply16(secs)
        missing_after = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertNotIn('DCC', missing_after, missing_after)
        self.assertTrue(diag.get('dcc_objective_present_after'), diag)
        blob = out.get('vision') or ''
        self.assertTrue(
            'NCA DCC' in blob or 'Data Cybersecurity Controls' in blob, blob)

    def test_07_selected_framework_blocker_cleared_after_real_repair(self):
        secs = _seed_sections(vision=_no_fw_compliance_vision())
        out, diag, _ = _apply16(secs)
        missing = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertEqual(missing, [], missing)
        self.assertEqual(
            diag.get('selected_framework_objective_blockers_after'), [], diag)
        self.assertNotIn(
            'selected_framework_compliance_objective_missing',
            ' '.join(diag.get('save_blockers_after') or []))

    def test_08_synth_failed_vision_cleared_after_real_repair(self):
        secs = _seed_sections(vision=_empty_so_vision())
        out, diag, _ = _apply16(secs)
        self.assertGreaterEqual(
            _app().count_valid_objective_rows(out.get('vision') or ''), 4)
        self.assertEqual(diag.get('synth_vision_blockers_after'), [], diag)
        self.assertNotIn(
            'synth_failed:vision', diag.get('save_blockers_after') or [])
        self.assertNotIn(
            'so_rows_insufficient',
            ' '.join(diag.get('save_blockers_after') or []))

    def test_09_diagnostic_failed_if_pillars_residue_remains(self):
        diag = evaluate_rel36_16_en_cyber_vision_pillars_objectives(
            selected_frameworks=_NCA_FWS,
            pillars_residue_after=['Please include each owner'],
            so_rows_after=6,
            ecc_objective_present_after=True,
            dcc_objective_present_after=True,
        )
        self.assertFalse(diag.get('passed'), diag)

    def test_10_diagnostic_failed_if_ecc_dcc_still_missing(self):
        diag = evaluate_rel36_16_en_cyber_vision_pillars_objectives(
            selected_frameworks=_NCA_FWS,
            so_rows_after=6,
            ecc_objective_present_after=False,
            dcc_objective_present_after=False,
            selected_framework_objective_blockers_after=[
                'selected_framework_compliance_objective_missing:ECC,DCC'],
        )
        self.assertFalse(diag.get('passed'), diag)

    def test_11_existing_valid_objectives_are_preserved(self):
        secs = _seed_sections(vision=_preserved_valid_vision())
        out, diag, _ = _apply16(secs)
        self.assertIn(_CUSTOM_OBJECTIVE, out.get('vision') or '')
        self.assertGreaterEqual(diag.get('so_rows_after'), 4, diag)
        missing = _app()._compute_missing_compliance_objective(
            out, _NCA_FWS, domain='Cyber Security', lang='en')
        self.assertEqual(missing, [], missing)


class Rel3616PreserveAndRegressionTests(unittest.TestCase):
    def test_12_rel36_15_kpi_repair_still_passes(self):
        secs = _seed_sections(kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)
        prior = _prior_repairs(secs)
        out, _diag, _ = _apply16(prior)
        self.assertGreaterEqual(
            _app().count_substantive_kpis(out.get('kpis') or ''), 4)
        self.assertIn('Frequency', out.get('kpis') or '')
        self.assertIn('### KPI Assessment Guidelines', out.get('kpis') or '')

    def test_13_rel36_15_roadmap_family_repair_still_passes(self):
        secs = _seed_sections(roadmap=_NO_CLASSIFICATION_ROADMAP)
        prior = _prior_repairs(secs)
        out, _diag, _ = _apply16(prior)
        missing = official_cyber_missing_families(
            out.get('roadmap') or '', _NCA_FWS)
        self.assertNotIn('data_classification', missing, missing)
        official = _app()._compute_missing_cyber_roadmap_balance_topics(
            out.get('roadmap') or '', _NCA_FWS, lang='en')
        self.assertNotIn('data_classification', official, official)

    def test_14_rel36_14_gap_confidence_roadmap_counters_still_pass(self):
        secs = _seed_sections(
            gaps=_duplicate_gap_guides(),
            confidence=_empty_first_csf_plus_second_table(),
            roadmap=_imbalanced_roadmap_ecc2_dcc8())
        prior = _prior_repairs(secs)
        out, diag, _ = _apply16(prior)
        from release_engine_v3.rel36_14_en_cyber_final_counted_structures import (
            _count_first_table_csf,
            _gap_duplicate_count,
            _roadmap_counts,
        )
        self.assertEqual(_gap_duplicate_count(out.get('gaps') or ''), 0)
        self.assertGreaterEqual(_count_first_table_csf(out.get('confidence') or ''), 4)
        ecc, dcc = _roadmap_counts(out.get('roadmap') or '')
        self.assertGreaterEqual(ecc, 3, (ecc, dcc))
        self.assertGreaterEqual(dcc, 3, (ecc, dcc))
        self.assertEqual(diag.get('save_blockers_after'), [], diag)

    def test_15_rel36_12_pillars_remain_valid(self):
        secs = _seed_sections(pillars=_malformed_en_cyber_pillars())
        prior = _prior_repairs(secs)
        out, diag, _ = _apply16(prior)
        self.assertEqual(
            _rel2_pillars_blockers(out.get('pillars') or ''), [], diag)
        self.assertEqual(diag.get('rel2_pillars_blockers_after'), [], diag)
        from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
            _owner_binding_inventory,
        )
        empty, mismatched = _owner_binding_inventory(out.get('pillars') or '')
        self.assertEqual(empty, [])
        self.assertEqual(mismatched, [])
        self.assertNotIn('family:', out.get('pillars') or '')

    def test_16_english_cyber_docx_pdf_allowed(self):
        secs = _seed_sections(
            vision=_empty_so_vision(), pillars=_residue_pillars(),
            environment=_WEAK_ENV, gaps=_WEAK_GAPS,
            confidence=_WEAK_CONF, kpis=_REL3613_KPI,
            roadmap=_NO_CLASSIFICATION_ROADMAP)
        prior = _prior_repairs(secs)
        out, diag, _ = _apply16(prior)
        self.assertTrue(diag.get('passed'), diag)
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('en_cyber_ecc_dcc', pair)
        _write_json('en_cyber_final_stability_diagnostic.json', diag)

    def test_17_english_cyber_10_seeded_shapes_pass(self):
        shapes = [
            ('s1', _seed_sections(vision=_empty_so_vision(), pillars=_residue_pillars())),
            ('s2', _seed_sections(vision=_residue_en_cyber_vision())),
            ('s3', _seed_sections(vision=_malformed_first_so_plus_later())),
            ('s4', _seed_sections(vision=_no_fw_compliance_vision())),
            ('s5', _seed_sections(vision=_WEAK_VISION, kpis=_WEAK_KPI,
                                  roadmap=_headingless_roadmap())),
            ('s6', _seed_sections(vision=_preserved_valid_vision(),
                                  pillars=_malformed_en_cyber_pillars())),
            ('s7', _seed_sections(gaps=_WEAK_GAPS, kpis=_REL3613_KPI,
                                  roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s8', _seed_sections(kpis=_REL3613_KPI,
                                  roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                                  confidence=_WEAK_CONF)),
            ('s9', _seed_sections(
                vision=_empty_so_vision(), pillars=_residue_pillars(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table(),
                kpis=_REL3613_KPI, roadmap=_NO_CLASSIFICATION_ROADMAP)),
            ('s10', _seed_sections(
                vision=_malformed_first_so_plus_later(),
                pillars=_residue_pillars(),
                kpis=_WEAK_KPI,
                roadmap=_imbalanced_roadmap_ecc2_dcc8(),
                gaps=_duplicate_gap_guides(),
                confidence=_empty_first_csf_plus_second_table())),
        ]
        summary = []
        for attempt_id, secs in shapes:
            prior = _prior_repairs(secs)
            out, diag, _ = _apply16(prior, attempt_id=attempt_id, task_id=attempt_id)
            pair = _export_pair(out, lang='en', domain='cyber')
            residue = _app().detect_arabic_prompt_residue(out, 'en') or []
            so = _app().count_valid_objective_rows(out.get('vision') or '')
            missing_fw = _app()._compute_missing_compliance_objective(
                out, _NCA_FWS, domain='Cyber Security', lang='en')
            missing_fam = official_cyber_missing_families(
                out.get('roadmap') or '', _NCA_FWS)
            rec = {
                'attempt_id': attempt_id,
                'so_rows': so,
                'residue': [t for t, _ in residue],
                'missing_fw': missing_fw,
                'missing_families': missing_fam,
                'save_blockers_after': diag.get('save_blockers_after'),
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'passed': (
                    bool(diag.get('passed'))
                    and so >= 4
                    and not residue
                    and not missing_fw
                    and 'data_classification' not in missing_fam
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
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

    def test_18_data_ndmo_pdpl_regression_passes(self):
        secs = dict(_data_sections())
        secs['roadmap'] = _DATA_MISSING_LIFECYCLE
        apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        apply_rel36_10_data_catalog_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        out15, _ = apply_rel36_15_final_registry_stability(
            secs, domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        out, diag, _ = _apply16(
            out15, domain='data', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'])
        self.assertFalse(diag.get('applied'), diag)
        official = _app()._compute_missing_data_roadmap_balance_topics(
            out15.get('roadmap') or '',
            ['NDMO', 'PDPL'], lang='ar')
        self.assertEqual(official, [], official)
        pair = _export_pair(out15, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_19_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        out, diag, _ = _apply16(
            sections, domain='cyber', lang='ar', selected_frameworks=_NCA_FWS)
        self.assertFalse(diag.get('applied'), diag)
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_20_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-16', canonical_hash='c' * 16,
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
        for dest in (_OUT, _QA):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
            (dest / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_21_ai_sdaia_regression_passes(self):
        leaked = dict(_ai_sections())
        leaked['environment'] = (
            str(leaked.get('environment') or '')
            + ' NIST CSF and NIST Cybersecurity Framework and NIST AI RMF '
            + 'and NCA ECC CISO SIEM CSIRT.'
        )
        repaired, diag = repair_sections_for_fidelity(
            leaked, domain='ai', document_type='strategy',
            selected_frameworks=['SDAIA'], lang='ar')
        blob = '\n'.join(str(v) for v in repaired.values())
        self.assertIn('SDAIA', detect_visible_frameworks(blob))
        for tok in (
                'NIST CSF', 'NIST Cybersecurity Framework', 'NIST AI RMF',
                'NCA ECC', 'CISO', 'SIEM', 'CSIRT'):
            self.assertNotIn(tok, blob)
        pair = _export_pair(_ai_sections(), lang='ar', domain='ai')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('ai_sdaia', pair)
        self.assertNotIn(
            'rel35_unexpected_frameworks', str(diag.get('blocking_errors')))

    def test_22_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_23_auth_csrf_regression_passes(self):
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
        self.assertEqual(valid.get('http_status'), 200)
        self.assertEqual(cross.get('http_status'), 403)

    def test_24_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
