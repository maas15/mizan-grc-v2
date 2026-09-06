"""REL36.12 — English Cyber pre-save pillar stability."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel36_12_')
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
from release_engine_v3.rel36_6_erm_risk_domain_isolation import (
    evaluate_rel36_6_erm_risk_domain_isolation,
    risk_cache_key,
)
from release_engine_v3.rel36_7_data_pdpl_roadmap_balance import (
    apply_rel36_7_data_pdpl_roadmap_balance,
    missing_families,
)
from release_engine_v3.rel36_8_en_cyber_pillars_parity import (
    REL36_8_PILLAR_HEADER,
    _TLS,
    _owner_binding_inventory,
    _rel2_pillars_blockers,
    render_canonical_english_cyber_pillars,
)
from release_engine_v3.rel36_10_data_catalog_roadmap_balance import (
    apply_rel36_10_data_catalog_roadmap_balance,
)
from release_engine_v3.rel36_12_en_cyber_presave_pillar_stability import (
    REL36_12_EN_CYBER_PRESAVE_PILLAR_STABILITY_TAG,
    apply_rel36_12_en_cyber_presave_pillar_stability,
    inspect_english_cyber_pillars,
    needs_deterministic_fallback,
    rel36_12_should_apply,
    render_deterministic_english_cyber_presave_pillars,
)
from tests.test_rel33_risk_export_gate_isolation import _CLEAN_RISK_MD
from tests.test_rel35_domain_framework_fidelity import (
    _ai_sections,
    _dt_sections,
)
from tests.test_rel36_7_data_roadmap_balance import _data_generated_missing_three
from tests.test_rel36_8_english_cyber_pillars_parity import (
    _NCA_FWS,
    _malformed_en_cyber_pillars,
    _shifted_staging_pillars,
)
from tests.test_rel36_9_english_cyber_live_stability import (
    _en_sections,
    _family_residue_roadmap,
    _headingless_roadmap,
    _invisible_export_roadmap,
    _roadmap_heading_variant,
)
from tests.test_rel36_10_data_catalog_roadmap_balance import (
    _DATA_STAGING_MISSING_CATALOG,
)
from tests.test_rel36_bilingual_preview_export_authority import (
    _cyber_ar_sections,
    _cyber_en_sections,
    _export_pair,
)

_OUT = Path('/tmp/rel36_12_samples')
_OUT.mkdir(parents=True, exist_ok=True)
_QA = ROOT / 'qa_outputs' / 'rel36_12_samples'
_QA.mkdir(parents=True, exist_ok=True)


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


def _canon_table(title: str, rows: list[tuple[str, str, str, str]]) -> str:
    header = '| ' + ' | '.join(REL36_8_PILLAR_HEADER) + ' |'
    lines = [title, '', header, '|---|---|---|---|']
    for row in rows:
        lines.append('| ' + ' | '.join(row) + ' |')
    lines.append('')
    return '\n'.join(lines)


def _gov_rows():
    return [
        ('Governance policy suite',
         'Adopt cybersecurity governance policies aligned to NCA ECC',
         'Approved governance policy library', 'CISO'),
        ('Cybersecurity governance committee',
         'Ratify the committee charter with quarterly meetings',
         'Active governance committee with minutes', 'CISO'),
        ('RACI accountability matrix',
         'Assign cybersecurity RACI across departments',
         'Approved cybersecurity RACI matrix', 'CISO'),
    ]


def _pdr_rows():
    return [
        ('SOC/SIEM operations',
         'Operate SOC with SIEM use cases aligned to NCA ECC',
         '24x7 SOC with SIEM for critical assets', 'SOC Manager'),
        ('CSIRT capability',
         'Establish CSIRT with approved incident response plans',
         'Ready CSIRT with annual tabletop exercises', 'CSIRT Lead'),
        ('Continuous monitoring',
         'Operate SIEM rules on critical assets',
         'SIEM coverage of critical assets', 'SOC Manager'),
    ]


def _idp_rows(*, mismatch: bool = False):
    first = (
        ('DLP governance controls',
         'Enable DLP monitoring of sensitive data',
         'Governance-aligned DLP platform',
         'Data Protection Officer')
        if mismatch else
        ('IAM/PAM/MFA controls',
         'Enforce IAM/PAM/MFA for privileged accounts aligned to NCA DCC',
         'MFA coverage for privileged accounts',
         'IAM/PAM Manager')
    )
    return [
        first,
        ('Data classification',
         'Classify and inventory sensitive data under NCA DCC',
         'Approved classified data register', 'Data Protection Officer'),
        ('DLP controls',
         'Enable DLP and leakage monitoring of sensitive data',
         'Operational DLP platform with leakage-prevention rules',
         'Data Protection Officer'),
    ]


def _res_rows():
    return [
        ('Backup validation',
         'Test backups of critical data under NCA ECC',
         'Approved backup plan with restore tests',
         'Business Continuity Manager'),
        ('Disaster recovery',
         'Test disaster-recovery plans under NCA ECC',
         'Tested DR plan with approved RTO/RPO',
         'Business Continuity Manager'),
        ('Business continuity',
         'Approve and test BCP for critical operations',
         'Approved BCP for critical operations',
         'Business Continuity Manager'),
    ]


def _valid_custom_pillars() -> str:
    return (
        '## 2. Strategic Pillars\n\n'
        + _canon_table('### Cybersecurity Governance & Operating Model', _gov_rows())
        + _canon_table('### Protection, Detection & Response — NCA ECC', _pdr_rows())
        + _canon_table('### Identity & Data Protection — NCA DCC', _idp_rows())
        + _canon_table('### Resilience & Business Continuity — NCA ECC', _res_rows())
    )


def _empty_pillar_shape() -> str:
    return (
        '## 2. Strategic Pillars\n\n'
        '### Cybersecurity Governance & Operating Model\n\n'
        + _canon_table('### Protection, Detection & Response — NCA ECC', _pdr_rows())
        + _canon_table('### Identity & Data Protection — NCA DCC', _idp_rows())
        + _canon_table('### Resilience & Business Continuity — NCA ECC', _res_rows())
    )


def _missing_table_shape() -> str:
    return (
        '## 2. Strategic Pillars\n\n'
        + _canon_table('### Cybersecurity Governance & Operating Model', _gov_rows())
        + _canon_table('### Protection, Detection & Response — NCA ECC', _pdr_rows())
        + '### Identity & Data Protection — NCA DCC\n\n'
        'Narrative only. IAM/PAM and DLP work is described without a table.\n\n'
        + _canon_table('### Resilience & Business Continuity — NCA ECC', _res_rows())
    )


def _prod_attempt5_mismatch_pillars() -> str:
    """Production-like leftover mismatch: DLP + governance in one initiative."""
    return (
        '## 2. Strategic Pillars\n\n'
        + _canon_table('### Cybersecurity Governance & Operating Model', _gov_rows())
        + _canon_table(
            '### Protection, Detection & Response — NCA ECC',
            _pdr_rows() + [
                ('Vulnerability management program',
                 'Operate vulnerability scanning aligned to NCA ECC',
                 'Vulnerability program with remediation SLA',
                 'Vulnerability Manager'),
            ])
        + _canon_table(
            '### Identity & Data Protection — NCA DCC',
            _idp_rows(mismatch=True) + [
                ('Sensitive-data handling procedures',
                 'Approve handling procedures under NCA DCC',
                 'Approved sensitive-data handling procedures',
                 'Data Protection Officer'),
                ('Encryption controls',
                 'Apply encryption for sensitive data under NCA DCC',
                 'Encryption controls for sensitive data',
                 'Data Protection Officer'),
            ])
    )


def _apply12(sections=None, **kwargs):
    _TLS.depth = 0
    secs = dict(sections or _en_sections(
        _prod_attempt5_mismatch_pillars(), _headingless_roadmap()))
    buf = io.StringIO()
    with redirect_stdout(buf):
        out, diag = apply_rel36_12_en_cyber_presave_pillar_stability(
            secs,
            domain='cyber',
            lang='en',
            document_type='strategy',
            selected_frameworks=_NCA_FWS,
            backend=_backend(),
            task_id=kwargs.pop('task_id', 'local-rel36-12'),
            attempt_id=kwargs.pop('attempt_id', 't1'),
            emit=True,
            **kwargs,
        )
    return out, diag, buf.getvalue()


def _finalize_art(sections, task_id='local-rel36-12-save'):
    art = {
        'sections': dict(sections),
        'final_markdown': sections.get('pillars') or '',
        'domain': 'cyber',
        'task_id': task_id,
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
    return merged, repairs, diags, buf.getvalue()


def _assert_post_gate(test, pillars: str, diag=None):
    empty, in_deliv = _owner_binding_inventory(pillars)
    test.assertEqual(_rel2_pillars_blockers(pillars), [])
    test.assertEqual(empty, [], empty)
    test.assertEqual(in_deliv, [], in_deliv)
    test.assertNotIn('family:', pillars.lower())
    header = '| ' + ' | '.join(REL36_8_PILLAR_HEADER) + ' |'
    test.assertIn(header, pillars)
    if diag is not None:
        test.assertTrue(diag.get('rendered_table_valid_after'), diag)
        test.assertEqual(diag.get('empty_pillars_after'), [], diag)
        test.assertEqual(diag.get('final_rel2_pillars_blockers_after'), [], diag)
        test.assertEqual(diag.get('final_section_parity_blockers_after'), [], diag)
        test.assertTrue(diag.get('save_allowed_after'), diag)
        test.assertTrue(diag.get('passed'), diag)


class Rel3612InspectAndFallbackTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_01_malformed_final_pillars_trigger_deterministic_fallback(self):
        out, diag, log = _apply12(_en_sections(
            _malformed_en_cyber_pillars(), _headingless_roadmap()))
        self.assertTrue(diag.get('deterministic_fallback_applied'), diag)
        self.assertIn(REL36_12_EN_CYBER_PRESAVE_PILLAR_STABILITY_TAG, log)
        _assert_post_gate(self, out.get('pillars') or '', diag)
        pillars = out.get('pillars') or ''
        self.assertIn('Governance', pillars)
        self.assertRegex(pillars, r'Protection|Detection|Response')
        self.assertRegex(pillars, r'Identity|IAM|Data Protection')
        self.assertRegex(pillars, r'Resilience|Continuity|Backup')

    def test_02_empty_pillar_is_repaired_before_save_gate(self):
        before = inspect_english_cyber_pillars(_empty_pillar_shape())
        self.assertTrue(needs_deterministic_fallback(_empty_pillar_shape()))
        self.assertTrue(
            before['empty_pillars'] or before['missing_tables']
            or not before['rendered_table_valid'], before)
        out, diag, _ = _apply12(_en_sections(
            _empty_pillar_shape(), _headingless_roadmap()))
        self.assertTrue(diag.get('deterministic_fallback_applied'), diag)
        self.assertEqual(diag.get('empty_pillars_after'), [], diag)
        merged, _rep, diags, _log = _finalize_art(_en_sections(
            _empty_pillar_shape(), _headingless_roadmap()))
        blockers = rel23_blocking_errors(diags)
        self.assertFalse(
            any(str(b).startswith('rel2_pillars_failed') for b in blockers),
            blockers)
        _assert_post_gate(self, merged['sections']['pillars'], diag)

    def test_03_missing_initiative_table_is_repaired_before_save_gate(self):
        snap = inspect_english_cyber_pillars(_missing_table_shape())
        self.assertTrue(snap['missing_tables'] or not snap['rendered_table_valid'], snap)
        out, diag, _ = _apply12(_en_sections(
            _missing_table_shape(), _headingless_roadmap()))
        self.assertTrue(diag.get('deterministic_fallback_applied'), diag)
        self.assertGreaterEqual(diag.get('pillar_count_after') or 0, 4, diag)
        self.assertTrue(all(
            c >= 3 for c in (diag.get('initiative_count_by_pillar_after') or [])),
            diag)
        _assert_post_gate(self, out.get('pillars') or '', diag)

    def test_04_mismatched_output_row_after_rebuild_is_repaired(self):
        raw = _prod_attempt5_mismatch_pillars()
        _secs, pil = finalize_pillars(
            {'pillars': raw}, lang='en', domain='cyber',
            backend={**_backend(), 'selected_frameworks': _NCA_FWS})
        leftover = inspect_english_cyber_pillars(raw)
        self.assertGreaterEqual(
            leftover['mismatched_outputs_after'], 1, leftover)
        self.assertTrue(
            pil.get('mismatched_outputs_after', 0) >= 1
            or leftover['mismatched_outputs_after'] >= 1, pil)
        out, diag, _ = _apply12(_en_sections(raw, _headingless_roadmap()))
        self.assertTrue(diag.get('deterministic_fallback_applied'), diag)
        self.assertEqual(diag.get('mismatched_outputs_after'), 0, diag)
        _assert_post_gate(self, out.get('pillars') or '', diag)

    def test_05_rendered_table_valid_true_after_fallback(self):
        _out, diag, _ = _apply12()
        self.assertTrue(diag.get('rendered_table_valid_after'), diag)

    def test_06_no_rel2_pillars_failed_after_fallback(self):
        out, diag, _ = _apply12()
        self.assertEqual(diag.get('final_rel2_pillars_blockers_after'), [], diag)
        self.assertEqual(_rel2_pillars_blockers(out.get('pillars') or ''), [])
        merged, _rep, diags, _ = _finalize_art(_en_sections(
            _prod_attempt5_mismatch_pillars(), _headingless_roadmap()))
        blockers = rel23_blocking_errors(diags)
        self.assertFalse(
            any(str(b).startswith('rel2_pillars_failed') for b in blockers),
            (blockers, diags.get('pillars'), diags.get('rel36_12')))
        self.assertFalse(
            (diags.get('pillars') or {}).get('blocking_error_if_any'),
            diags.get('pillars'))

    def test_07_no_rel2_section_parity_failed_pillars_after_fallback(self):
        out, diag, _ = _apply12()
        self.assertEqual(
            diag.get('final_section_parity_blockers_after'), [], diag)
        art = {
            'sections': out,
            'final_markdown': out.get('pillars') or '',
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

    def test_08_owner_cells_nonempty(self):
        out, diag, _ = _apply12(_en_sections(
            _malformed_en_cyber_pillars(), _headingless_roadmap()))
        empty, _ = _owner_binding_inventory(out.get('pillars') or '')
        self.assertEqual(empty, [])
        self.assertEqual(diag.get('owner_cells_empty_after'), [], diag)

    def test_09_owner_values_not_in_expected_deliverable(self):
        out, diag, _ = _apply12(_en_sections(
            _shifted_staging_pillars(), _headingless_roadmap()))
        _, in_deliv = _owner_binding_inventory(out.get('pillars') or '')
        self.assertEqual(in_deliv, [])
        self.assertEqual(diag.get('owner_values_in_deliverable_after'), [], diag)

    def test_10_docx_pdf_parity_sees_pillars(self):
        out, diag, _ = _apply12()
        pair = _export_pair(out, lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        blob = (out.get('pillars') or '')
        self.assertIn('Initiative', blob)
        self.assertIn('Owner', blob)

    def test_11_fallback_does_not_run_when_pillars_already_valid(self):
        valid = render_canonical_english_cyber_pillars()
        self.assertFalse(needs_deterministic_fallback(valid))
        out, diag, _ = _apply12(_en_sections(valid, _headingless_roadmap()))
        self.assertFalse(diag.get('deterministic_fallback_applied'), diag)
        self.assertIn('Governance policy suite', out.get('pillars') or '')
        _assert_post_gate(self, out.get('pillars') or '', diag)

    def test_12_existing_valid_english_cyber_pillars_are_preserved(self):
        custom = _valid_custom_pillars()
        self.assertFalse(needs_deterministic_fallback(custom), inspect_english_cyber_pillars(custom))
        out, diag, _ = _apply12(_en_sections(custom, _headingless_roadmap()))
        self.assertFalse(diag.get('deterministic_fallback_applied'), diag)
        pillars = out.get('pillars') or ''
        self.assertIn('Governance policy suite', pillars)
        self.assertIn('SOC/SIEM operations', pillars)
        self.assertIn('IAM/PAM/MFA controls', pillars)
        self.assertIn('Backup validation', pillars)

    def test_13_english_cyber_docx_pdf_allowed(self):
        merged, _rep, diags, _ = _finalize_art(_en_sections(
            _prod_attempt5_mismatch_pillars(), _roadmap_heading_variant()))
        pair = _export_pair(merged['sections'], lang='en', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('en_cyber_ecc_dcc', pair)
        self.assertFalse(rel36_12_should_apply(
            domain='data', lang='ar', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL']))


class Rel3612TenShapeAndRegressionTests(unittest.TestCase):
    def setUp(self):
        _TLS.depth = 0
        self.addCleanup(setattr, _TLS, 'depth', 0)

    def test_14_english_cyber_10_seeded_shapes_pass(self):
        shapes = [
            ('shape-01-malformed', _malformed_en_cyber_pillars(),
             _headingless_roadmap()),
            ('shape-02-empty-pillar', _empty_pillar_shape(),
             _roadmap_heading_variant()),
            ('shape-03-missing-table', _missing_table_shape(),
             _headingless_roadmap()),
            ('shape-04-mismatch-leftover', _prod_attempt5_mismatch_pillars(),
             _headingless_roadmap()),
            ('shape-05-shifted-owner', _shifted_staging_pillars(),
             _family_residue_roadmap()),
            ('shape-06-canonical-valid', render_canonical_english_cyber_pillars(),
             _headingless_roadmap()),
            ('shape-07-custom-valid', _valid_custom_pillars(),
             _roadmap_heading_variant()),
            ('shape-08-invisible-roadmap', _prod_attempt5_mismatch_pillars(),
             _invisible_export_roadmap()),
            ('shape-09-family-residue', _malformed_en_cyber_pillars(),
             _family_residue_roadmap()),
            ('shape-10-deterministic-catalog',
             render_deterministic_english_cyber_presave_pillars(_NCA_FWS),
             _headingless_roadmap()),
        ]
        summary = []
        last_diag = None
        last_pair = None
        for attempt_id, pillars, roadmap in shapes:
            secs = _en_sections(pillars, roadmap)
            out, diag, log = _apply12(secs, attempt_id=attempt_id, task_id=attempt_id)
            merged, _rep, diags, _ = _finalize_art(secs, task_id=attempt_id)
            blockers = rel23_blocking_errors(diags)
            pair = _export_pair(merged['sections'], lang='en', domain='cyber')
            rec = {
                'attempt_id': attempt_id,
                'deterministic_fallback_applied': diag.get(
                    'deterministic_fallback_applied'),
                'rendered_table_valid_after': diag.get(
                    'rendered_table_valid_after'),
                'empty_pillars_after': diag.get('empty_pillars_after'),
                'final_rel2_pillars_blockers_after': diag.get(
                    'final_rel2_pillars_blockers_after'),
                'final_section_parity_blockers_after': diag.get(
                    'final_section_parity_blockers_after'),
                'save_allowed_after': diag.get('save_allowed_after'),
                'rel23_blockers': blockers,
                'docx_allowed': pair['docx_ev'].export_return_allowed,
                'pdf_allowed': pair['pdf_ev'].export_return_allowed,
                'log_has_tag': REL36_12_EN_CYBER_PRESAVE_PILLAR_STABILITY_TAG in log,
                'passed': (
                    bool(diag.get('passed'))
                    and not any(
                        str(b).startswith('rel2_pillars_failed')
                        or str(b).startswith('rel2_section_parity_failed:pillars')
                        for b in blockers)
                    and pair['docx_ev'].export_return_allowed
                    and pair['pdf_ev'].export_return_allowed
                ),
            }
            summary.append(rec)
            self.assertTrue(rec['passed'], rec)
            self.assertTrue(rec['log_has_tag'], rec)
            last_diag = diag
            last_pair = pair
        payload = {
            'attempts': summary,
            'pass_count': sum(1 for r in summary if r['passed']),
            'required': 10,
            'root_cause': (
                'finalize_pillars leftover mismatched_outputs_after=1 '
                '(initiative title contains both DLP and governance); '
                'needs_rebuild ignores mismatch so action_taken=no_changes; '
                'REL36.8/36.9 structural checks can report passed while the '
                'unchanged REL2 gate still blocks save.'
            ),
        }
        _write_json('en_cyber_ecc_dcc_10shape_summary.json', payload)
        _write_json('en_cyber_presave_pillar_stability_diagnostic.json', last_diag or {})
        if last_pair is not None:
            _write_export('en_cyber_ecc_dcc', last_pair)
        self.assertEqual(len(summary), 10)
        self.assertEqual(payload['pass_count'], 10)

    def test_15_data_ndmo_pdpl_regression_passes(self):
        secs = dict(_data_generated_missing_three())
        secs['roadmap'] = _DATA_STAGING_MISSING_CATALOG
        repaired, d367 = apply_rel36_7_data_pdpl_roadmap_balance(
            secs, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        repaired, d3610 = apply_rel36_10_data_catalog_roadmap_balance(
            repaired, domain='data', document_type='strategy', lang='ar',
            selected_frameworks=['NDMO', 'PDPL'], emit=False)
        self.assertEqual(missing_families(repaired.get('roadmap') or ''), [])
        self.assertTrue(d367.get('passed') or d3610.get('passed'))
        self.assertFalse(rel36_12_should_apply(
            lang='ar', domain='data', document_type='strategy',
            selected_frameworks=['NDMO', 'PDPL'],
            pillars_text=repaired.get('pillars') or ''))
        pair = _export_pair(repaired, lang='ar', domain='data')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('data_ndmo_pdpl', pair)

    def test_16_arabic_cyber_regression_passes(self):
        sections = _cyber_ar_sections()
        self.assertFalse(rel36_12_should_apply(
            lang='ar', domain='cyber', document_type='strategy',
            selected_frameworks=_NCA_FWS, pillars_text=sections.get('pillars') or ''))
        pair = _export_pair(sections, lang='ar', domain='cyber')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('arabic_cyber', pair)

    def test_17_erm_risk_regression_passes(self):
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
            artifact_id='risk-rel36-12', canonical_hash='c' * 16,
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
        (_OUT / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
        (_OUT / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        (_QA / 'erm_risk.docx').write_bytes(docx.docx_bytes or b'PK-docx')
        (_QA / 'erm_risk.pdf').write_bytes(pdf.pdf_bytes or b'%PDF-bytes')
        self.assertIn('سجل المخاطر', REL33_TYPE_FIXTURES_AR['risk']['register'])

    def test_18_ai_sdaia_regression_passes(self):
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

    def test_19_dt_dga_regression_passes(self):
        repaired, _ = repair_dga_interoperability_sections(
            _dt_sections(), lang='ar')
        self.assertTrue(dga_interoperability_covered(repaired))
        pair = _export_pair(repaired, lang='ar', domain='dt')
        self.assertTrue(
            pair['docx_ev'].export_return_allowed, pair['docx_ev'].blocking_errors)
        self.assertTrue(
            pair['pdf_ev'].export_return_allowed, pair['pdf_ev'].blocking_errors)
        _write_export('dt_dga', pair)

    def test_20_full_smoke_matrix_scripts_present(self):
        self.assertTrue((ROOT / 'scripts' / 'smoke_document_type_matrix.py').is_file())
        self.assertTrue(
            (ROOT / 'scripts' / 'smoke_all_domains_preview_docx_pdf.py').is_file())


if __name__ == '__main__':
    unittest.main()
