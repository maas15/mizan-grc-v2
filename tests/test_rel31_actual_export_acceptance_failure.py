"""PR-REL3.1 — acceptance failure regression on actual attached DOCX/PDF fixtures.

Fixtures (from staging export 2026-06-17):
  tests/fixtures/rel31_acceptance_failure/cyber_strategy_33.docx
  tests/fixtures/rel31_acceptance_failure/cyber_strategy_60.pdf
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_acceptance_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.export_evidence_validator import validate_actual_export_evidence
from release_engine.pillar_model import _build_canonical_pillars
from release_engine.rel31_acceptance_checks import (
    PLACEHOLDER_PILLAR_TEXT,
    rel31_blockers,
    repair_rel31_canonical_sections,
    run_rel31_acceptance_checks,
)
from release_engine_v3.canonical_document import build_final_document_artifact, freeze_artifact
from release_engine_v3.contracts import ExportResult, _sha256_bytes
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.evidence.evidence_validator import validate_returned_export_bytes
from release_engine_v3.evidence.pdf_text_extractor import extract_pdf_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches

FIXTURE_DIR = ROOT / 'tests' / 'fixtures' / 'rel31_acceptance_failure'
DOCX_FIXTURE = FIXTURE_DIR / 'cyber_strategy_33.docx'
PDF_FIXTURE = FIXTURE_DIR / 'cyber_strategy_60.pdf'


def _load_docx():
    assert DOCX_FIXTURE.is_file(), f'missing fixture {DOCX_FIXTURE}'
    data = DOCX_FIXTURE.read_bytes()
    return data, extract_docx_visible_text(data)


def _load_pdf():
    assert PDF_FIXTURE.is_file(), f'missing fixture {PDF_FIXTURE}'
    data = PDF_FIXTURE.read_bytes()
    return data, extract_pdf_visible_text(data)


def _rel3_evidence(docx_bytes=None, pdf_bytes=None, route='docx', text=''):
    art = freeze_artifact(build_final_document_artifact({
        'sections': {'vision': _build_canonical_pillars('ar'), 'pillars': _build_canonical_pillars('ar')},
        'domain': 'cyber',
        'sealed': True,
        'blocking_errors': [],
        'contract_meta': {'lang': 'ar'},
    }))
    if route == 'docx':
        b = docx_bytes or b''
        export = ExportResult(
            route_name='docx', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            docx_bytes=b, bytes_data=b,
            returned_bytes_sha256=_sha256_bytes(b),
            evidence_bytes_sha256=_sha256_bytes(b),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
    else:
        b = pdf_bytes or b''
        export = ExportResult(
            route_name='pdf', artifact_id=art.artifact_id,
            render_tree_hash='h', canonical_hash=art.canonical_hash,
            pdf_bytes=b, bytes_data=b,
            returned_bytes_sha256=_sha256_bytes(b),
            evidence_bytes_sha256=_sha256_bytes(b),
            returned_equals_evidence_bytes=True, exact_bytes_checked=True,
        )
    return validate_returned_export_bytes(export, art, route=route)


def _has_blocker(blockers, needle):
    return any(needle in b for b in blockers)


class Rel31FixtureFailureTests(unittest.TestCase):
    """Attached exports must fail REL3 evidence before canonical repair."""

    @classmethod
    def setUpClass(cls):
        cls.docx_bytes, cls.docx_text = _load_docx()
        cls.pdf_bytes, cls.pdf_text = _load_pdf()

    def test_01_docx_missing_pillars_after_heading(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('missing_pillars_after_heading', defects)
        gate = validate_actual_export_evidence('', self.docx_text, '', route_name='docx')
        self.assertFalse(gate['export_return_allowed'])
        self.assertTrue(_has_blocker(
            gate['blocking_errors'], 'missing_pillars_after_heading'))

    def test_02_pdf_missing_pillars_after_heading(self):
        defects = run_rel31_acceptance_checks(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        self.assertIn('missing_pillars_after_heading', defects)
        gate = validate_actual_export_evidence(
            '', '', self.pdf_text, route_name='pdf',
            pdf_bytes_had=True, pdf_bytes=self.pdf_bytes)
        self.assertFalse(gate['export_return_allowed'])

    def test_03_docx_placeholder_pillar_in_objectives(self):
        self.assertIn(PLACEHOLDER_PILLAR_TEXT, self.docx_text)
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('placeholder_pillar_text_in_objectives', defects)

    def test_04_docx_kpi_dlp_incident_as_percentage(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('kpi_dlp_incident_as_percentage', defects)

    def test_05_docx_generic_kpi_formula(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('generic_kpi_formula', defects)
        self.assertIn('المنجز المقيس', self.docx_text)

    def test_06_docx_empty_risk_treatment(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('empty_risk_treatment', defects)

    def test_07_pdf_empty_risk_or_structural_fail(self):
        """PDF text extraction is unreliable for tables; structural pillar fail."""
        defects = run_rel31_acceptance_checks(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        self.assertTrue(
            'empty_risk_treatment' in defects
            or 'missing_pillars_after_heading' in defects)

    def test_08_docx_traceability_dcc_classification_invalid(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('traceability_dcc_classification_invalid', defects)

    def test_09_docx_arabic_residue(self):
        defects = run_rel31_acceptance_checks(self.docx_text, route='docx')
        self.assertIn('arabic_residue', defects)

    def test_10_pdf_shares_structural_defects_when_extractable(self):
        defects = run_rel31_acceptance_checks(
            self.pdf_text, route='pdf', pdf_bytes=self.pdf_bytes)
        self.assertIn('missing_pillars_after_heading', defects)

    def test_11_pdf_render_model_requires_pillars_when_text_unreliable(self):
        """When PDF lacks pillar markers, evidence must fail (render fallback)."""
        gate = validate_actual_export_evidence(
            '', '', self.pdf_text, route_name='pdf',
            pdf_bytes_had=True, pdf_bytes=self.pdf_bytes)
        self.assertFalse(gate['pdf_export_evidence_passed'])

    def test_12_rel3_returned_file_evidence_rejects_docx_fixture(self):
        ev = _rel3_evidence(docx_bytes=self.docx_bytes, route='docx')
        self.assertFalse(ev.export_return_allowed)
        self.assertFalse(ev.evidence_passed)
        self.assertTrue(ev.docx_bytes_checked)
        self.assertTrue(ev.exact_bytes_checked)
        blockers = ' '.join(ev.blocking_errors)
        self.assertIn('missing_pillars', blockers)

    def test_13_rel3_returned_file_evidence_rejects_pdf_fixture(self):
        ev = _rel3_evidence(pdf_bytes=self.pdf_bytes, route='pdf')
        self.assertFalse(ev.export_return_allowed)
        self.assertFalse(ev.evidence_passed)
        self.assertTrue(ev.pdf_bytes_checked)

    def test_14_no_export_return_for_fixtures(self):
        for route, data in (('docx', self.docx_bytes), ('pdf', self.pdf_bytes)):
            ev = _rel3_evidence(
                docx_bytes=data if route == 'docx' else None,
                pdf_bytes=data if route == 'pdf' else None,
                route=route,
            )
            self.assertFalse(ev.export_return_allowed)
            self.assertEqual(ev.returned_equals_evidence_bytes, True)


class Rel31CanonicalRepairTests(unittest.TestCase):
    """After canonical repair, markdown model must pass acceptance checks."""

    def setUp(self):
        clear_rel3_caches()

    def _defect_sections(self):
        from domains.cyber.fixtures_ar import technical_sections
        s = dict(technical_sections())
        s['vision'] = (
            '## 1. الرؤية والأهداف\n\n'
            + '\n'.join([PLACEHOLDER_PILLAR_TEXT] * 3)
            + '\n| 1 | هدف | tgt | why | 6m |\n|---|---|---|---|---|\n'
        )
        s['pillars'] = '## 2. الركائز الاستراتيجية\n\n'
        s['kpis'] = (
            '## 6. مؤشرات\n| # | name | tgt | f | s | freq |\n|---|---|---|---|---|---|\n'
            '| 4 | عدد حوادث تسرب البيانات الحرجة | 100% | '
            '(المنجز / المخطط) × 100 | DLP | m |\n'
        )
        s['confidence'] = (
            '## 7. risk\n| r | p | i | plan | o |\n|---|---|---|---|---|\n'
            '| x | h | h | — | CISO |\n'
        )
        s['traceability'] = (
            '## 13. مصفوفة التتبع\n| fw | cap | gap |\n|---|---|---|\n'
            '| DCC | تصنيف البيانات | مراجعة حسابات متميزة IAM |\n'
        )
        return s

    def test_repaired_sections_pass_acceptance_blob(self):
        repaired, repairs = repair_rel31_canonical_sections(
            self._defect_sections(), lang='ar', domain='cyber')
        self.assertTrue(repairs)
        blob = '\n\n'.join(repaired.get(k, '') for k in repaired if isinstance(repaired.get(k), str))
        defects = run_rel31_acceptance_checks(blob, route='docx')
        self.assertNotIn('missing_pillars_after_heading', defects)
        self.assertNotIn('placeholder_pillar_text_in_objectives', defects)
        self.assertNotIn('generic_kpi_formula', defects)
        self.assertNotIn('empty_risk_treatment', defects)
        self.assertIn('حوكمة ونموذج التشغيل', repaired.get('pillars', ''))

    def test_repaired_markdown_passes_rel3_preview_evidence(self):
        repaired, _ = repair_rel31_canonical_sections(
            self._defect_sections(), lang='ar', domain='cyber')
        blob = '\n\n'.join(
            (repaired.get(k) or '').strip()
            for k in ('vision', 'pillars', 'roadmap', 'kpis',
                      'traceability', 'confidence')
            if (repaired.get(k) or '').strip())
        gate = validate_actual_export_evidence(blob, '', '', route_name='preview')
        rel3_blockers = [
            b.replace('rel2_actual_export_evidence_failed',
                      'rel3_export_evidence_failed')
            for b in gate.get('blocking_errors') or []]
        pillar_blockers = [
            b for b in rel3_blockers
            if 'missing_pillars' in b or 'placeholder_pillar' in b]
        self.assertEqual(pillar_blockers, [], rel3_blockers)


class Rel31BlockerFormatTests(unittest.TestCase):

    def test_blocker_codes_match_contract(self):
        defects = [
            'missing_pillars_after_heading',
            'arabic_residue',
        ]
        blockers = rel31_blockers('docx', defects)
        self.assertIn(
            'rel3_export_evidence_failed:docx:missing_pillars_after_heading',
            blockers)


if __name__ == '__main__':
    unittest.main()
