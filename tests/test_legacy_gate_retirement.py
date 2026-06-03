"""PR-REL1 — Known legacy gates must be scoped or diagnostic-only after seal."""

import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_legacy_gate_retirement_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')

from release_hardening.validator_registry import (
    LEGACY_GATE_CLASSIFICATION,
    VALIDATOR_REGISTRY,
    classify_legacy_gate,
)

KNOWN_BLOCKERS = [
    'strategic_objectives_incomplete_row',
    'strategic_objectives_row_schema_violation',
    'strategic_objectives_rows_insufficient',
    'strategic_objectives_section_missing',
    'roadmap_phase_missing_timeline',
    'roadmap_phase_coverage_invalid',
    'cyber_roadmap_balance_missing',
    'prcy74_missing_required_dcc_family',
    'prcy71_final_artifact_missing_required_dcc_roadmap_rows',
    'confidence_score_missing',
    'score_justification_missing',
    'kpi_metric_semantics_invalid',
    'pdf_table_vertical_stack_warnings',
    'docmodel_professional_quality',
]


class LegacyGateRetirementTests(unittest.TestCase):

    def test_all_known_blockers_classified(self):
        for code in KNOWN_BLOCKERS:
            meta = classify_legacy_gate(code)
            self.assertIn(
                meta.get('status'),
                ('scoped', 'diagnostic'),
                msg=f'{code}: {meta!r}')

    def test_no_known_blocker_left_unscoped_unless_diagnostic(self):
        for code in KNOWN_BLOCKERS:
            meta = LEGACY_GATE_CLASSIFICATION.get(code) or classify_legacy_gate(code)
            self.assertNotEqual(meta.get('status'), 'unsafe')

    def test_registry_global_scan_disabled(self):
        for entry in VALIDATOR_REGISTRY.values():
            self.assertTrue(entry.get('global_scan_disabled'))

    def test_so_validator_source_is_canonical_table(self):
        so = VALIDATOR_REGISTRY['strategic_objectives']
        self.assertIn('vision_objectives', so['source'])
        self.assertIn('canonical_table', so['source'])

    def test_pdf_validator_does_not_mutate_sealed(self):
        pdf = VALIDATOR_REGISTRY['pdf_render']
        self.assertFalse(pdf.get('mutates_sealed_content', True))

    @unittest.skipIf(_APP is None, 'app unavailable')
    def test_sealed_artifact_has_rel1_envelope(self):
        from domains.cyber.fixtures_ar import technical_sections
        sections = technical_sections()
        order = ('vision', 'pillars', 'environment', 'gaps',
                 'roadmap', 'kpis', 'confidence')
        content = '\n\n'.join(sections[k] for k in order if sections.get(k))
        art = _APP._build_cyber_final_strategy_artifact(
            content,
            sections=dict(sections),
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='generation',
            doc_subtype='technical',
        )
        self.assertTrue(art.get('sealed'))
        canon = art.get('rel1_canonical') or {}
        self.assertEqual(canon.get('domain'), 'cyber')
        self.assertTrue(canon.get('sealed'))
        self.assertEqual(canon.get('blocking_errors') or [], [])

    @unittest.skipIf(_APP is None, 'app unavailable')
    def test_roadmap_trace_row_not_so_blocker_after_seal(self):
        from domains.cyber.fixtures_ar import technical_sections
        sections = technical_sections()
        order = ('vision', 'pillars', 'environment', 'gaps',
                 'roadmap', 'kpis', 'confidence')
        content = '\n\n'.join(sections[k] for k in order if sections.get(k))
        art = _APP._build_cyber_final_strategy_artifact(
            content,
            sections=dict(sections),
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type='generation',
        )
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(
            art.get('sections') or {}, 'ar')
        self.assertFalse(
            any('strategic_objectives_incomplete_row:1' in (i or '')
                for i in issues))

    @unittest.skipIf(_APP is None, 'app unavailable')
    def test_final_artifact_blocker_registry_maps_to_scoped(self):
        reg = _APP._FINAL_ARTIFACT_BLOCKER_REGISTRY
        for key in (
            'strategic_objectives_incomplete_row',
            'roadmap_phase_missing_timeline',
            'confidence_score_missing',
        ):
            self.assertIn(key, reg)
            meta = classify_legacy_gate(reg[key].get('blocker') or key)
            self.assertIn(meta.get('status'), ('scoped', 'diagnostic'))


if __name__ == '__main__':
    unittest.main()
