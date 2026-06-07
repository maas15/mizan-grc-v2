"""PR-REL2 — legacy gate retirement (extends REL1 classification)."""

import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_legacy_gate_retirement_rel2_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

from release_engine.validator_registry import (
    LEGACY_GATE_CLASSIFICATION,
    REL2_CONTENT_VALIDATORS,
    REL2_EXPORT_ONLY_VALIDATORS,
    VALIDATOR_REGISTRY,
    classify_legacy_gate,
)
from release_hardening.validator_registry import classify_legacy_gate as rel1_classify

KNOWN_BLOCKERS = [
    'strategic_objectives_incomplete_row',
    'strategic_objectives_row_schema_violation',
    'roadmap_phase_missing_timeline',
    'cyber_roadmap_balance_missing',
    'confidence_score_missing',
    'score_justification_missing',
    'kpi_metric_semantics_invalid',
    'pdf_table_vertical_stack_warnings',
    'pdf_table_vertical_stack_unresolved',
    'docmodel_professional_quality',
]


class LegacyGateRetirementRel2Tests(unittest.TestCase):

    def test_rel2_content_validators_scoped(self):
        for name in REL2_CONTENT_VALIDATORS:
            entry = VALIDATOR_REGISTRY[name]
            self.assertTrue(entry.get('global_scan_disabled'), msg=name)
            self.assertTrue(
                entry['source'].startswith('sections.'),
                msg=f'{name}: {entry["source"]}',
            )

    def test_export_validators_layout_only(self):
        for name in REL2_EXPORT_ONLY_VALIDATORS:
            entry = VALIDATOR_REGISTRY[name]
            self.assertFalse(entry.get('mutates_sealed_content', True), msg=name)

    def test_all_known_blockers_classified(self):
        for code in KNOWN_BLOCKERS:
            meta = classify_legacy_gate(code) or rel1_classify(code)
            status = meta.get('status')
            self.assertIn(
                status,
                ('scoped', 'diagnostic', 'export_only'),
                msg=f'{code}: {meta!r}')

    def test_no_unscoped_unsafe_known_blockers(self):
        for code in KNOWN_BLOCKERS:
            meta = LEGACY_GATE_CLASSIFICATION.get(code) or classify_legacy_gate(code)
            self.assertNotEqual(meta.get('status'), 'unsafe', msg=code)

    def test_final_quality_contract_is_single_gate(self):
        from release_engine.final_quality_contract import evaluate_final_quality
        art = {
            'sealed': True,
            'sections': {'vision': '## 1\n\n| # | O | M | R | T |\n|---|---|---|---|---|\n| 1 | a | b | c | d |\n| 2 | e | f | g | h |\n| 3 | i | j | k | l |\n',
                        'pillars': '## 2\n\np\n', 'environment': '## 3\n\ne\n',
                        'gaps': '## 4\n\ng\n', 'roadmap': '## 5\n\n| P | I | M |\n|---|---|---|\n| S | x | 0-6 months |\n| M | y | 7-12 months |\n| L | z | 13-24 months |\n',
                        'kpis': '## 6\n\n| # | K | T |\n|---|---|\n| 1 | k | 90% |\n| 2 | l | 80% |\n',
                        'confidence': '## 7\n\n**Confidence score:** 80%\n**Justification:** ok.\n'},
            'final_markdown': '',
            'blocking_errors': [],
            'quality_flags': {'strategic_objectives_valid': True},
            'final_hash': 'abc',
        }
        art['final_markdown'] = '\n\n'.join(art['sections'].values())
        result = evaluate_final_quality(art, document_type='strategy', lang='en')
        self.assertIn('release_ready_final_passed', result)


if __name__ == '__main__':
    unittest.main()
