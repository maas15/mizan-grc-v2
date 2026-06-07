"""PR-REL2 policy and procedure document-type scoring thresholds."""

import unittest

from release_engine.scoring import DOC_TYPE_THRESHOLDS, score_artifact


class PolicyProcedureRel2Tests(unittest.TestCase):

    def _minimal_art(self, doc_type):
        sections = {
            'vision': '## Policy\n\nScope and purpose.\n',
            'pillars': '## Roles\n\nOwner: CISO\n',
            'environment': '## References\n\nNCA ECC.\n',
            'gaps': '## Exceptions\n\nNone.\n',
            'roadmap': '## Review\n\nAnnual.\n',
            'kpis': '## Metrics\n\n| # | M | T |\n|---|---|\n| 1 | Compliance | 95% |\n',
            'confidence': '## Approval\n\n**Confidence score:** 85%\n**Justification:** ok.\n',
        }
        return {
            'sections': sections,
            'final_markdown': '\n\n'.join(sections.values()),
            'sealed': True,
            'blocking_errors': [],
            'quality_flags': {},
        }

    def test_policy_threshold_90(self):
        self.assertEqual(DOC_TYPE_THRESHOLDS['policy'], 90)
        s = score_artifact(
            self._minimal_art('policy'), document_type='policy', lang='en')
        self.assertGreaterEqual(s['total_score'], 75)

    def test_procedure_threshold_88(self):
        self.assertEqual(DOC_TYPE_THRESHOLDS['procedure'], 88)
        s = score_artifact(
            self._minimal_art('procedure'), document_type='procedure', lang='en')
        self.assertGreaterEqual(s['total_score'], 75)


if __name__ == '__main__':
    unittest.main()
