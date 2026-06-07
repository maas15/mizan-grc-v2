"""PR-REL2 risk register and audit/assessment output requirements."""

import unittest

from domain_packs import get_domain_pack
from release_engine.scoring import DOC_TYPE_THRESHOLDS, score_artifact


class RiskAuditOutputsRel2Tests(unittest.TestCase):

    def test_domain_audit_requirements_present(self):
        for code in ('cyber', 'data_management', 'erm'):
            pack = get_domain_pack(code)
            req = pack.get('audit_risk_roadmap_requirements') or {}
            self.assertIn('audit', req)
            self.assertIn('risk_register', req)

    def test_risk_register_threshold(self):
        self.assertEqual(DOC_TYPE_THRESHOLDS['risk_register'], 90)

    def test_audit_scoring_runs(self):
        art = {
            'sections': {
                'vision': '## Audit scope\n\nScope text.\n',
                'pillars': '## Criteria\n\nISO 27001.\n',
                'environment': '## Evidence\n\nLogs.\n',
                'gaps': '## Findings\n\n| # | F | S |\n|---|---|\n| 1 | Gap | High |\n',
                'roadmap': '## Remediation\n\n| P | A | M |\n|---|---|\n| S | Fix | 0-3 months |\n',
                'kpis': '## Metrics\n\n| # | M | T |\n|---|---|\n| 1 | Close rate | 100% |\n',
                'confidence': '## Opinion\n\n**Confidence score:** 88%\n**Justification:** ok.\n',
            },
            'sealed': True,
            'blocking_errors': [],
        }
        s = score_artifact(art, document_type='audit', lang='en')
        self.assertIn('risk_quality', s['dimension_scores'])


if __name__ == '__main__':
    unittest.main()
