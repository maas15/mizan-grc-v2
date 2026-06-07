"""PR-REL2 domain packs — six domains, terminology, frameworks."""

import unittest

from domain_packs import DOMAIN_PACKS, get_domain_pack
from framework_catalogs import FRAMEWORK_CATALOG


class DomainPacksRel2Tests(unittest.TestCase):

    def test_six_production_packs(self):
        for code in (
            'cyber', 'data_management', 'artificial_intelligence',
            'digital_transformation', 'enterprise_risk_management',
            'global_standards',
        ):
            pack = get_domain_pack(code)
            self.assertIsNotNone(pack, code)
            self.assertEqual(pack.get('pack_version'), 'rel2')
            self.assertTrue(pack.get('mandatory_canonical_sections'))
            self.assertTrue(pack.get('terminology_en'))
            self.assertTrue(pack.get('terminology_ar'))

    def test_framework_catalog_minimum_entries(self):
        ids = {e['framework_id'] for e in FRAMEWORK_CATALOG}
        for fid in (
            'nca_ecc', 'nca_dcc', 'ndmo', 'dga', 'iso_27001',
            'nist_csf_2', 'nist_ai_rmf', 'iso_31000',
        ):
            self.assertIn(fid, ids)

    def test_catalog_granularity_when_no_control_id(self):
        for entry in FRAMEWORK_CATALOG:
            if not entry.get('control_id'):
                self.assertEqual(
                    entry.get('coverage_granularity'), 'capability_family')

    def test_registry_aliases(self):
        self.assertIs(get_domain_pack('cyber_security'), get_domain_pack('cyber'))
        self.assertEqual(len(DOMAIN_PACKS), 12)


if __name__ == '__main__':
    unittest.main()
