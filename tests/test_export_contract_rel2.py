"""PR-REL2 export contract — hash parity, no post-seal mutation."""

import unittest

from release_engine.export_contract import (
    assert_export_hash_parity,
    read_only_export_meta,
)


class ExportContractRel2Tests(unittest.TestCase):

    def test_hash_parity_sealed(self):
        art = {'sealed': True, 'final_hash': 'deadbeef'}
        issues = assert_export_hash_parity(
            art, route='preview', content_hash='deadbeef')
        self.assertEqual(issues, [])

    def test_hash_mismatch_blocked(self):
        art = {'sealed': True, 'final_hash': 'aaa'}
        issues = assert_export_hash_parity(
            art, route='docx', content_hash='bbb')
        self.assertTrue(any('hash_mismatch' in i for i in issues))

    def test_read_only_meta_no_mutation(self):
        art = {'sealed': True, 'final_hash': 'h1'}
        meta = read_only_export_meta(art)
        self.assertFalse(meta['mutates_content'])
        self.assertEqual(meta['display_hash'], 'h1')


if __name__ == '__main__':
    unittest.main()
