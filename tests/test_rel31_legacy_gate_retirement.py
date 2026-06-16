"""PR-REL3.1 — legacy gate retirement after REL3 authority."""

import importlib.util
import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel31_legacy_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine_v3.rel31_authority import (
    guard_legacy_gate_after_freeze,
    translate_legacy_blocker,
)


class Rel31LegacyGateRetirementTests(unittest.TestCase):

    def test_01_legacy_gate_after_freeze_blocked(self):
        err = guard_legacy_gate_after_freeze(True, 'rel2_preview')
        self.assertEqual(err, 'rel3_legacy_gate_after_freeze:rel2_preview')

    def test_02_no_block_when_not_frozen(self):
        self.assertIsNone(guard_legacy_gate_after_freeze(False, 'rel2_preview'))

    def test_03_translate_so_legacy_blocker(self):
        t = translate_legacy_blocker(
            'cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like')
        self.assertEqual(t, 'rel3_generation_contract_failed:objectives')

    def test_04_translate_roadmap_weak_output(self):
        t = translate_legacy_blocker(
            'rel2_actual_export_evidence_failed:preview:roadmap_weak_output')
        self.assertIn('roadmap', t)

    def test_05_rel31_flag_enabled(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('rel31'))

    def test_06_rel31_is_authoritative_cyber_ar(self):
        self.assertTrue(_APP._rel31_is_authoritative('cyber', 'ar'))

    def test_07_legacy_rel2_not_authoritative_when_rel31(self):
        ext = _APP._prcy37_runtime_build_fingerprint_payload()
        if ext.get('rel31'):
            self.assertFalse(ext.get('legacy_rel2_authoritative'))

    def test_08_generation_does_not_use_legacy_blockers_as_final(self):
        from release_engine_v3.rel31_authority import apply_rel31_authoritative_contract
        from release_engine.pillar_model import _build_canonical_pillars
        art = {
            'sections': {
                'vision': '## 1\n| # | o | t | r | f |\n|---|---|---|---|---|\n'
                + '\n'.join(f'| {i} | obj {i} | t | r | ECC |' for i in range(1, 7)),
                'pillars': _build_canonical_pillars('ar'),
                'roadmap': '## 5\n| p | t | i | o | out | f |\n|---|---|---|---|---|---|\n'
                + '\n'.join(
                    f'| 1 | 1-6 | init {j} CISO | CISO / الإدارة العليا | out {j} | ECC |'
                    for j in range(1, 12)),
            },
            'domain': 'cyber',
            'blocking_errors': [
                'rel2_actual_export_evidence_failed:preview:roadmap_weak_output'],
            'contract_meta': {'lang': 'ar'},
        }
        out = apply_rel31_authoritative_contract(
            art, backend=_APP._rel31_backend_callables(),
            flags={'rel3': True, 'rel31': True})
        final = out.get('blocking_errors') or []
        for b in final:
            self.assertFalse(b.startswith('rel2_actual_export_evidence_failed'))
            self.assertFalse(b.startswith('cyber_board_ready_so_failed'))


if __name__ == '__main__':
    unittest.main()
