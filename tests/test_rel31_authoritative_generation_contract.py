"""PR-REL3.1 — authoritative generation contract tests."""

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel31_contract_')
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

from release_engine.pillar_model import _build_canonical_pillars
from release_engine_v3.rel31_authority import (
    apply_rel31_authoritative_contract,
    emit_rel3_generation_contract,
    rel31_fingerprint_extension,
    rel31_user_facing_error,
    validate_rel3_objectives,
    validate_rel3_roadmap_output_quality,
)

_ROADMAP = (
    '## 5. خارطة الطريق\n\n| المرحلة | الإطار | المبادرة | المالك | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    + '\n'.join([
        '| 1 | 1-6 | تأسيس CISO ولجنة حوكمة | CISO / الإدارة العليا | هيكل CISO معتمد | ECC |',
        '| 2 | 7-18 | تشغيل SOC SIEM | مدير SOC | مركز SOC تشغيلي | ECC |',
        '| 2 | 7-18 | IAM PAM MFA | مدير IAM/PAM | منصة IAM مع MFA | ECC |',
        '| 2 | 7-18 | CSIRT استجابة | قائد CSIRT | فريق CSIRT جاهز | ECC |',
        '| 2 | 7-18 | إدارة ثغرات | مدير الثغرات | برنامج ثغرات SLA | ECC |',
        '| 2 | 7-18 | توعية أمنية | مدير التوعية | خطة توعية سنوية | ECC |',
        '| 2 | 7-18 | DR نسخ احتياطي | مدير استمرارية الأعمال | خطة DR مختبرة | ECC |',
        '| 1 | 1-6 | تصنيف بيانات | مدير حماية البيانات | سجل بيانات مصنف | DCC |',
        '| 2 | 7-18 | تشفير مفاتيح | مدير حماية البيانات | ضوابط KMS مطبقة | DCC |',
        '| 2 | 7-18 | DLP تسرب | مدير حماية البيانات | منصة DLP مفعّلة | DCC |',
        '| 3 | 19-24 | معالجة بيانات حساسة | مدير حماية البيانات | إجراءات معالجة معتمدة | DCC |',
    ])
)

_GOOD_SECTIONS = {
    'vision': (
        '## 1. الأهداف\n\n| # | الهدف | المستهدف | المبرر | الإطار |\n'
        '|---|---|---|---|---|\n'
        + '\n'.join(
            f'| {i} | هدف {i} governance soc iam | مستهدف {i} | مبرر | ECC |'
            for i in range(1, 7)
        )
    ),
    'pillars': _build_canonical_pillars('ar'),
    'roadmap': _ROADMAP,
    'kpis': (
        '## 6. مؤشرات\n| # | وصف المؤشر | القيمة | صيغة | مصدر | تواتر |\n'
        '|---|---|---|---|---|---|\n| 1 | MTTD | 30 | f | s | m |\n'
    ),
    'confidence': (
        '## 7. risk\n| r | p | i | plan | o |\n|---|---|---|---|---|\n'
        '| x | h | h | action | CISO |\n'
    ),
}


def _backend():
    if _APP is None:
        return {}
    return _APP._rel31_backend_callables()


class Rel31AuthoritativeGenerationTests(unittest.TestCase):

    def test_01_fingerprint_includes_rel3_authoritative(self):
        ext = rel31_fingerprint_extension({'rel3': True, 'rel31': True})
        self.assertTrue(ext['rel3'])
        self.assertTrue(ext['rel31'])
        self.assertTrue(ext['rel3_authoritative'])
        self.assertFalse(ext['legacy_rel2_authoritative'])
        self.assertFalse(ext['legacy_prcy_export_contract_authoritative'])

    def test_02_runtime_fingerprint_payload_has_rel3_authoritative(self):
        payload = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        self.assertTrue(payload.get('rel3_authoritative'))
        self.assertIn('python_version', payload)

    def test_03_legacy_so_blocker_translated_to_rel3_objectives(self):
        art = {
            'sections': dict(_GOOD_SECTIONS),
            'domain': 'cyber',
            'sealed': False,
            'blocking_errors': [
                'cyber_board_ready_so_failed:so_count_or_duplicates_or_target_like'],
            'contract_meta': {'lang': 'ar'},
        }
        out = apply_rel31_authoritative_contract(
            art, backend=_backend(),
            flags={'rel3': True, 'rel31': True})
        contract = out.get('rel31_generation_contract') or {}
        user_errs = contract.get('blocking_errors') or []
        for b in user_errs:
            self.assertNotIn('cyber_board_ready_so_failed', b)
        self.assertTrue(contract.get('generation_save_allowed'), contract)

    def test_04_roadmap_weak_output_repaired_before_freeze(self):
        weak_road = _ROADMAP.replace('هيكل CISO معتمد', 'مخرج تشغيلي')
        sections = dict(_GOOD_SECTIONS)
        sections['roadmap'] = weak_road
        val = validate_rel3_roadmap_output_quality(sections, backend=_backend())
        self.assertTrue(val.get('valid'), val.get('defects'))

    def test_05_generation_contract_emitted(self):
        contract = {
            'artifact_id': 'a1',
            'generation_save_allowed': True,
            'blocking_errors': [],
        }
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            emit_rel3_generation_contract(contract)
        self.assertIn('[REL3-GENERATION-CONTRACT]', buf.getvalue())
        self.assertIn('a1', buf.getvalue())

    def test_06_user_message_not_legacy_blocker(self):
        msg = rel31_user_facing_error(
            ['cyber_board_ready_so_failed:x'], lang='ar')
        self.assertNotIn('cyber_board_ready', msg)
        self.assertIn('الأهداف', msg)

    def test_07_failing_fixture_blocks_with_rel3_blocker(self):
        bad = {
            'sections': {'vision': '## 1\n\nno table', 'roadmap': '## 5\n\nempty'},
            'domain': 'cyber',
            'blocking_errors': [],
            'contract_meta': {'lang': 'ar'},
        }
        out = apply_rel31_authoritative_contract(
            bad, backend=_backend(),
            flags={'rel3': True, 'rel31': True})
        contract = out.get('rel31_generation_contract') or {}
        self.assertFalse(contract.get('generation_save_allowed'))
        errs = contract.get('blocking_errors') or []
        self.assertTrue(
            any('rel3_generation_contract_failed' in e for e in errs))


if __name__ == '__main__':
    unittest.main()
