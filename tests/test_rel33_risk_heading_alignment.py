"""REL3.3 — risk contract heading detection aligned with _split_risk_markdown.

Live staging kept failing ERM with the identical raw guard blocker
(rel33_domain_contamination:الرؤية_والأهداف_الاستراتيجية:cyber_primary) because
the contract's heading detection (^\\s{0,3}#{2,4}) was stricter than the risk
splitter (line.strip().startswith('##')). A heading with >3 leading spaces, 5+
hashes, a tab indent, or no space after the hashes was turned into a section by
the splitter (so the domain guard saw it) yet escaped the contract's detection
(so it passed-without-repair). These tests pin the alignment: every heading the
splitter sections is also seen by the contract, and repair removes it.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_heading_align_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine_v3.domain_codes import normalize_domain_code
from release_engine_v3.rel33_risk_artifact import (
    _split_risk_markdown,
    resolve_rel33_risk_export_artifact,
)
from release_engine_v3.rel33_risk_generation_contract import (
    detect_forbidden_strategy_sections,
    evaluate_risk_export_prep_contract,
    evaluate_risk_generation_contract,
    risk_native_repair,
)

_RISK_BODY = (
    '\n## 3. جدول تقييم المخاطر — سجل المخاطر\n'
    '| الخطر | الاحتمالية |\n|---|---|\n| توقف | متوسطة |\n\n'
    '## 6. جدول استراتيجية المعالجة والضوابط\n'
    '| الضابط | المالك |\n|---|---|\n| خطة | مالك المخاطر |\n| نسخ | لجنة |\n')

# Heading styling variants that the OLD detector missed but the splitter sections.
_VARIANTS = {
    'gt3_leading_spaces': '     ## الرؤية والأهداف الاستراتيجية\nنص\n',
    'five_hashes': '##### خارطة الطريق التنفيذية\nنص\n',
    'no_space_after_hashes': '##الرؤية والأهداف الاستراتيجية\nنص\n',
    'tab_indent': '\t## نموذج الحوكمة والمسؤوليات\nنص\n',
    'bold_wrap': '## **مصفوفة تتبع الأطر المرجعية**\nنص\n',
}


def _norm(d):
    return normalize_domain_code(d, default='') or d


class HeadingAlignmentTests(unittest.TestCase):

    def test_all_variants_detected(self):
        for name, head in _VARIANTS.items():
            self.assertTrue(
                detect_forbidden_strategy_sections(head + _RISK_BODY),
                f'{name}: forbidden heading not detected')

    def test_all_variants_repaired(self):
        for name, head in _VARIANTS.items():
            rep = risk_native_repair(head + _RISK_BODY)
            self.assertEqual(
                detect_forbidden_strategy_sections(rep), [],
                f'{name}: forbidden heading survived repair')
            # risk body preserved
            self.assertIn('سجل المخاطر', rep, name)
            self.assertIn('استراتيجية المعالجة', rep, name)

    def test_splitter_forbidden_keys_are_all_detected(self):
        # Property: any section the splitter mints from a forbidden heading must
        # be caught by the contract (no escape to the domain guard).
        forbidden_bodies = [
            '## الرؤية والأهداف الاستراتيجية\nx\n',
            '     ## خارطة الطريق التنفيذية\nx\n',
            '##### مؤشرات الأداء الرئيسية\nx\n',
            '\t## نموذج الحوكمة\nx\n',
        ]
        for body in forbidden_bodies:
            doc = body + _RISK_BODY
            # every non-register/treatment slug key that came from a forbidden
            # heading must correspond to a detected forbidden heading.
            self.assertTrue(detect_forbidden_strategy_sections(doc), doc[:40])
            self.assertEqual(
                detect_forbidden_strategy_sections(risk_native_repair(doc)), [])

    def test_risk_native_headings_not_flagged(self):
        for head in ('## جدول استراتيجية المعالجة\nx\n',
                     '## خطة المعالجة\nx\n',
                     '## مصفوفة تحديد مستوى الخطورة\nx\n',
                     '## مصفوفة المخاطر\nx\n',
                     '##### سجل المخاطر\nx\n',
                     '     ## مقاييس KRI للمراقبة\nx\n'):
            self.assertEqual(
                detect_forbidden_strategy_sections(head), [], head)

    def test_generation_contract_repairs_indented_vision(self):
        doc = _VARIANTS['gt3_leading_spaces'] + _RISK_BODY
        d = evaluate_risk_generation_contract(
            doc, domain='Enterprise Risk Management', route='gen', emit=False)
        self.assertTrue(d['contract_passed'])
        self.assertTrue(d['forbidden_strategy_sections_detected'])
        self.assertEqual(
            detect_forbidden_strategy_sections(d['content']), [])

    def test_export_prep_repairs_indented_vision(self):
        doc = _VARIANTS['gt3_leading_spaces'] + _RISK_BODY
        p = evaluate_risk_export_prep_contract(
            doc, domain='Enterprise Risk Management', route='docx', risk_id=1,
            emit=False)
        self.assertTrue(p['contract_passed'])
        self.assertTrue(p['export_content_differs_from_saved'])
        self.assertEqual(
            detect_forbidden_strategy_sections(p['content']), [])

    def test_resolver_repairs_indented_vision_saved_artifact(self):
        doc = _VARIANTS['gt3_leading_spaces'] + _RISK_BODY

        def _load(rid, uid):
            return {'id': rid, 'analysis': doc,
                    'domain': 'Enterprise Risk Management',
                    'document_type': 'risk'}

        out = resolve_rel33_risk_export_artifact(
            artifact_id=1, risk_id=1, user_id=1,
            domain='Enterprise Risk Management', route='docx',
            client_content='', load_risk_row=_load,
            load_strategy_risk_row=lambda a, u, domain='': None,
            assemble_sections=lambda s: '\n\n'.join(str(v) for v in s.values()),
            normalize_domain_fn=_norm)
        self.assertTrue(out['content'].strip())
        self.assertTrue(out.get('export_prep_contract_passed'))
        self.assertEqual(
            detect_forbidden_strategy_sections(out['content']), [])
        # the splitter over the repaired content must not mint a vision key
        keys = list(_split_risk_markdown(out['content']).keys())
        self.assertFalse(any('الرؤية' in k or 'خارطة' in k or 'الحوكمة' in k
                             for k in keys), keys)


if __name__ == '__main__':
    unittest.main()
