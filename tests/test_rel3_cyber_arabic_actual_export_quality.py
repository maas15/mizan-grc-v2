"""PR-REL3 — Cyber Arabic Technical actual export quality."""

import os
import sys
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix='test_rel3_cyber_ar_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from release_engine.pillar_model import _build_canonical_pillars
from release_engine_v3.canonical_document import build_final_document_artifact, freeze_artifact
from release_engine_v3.orchestrator import (
    clear_rel3_caches,
    rel3_build_render_tree,
    rel3_export_with_evidence,
)

_PILLARS = _build_canonical_pillars('ar')

_ROADMAP = (
    '## 5. خارطة الطريق\n\n| المرحلة | الإطار | المبادرة | المالك | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    + '\n'.join([
        '| 1 | 1-6 | تأسيس CISO ولجنة حوكمة | CISO / الإدارة العليا | هيكل CISO | ECC |',
        '| 1 | 1-6 | تفعيل لجنة حوكمة | CISO / الإدارة العليا | ميثاق | ECC |',
        '| 2 | 7-18 | تشغيل SOC SIEM | مدير SOC | مركز SOC | ECC |',
        '| 2 | 7-18 | IAM PAM MFA | مدير IAM/PAM | MFA | ECC |',
        '| 2 | 7-18 | CSIRT استجابة | قائد CSIRT | فريق CSIRT | ECC |',
        '| 2 | 7-18 | إدارة ثغرات | مدير الثغرات | برنامج | ECC |',
        '| 2 | 7-18 | توعية أمنية | مدير التوعية | خطة | ECC |',
        '| 2 | 7-18 | DR نسخ احتياطي | مدير استمرارية الأعمال | DR | ECC |',
        '| 1 | 1-6 | تصنيف بيانات | مدير حماية البيانات | سجل | DCC |',
        '| 2 | 7-18 | تشفير مفاتيح | مدير حماية البيانات | KMS | DCC |',
        '| 2 | 7-18 | DLP تسرب | مدير حماية البيانات | DLP | DCC |',
        '| 3 | 19-24 | معالجة بيانات حساسة | مدير حماية البيانات | إجراءات | DCC |',
    ])
)

_KPI = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر | تواتر |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | MTTD | ≤ 30 دقيقة | (المكتشف/الإجمالي)×100 | SOC | ش |\n'
    '| 2 | MTTR | ≤ 4 ساعات | (المغلق/الإجمالي)×100 | SOC | ش |\n'
    '| 3 | DLP coverage | 95% | (المغطى/الحرج)×100 | DLP | ش |\n\n'
    '### صيغ KPI\n| # | صيغة |\n|---|---|\n| 1 | f1 |\n| 2 | f2 |\n| 3 | f3 |\n'
)

_RISK = (
    '## 7. المخاطر\n\n'
    '| المخاطرة | احتمال | أثر | المعالجة | المالك |\n|---|---|---|---|---|\n'
    '| تصيد | عالي | عالي | برنامج توعية ربع سنوي | CISO |\n'
    '| IAM | متوسط | عالي | MFA/PAM | مدير IAM/PAM |\n'
    '| تسرب | عالي | عالي | DLP وتصنيف | مدير حماية البيانات |\n'
)

_TRACE = (
    '## 8. التتبع\n\n| متطلب | فجوة | مبادرة |\n|---|---|---|\n'
    '| DCC حماية البيانات | ضعف حماية البيانات أثناء النقل والتخزين | تشفير |\n'
    '| DCC DLP | ضعف ضوابط منع تسرب البيانات | DLP |\n'
    '| ECC الاستجابة | غياب فريق CSIRT | CSIRT |\n'
)

_GOOD_MD = (
    '## 1. الرؤية\n\nنص.\n'
    + _PILLARS + '\n'
    + '## 3. البيئة\n\nنص.\n'
    + '## 4. الفجوات\n\nنص.\n'
    + _ROADMAP + '\n'
    + _KPI + '\n'
    + _RISK + '\n'
    + _TRACE
)

_SECTIONS = {
    'vision': '## 1. الرؤية\n\nنص.\n',
    'pillars': _PILLARS,
    'environment': '## 3. البيئة\n\nنص.\n',
    'gaps': '## 4. الفجوات\n\nنص.\n',
    'roadmap': _ROADMAP,
    'kpis': _KPI,
    'confidence': _RISK,
    'traceability': _TRACE,
}


def _backend_good():
    return {
        'build_docx_bytes': lambda content, *a, **k: content.encode('utf-8'),
        'build_pdf_bytes': lambda content, **k: content.encode('utf-8'),
        'split_sections': lambda x: _SECTIONS,
    }


class Rel3CyberArabicExportQualityTests(unittest.TestCase):

    def setUp(self):
        clear_rel3_caches()

    def _frozen(self):
        art = build_final_document_artifact({
            'sections': _SECTIONS,
            'final_markdown': _GOOD_MD,
            'domain': 'cyber',
            'sealed': True,
            'blocking_errors': [],
            'contract_meta': {'lang': 'ar', 'domain': 'cyber'},
        })
        return freeze_artifact(art)

    def test_01_valid_preview_export(self):
        art = self._frozen()
        export, ev = rel3_export_with_evidence(
            'preview', art, backend=_backend_good())
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)

    def test_02_valid_docx_export(self):
        art = self._frozen()
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=_backend_good(),
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)
        self.assertTrue(ev.returned_equals_evidence_bytes)
        self.assertTrue(ev.exact_bytes_checked)

    def test_03_valid_pdf_export(self):
        art = self._frozen()
        export, ev = rel3_export_with_evidence(
            'pdf', art, backend=_backend_good(),
            export_kwargs={'lang': 'ar'})
        self.assertTrue(ev.export_return_allowed, ev.blocking_errors)

    def test_04_render_tree_has_all_sections(self):
        art = self._frozen()
        tree = rel3_build_render_tree(art)
        keys = {n['section_key'] for n in tree.nodes}
        for req in ('pillars', 'roadmap', 'kpi_kri', 'confidence_risk'):
            self.assertIn(req, keys)

    def test_05_same_render_tree_hash_all_routes(self):
        art = self._frozen()
        t = rel3_build_render_tree(art)
        h = t.render_tree_hash
        for route in ('preview', 'docx', 'pdf'):
            export, _ = rel3_export_with_evidence(
                route, art, backend=_backend_good(),
                export_kwargs={'filename': 's.docx', 'lang': 'ar'})
            self.assertEqual(export.render_tree_hash, h)

    def test_06_extracted_docx_has_pillars(self):
        art = self._frozen()
        export, ev = rel3_export_with_evidence(
            'docx', art, backend=_backend_good(),
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        text = export.docx_bytes.decode('utf-8')
        for name in (
            'حوكمة ونموذج التشغيل',
            'الحماية والكشف والاستجابة',
            'الهوية وحماية البيانات',
            'المرونة واستمرارية الأعمال',
        ):
            self.assertIn(name, text)

    def test_07_failed_export_no_return_allowed(self):
        art = self._frozen()
        _MISSING = '## 2. الركائز\n\n### حوكمة\n\nنص.\n'
        bad_backend = {
            'build_docx_bytes': lambda *a, **k: _MISSING.encode('utf-8'),
            'split_sections': lambda x: _SECTIONS,
        }
        _, ev = rel3_export_with_evidence(
            'docx', art, backend=bad_backend,
            export_kwargs={'filename': 's.docx', 'lang': 'ar'})
        self.assertFalse(ev.export_return_allowed)


if __name__ == '__main__':
    unittest.main()
