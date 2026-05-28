"""PR-CY22 — Cyber strategy final exported document audit.

These tests cover the LAST-MILE export audit that runs immediately
before PDF / DOCX / preview rendering (see ``_cyber_final_export_audit``
in ``app.py``). They focus on the new behaviours introduced in
PR-CY22 — the regulator guard, the dash-only orphan-row strip, the
content-splice contract, the snapshot diagnostic, and the blank-page
sanitizer applied to the ReportLab story.

PR-CY18 specialized-objective preservation and PR-CY20 framework-
compliance objective preservation are NOT exercised here and MUST
remain untouched by this PR.
"""
import functools
import importlib.util
import io
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_final_export_audit_prcy22_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP_DB_DIR, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('ANTHROPIC_API_KEY', '')
os.environ.setdefault('GOOGLE_API_KEY', '')


_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_CYBER_CONTENT_AR = """## 1. الرؤية الاستراتيجية

نص الرؤية هنا.

## 2. الركائز الاستراتيجية

الركائز.

## 5. خارطة الطريق

### المرحلة 1

| # | المبادرة | الشهر | المالك |
|---|----------|------|--------|
| 1 | حوكمة الأمن | 1-6 | CISO |

### المرحلة 3

| # | المبادرة | الشهر | المالك |
|---|----------|------|--------|
| 1 | عمليات SOC | 31-36 | SOC |

#### معايير النجاح للمرحلة 3
- مركز عمليات.

| # | المبادرة | الشهر | المالك |
|---|----------|-------|--------|
| 1 | تصنيف البيانات | — | فريق |
| 2 | PAM/IAM | - | فريق |

## 6. مؤشرات الأداء الرئيسية

| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب | مصدر البيانات/الأداة | الإطار الزمني |
|---|------------|-------------------|----------------|----------------------|----------------|
| 1 | KPI: زمن الاستجابة | 95% | (الحوادث المغلقة / الكل) * 100 | SIEM | ربع سنوي |

## 7. تقييم الثقة

نص الثقة.

تنظمها هيئة الاتصالات وتقنية المعلومات بناءً على تفويض CITC.
"""


class FinalExportAuditPRCY22Tests(unittest.TestCase):

    # ── (A) Snapshot diagnostic ────────────────────────────────────────
    @_skip_if_no_app
    def test_final_audit_emits_snapshot_diagnostic(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        self.assertIn('snapshot_before', diag)
        self.assertIn('snapshot_after', diag)
        self.assertIn('content_len_before', diag)
        self.assertIn('content_len_after', diag)
        self.assertIsInstance(sections, dict)

    # ── (G) Regulator guard ───────────────────────────────────────────
    @_skip_if_no_app
    def test_regulator_guard_replaces_citc_cst_haya_for_ecc(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        self.assertNotIn('هيئة الاتصالات وتقنية المعلومات', new_content)
        self.assertNotIn('CITC', new_content)
        self.assertNotIn('CST', new_content)
        self.assertIn('الهيئة الوطنية للأمن السيبراني', new_content)

    @_skip_if_no_app
    def test_regulator_guard_noop_when_no_nca_framework_selected(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['NDMO'],  # NOT an NCA framework
            lang='ar',
            domain='cyber',
        )
        # No replacement should have occurred.
        self.assertIn('هيئة الاتصالات', new_content)
        self.assertEqual(diag.get('regulator_guard', {}), {})

    @_skip_if_no_app
    def test_regulator_guard_idempotent(self):
        new_content, _, _ = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC', 'DCC'],
            lang='ar',
            domain='cyber',
        )
        new_content2, _, diag2 = _APP._cyber_final_export_audit(
            new_content,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC', 'DCC'],
            lang='ar',
            domain='cyber',
        )
        self.assertEqual(diag2.get('regulator_guard', {}), {})
        self.assertNotIn('CITC', new_content2)
        self.assertNotIn('هيئة الاتصالات وتقنية المعلومات', new_content2)

    # ── No-op for non-cyber domain ────────────────────────────────────
    @_skip_if_no_app
    def test_noop_for_non_cyber_domain(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'data'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='data',
        )
        self.assertEqual(new_content, _CYBER_CONTENT_AR)
        self.assertEqual(diag, {})

    # ── (C) Dash-only orphan row strip ────────────────────────────────
    @_skip_if_no_app
    def test_dash_only_orphan_rows_stripped_after_phased_roadmap(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        # PR-CY31 — the dash-only ``| 1 | تصنيف البيانات |`` orphan row
        # in the inbound fixture must be dropped from the final
        # roadmap. The canonical rebuild may then re-introduce "تصنيف
        # البيانات" as part of a properly-phased Phase 2 activity
        # (e.g. ``تطبيق تصنيف البيانات وفق ضوابط DCC``); that is the
        # accepted PR-CY31 behaviour and must NOT be flagged as an
        # orphan row.
        roadmap = sections.get('roadmap', '')
        # The orphan dash-only row variant must not survive.
        self.assertNotIn('| 1 | تصنيف البيانات |', new_content)
        self.assertNotIn('| 1 | PAM/IAM |', new_content)
        # The strip counter (PR-CY22 dash-only OR PR-CY21 orphan-flat)
        # should reflect that at least one orphan row got dropped.
        total_dropped = (
            int(diag.get('roadmap_dash_only_dropped', 0) or 0)
            + int(((diag.get('consistency') or {})
                   .get('roadmap_orphan_flat_dropped', 0)) or 0)
        )
        self.assertGreaterEqual(total_dropped, 1)

    # ── (A) Splicing preserves audited content ────────────────────────
    @_skip_if_no_app
    def test_content_splice_writes_audited_sections_back(self):
        new_content, sections, diag = _APP._cyber_final_export_audit(
            _CYBER_CONTENT_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
        )
        # Sanity: returned content still carries the major H2 anchors.
        for anchor in (
            'الرؤية الاستراتيجية',
            'خارطة الطريق',
            'مؤشرات الأداء الرئيسية',
            'تقييم الثقة',
        ):
            self.assertIn(anchor, new_content)
        # The roadmap section in the spliced content must mirror what
        # we hold in ``sections`` (the audited body).
        self.assertIn(sections.get('roadmap', '').strip(), new_content)

    # ── (H) Blank-page sanitizer ──────────────────────────────────────
    @_skip_if_no_app
    def test_blank_pdf_pages_collapsed_and_trailing_dropped(self):
        try:
            from reportlab.platypus import PageBreak, Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
        except Exception as _e:  # pragma: no cover
            self.skipTest(f'reportlab unavailable: {_e}')
        styles = getSampleStyleSheet()
        story = [
            Paragraph('A', styles['Normal']),
            PageBreak(),
            PageBreak(),  # consecutive — should collapse to one
            PageBreak(),  # consecutive — should collapse
            Paragraph('B', styles['Normal']),
            PageBreak(),  # trailing — should be dropped
        ]
        new_story, dropped = _APP._prcy22_strip_blank_pdf_pages(story)
        self.assertEqual(dropped, 3)
        # Final story should be Paragraph, PageBreak, Paragraph
        kinds = [type(fl).__name__ for fl in new_story]
        self.assertEqual(
            kinds, ['Paragraph', 'PageBreak', 'Paragraph']
        )

    @_skip_if_no_app
    def test_blank_pdf_pages_noop_when_no_breaks(self):
        try:
            from reportlab.platypus import Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
        except Exception as _e:  # pragma: no cover
            self.skipTest(f'reportlab unavailable: {_e}')
        styles = getSampleStyleSheet()
        story = [Paragraph('A', styles['Normal'])]
        new_story, dropped = _APP._prcy22_strip_blank_pdf_pages(story)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(new_story), 1)

    # ── (B) Horizon parsing is exercised by PR-CY21's own suite —
    # PR-CY22 only ensures the audited content reaches the renderer.
    # See ``tests/test_cyber_final_document_audit_prcy21.py`` for the
    # executive-summary horizon (defect B) coverage.


if __name__ == '__main__':
    unittest.main()
