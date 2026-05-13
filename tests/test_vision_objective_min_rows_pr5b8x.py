"""PR-5B.8X — Vision/Strategic-Objectives minimum-row enforcement during
the selected-framework compliance-objective AI repair.

These tests fix the regression where the framework-compliance objective
repair could overwrite a 6-row vision with a 4-row vision (because the
AI repair call did not pass ``min_rows`` and only the compliance-
objective presence was re-validated).  The post-normalization save gate
then surfaced the failure as ``vision_so_rows=4 (need >= 6)``.

Required by the problem statement:

  1. Arabic consulting vision with 6 valid objective rows passes.
  2. Arabic consulting vision with 4 valid objective rows fails with
     ``vision_so_rows`` / below minimum.
  3. selected-framework compliance objective repair requests
     ``min_rows=6`` (not the schema default of 5).
  4. Repaired vision with only 4 rows is rejected and original vision
     remains unchanged (fail-closed, AI-first).
  5. Repaired vision with 6 rows including ECC/TCC compliance objective
     passes.
  6. ``count_valid_objective_rows`` does not reject valid Arabic rows
     with proper timeframe.
  7. Framework-compliance repair must not reduce existing valid
     objective count.
  8. Drafting mode preserves its intended lower threshold.
  9. No deterministic objective rows are inserted by the repair path.
 10. PDF/export/auth/DB are untouched by the change.

Run:
    python -m pytest tests/test_vision_objective_min_rows_pr5b8x.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_vision_min_rows_pr5b8x_')
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
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Vision fixtures ───────────────────────────────────────────────────────
_VISION_AR_6_ROWS_WITH_COMPLIANCE = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني رائدة على المستوى الوطني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تعزيز إدارة الهوية والوصول المميز IAM/PAM | تغطية 100% | حوكمة | 12 شهراً |\n'
    '| 2 | تحقيق الالتزام بضوابط NCA ECC وNCA TCC | نسبة امتثال ≥ 90% '
    'للضوابط المختارة | مواءمة برنامج الأمن السيبراني | 12 شهراً |\n'
    '| 3 | تطوير مركز العمليات الأمنية SOC والمراقبة | 24/7 | الكشف المبكر '
    '| 9 أشهر |\n'
    '| 4 | الاستجابة للحوادث وإدارة الثغرات | < 4 ساعات | تقليل الأثر '
    '| 6 أشهر |\n'
    '| 5 | تأمين الوصول عن بُعد عبر VPN و MFA | 100% MFA | حماية '
    '| 9 أشهر |\n'
    '| 6 | تعزيز التوعية والتدريب ضد التصيد | 95% إكمال | بشري | 12 شهراً |\n'
)

_VISION_AR_4_ROWS_WITH_COMPLIANCE = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تحقيق الالتزام بضوابط NCA ECC وNCA TCC | ≥ 90% امتثال '
    '| تنظيمي | 12 شهراً |\n'
    '| 2 | تطوير SOC | 24/7 | كشف | 9 أشهر |\n'
    '| 3 | الاستجابة للحوادث | < 4 ساعات | احتواء | 6 أشهر |\n'
    '| 4 | التوعية والتدريب | 95% | بشري | 12 شهراً |\n'
)

_VISION_AR_6_ROWS_NO_COMPLIANCE = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** بناء قدرات أمن سيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | تعزيز IAM/PAM | تغطية 100% | حوكمة | 12 شهراً |\n'
    '| 2 | تطوير SOC والمراقبة | 24/7 | كشف | 9 أشهر |\n'
    '| 3 | إدارة الثغرات والتصحيح الدوري | شهري | حماية | 6 أشهر |\n'
    '| 4 | الاستجابة للحوادث | < 4 ساعات | احتواء | 6 أشهر |\n'
    '| 5 | تأمين الوصول عن بُعد عبر VPN و MFA | 100% MFA | حماية | 9 أشهر |\n'
    '| 6 | التوعية والتدريب ضد التصيد | 95% إكمال | بشري | 12 شهراً |\n'
)


# ── 1. Arabic consulting vision with 6 valid objective rows passes. ──────
class ConsultingMinRowsTest(unittest.TestCase):

    @_skip_if_no_app
    def test_01_consulting_vision_6_rows_passes_audit(self):
        defects = _APP._final_strategy_audit(
            {'vision': _VISION_AR_6_ROWS_WITH_COMPLIANCE},
            lang='ar', doc_subtype='strategy',
        )
        so_defects = [
            t for (_s, t, _c, _m) in defects
            if t == 'so_rows_insufficient'
        ]
        self.assertEqual(
            so_defects, [],
            f'6-row vision must not produce so_rows_insufficient; '
            f'all_defects={defects!r}',
        )

    # ── 2. Arabic consulting vision with 4 valid objective rows fails
    #       the consulting-mode floor (6).  Mirrors the post-repair save
    #       gate at app.py:34164 (``if _pa_so < 6``).
    @_skip_if_no_app
    def test_02_consulting_vision_4_rows_below_consulting_floor(self):
        n = _APP.count_valid_objective_rows(
            _VISION_AR_4_ROWS_WITH_COMPLIANCE)
        self.assertEqual(n, 4)
        # A 4-row consulting vision must not be considered sufficient by
        # synthesize_objectives_depth(generation_mode='consulting').  We
        # verify by mocking ai_repair_strategy_section: if the helper
        # treated 4 as sufficient it would be a no-op and never call the
        # AI; here it MUST invoke the AI (eff_min=6).
        sections = {'vision': _VISION_AR_4_ROWS_WITH_COMPLIANCE}
        called = {'count': 0, 'min_rows': None}

        def _spy(**kwargs):
            called['count'] += 1
            called['min_rows'] = kwargs.get('min_rows')
            return _VISION_AR_6_ROWS_WITH_COMPLIANCE

        with mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_spy,
        ):
            _APP.synthesize_objectives_depth(
                sections, lang='ar', domain='Cyber Security',
                fw_short='NCA ECC', generation_mode='consulting',
            )
        self.assertEqual(
            called['count'], 1,
            'consulting mode with 4 valid rows must invoke AI repair '
            '(below consulting floor of 6)',
        )
        self.assertEqual(
            called['min_rows'], 6,
            'consulting-mode AI repair must request min_rows=6',
        )

    # ── 6. count_valid_objective_rows accepts valid Arabic rows. ────────
    @_skip_if_no_app
    def test_06_count_valid_objective_rows_accepts_arabic_rows(self):
        n = _APP.count_valid_objective_rows(
            _VISION_AR_6_ROWS_WITH_COMPLIANCE)
        self.assertEqual(
            n, 6,
            f'count_valid_objective_rows must accept 6 valid Arabic '
            f'rows with proper timeframe; got {n}',
        )
        n4 = _APP.count_valid_objective_rows(
            _VISION_AR_4_ROWS_WITH_COMPLIANCE)
        self.assertEqual(n4, 4)


# ── 3 & 7. Framework-compliance repair requests min_rows ≥ 6 in
#           consulting mode AND never below the existing row count. ──────
class FrameworkComplianceRepairMinRowsTest(unittest.TestCase):
    """Exercise the repair branch by calling ``synthesize_objectives_depth``
    (which is the AI-first helper that the framework-compliance repair
    path delegates ``ai_repair_strategy_section`` to). The behavior under
    test is identical: the repair must request ``min_rows=6`` in
    consulting mode and must validate the AI output against that floor.
    """

    @_skip_if_no_app
    def test_03_synthesize_objectives_depth_consulting_uses_min_rows_6(self):
        # When generation_mode='consulting' and the input has fewer than 6
        # valid SO rows, synthesize_objectives_depth must call
        # ai_repair_strategy_section with min_rows=6.
        sections = {'vision': _VISION_AR_4_ROWS_WITH_COMPLIANCE}
        captured = {}

        def _fake_repair(**kwargs):
            captured.update(kwargs)
            # Return a vision body with exactly 6 valid rows and a
            # compliance objective so the helper accepts it.
            return _VISION_AR_6_ROWS_WITH_COMPLIANCE

        with mock.patch.object(
            _APP, 'ai_repair_strategy_section',
            side_effect=_fake_repair,
        ):
            res = _APP.synthesize_objectives_depth(
                sections, lang='ar', domain='Cyber Security',
                fw_short='NCA ECC', generation_mode='consulting',
            )
        self.assertEqual(
            captured.get('min_rows'), 6,
            f'consulting-mode repair must request min_rows=6; '
            f'captured={captured.get("min_rows")!r}',
        )
        self.assertEqual(captured.get('section_key'), 'vision')
        self.assertTrue(res.get('rebuilt'))
        self.assertEqual(res.get('total_after'), 6)

    # ── 4. Repaired vision with only 4 rows is rejected; original kept. ─
    @_skip_if_no_app
    def test_04_repaired_4_row_vision_rejected_original_kept(self):
        sections = {'vision': _VISION_AR_4_ROWS_WITH_COMPLIANCE}

        # Simulate AI returning a 4-row vision (below the consulting
        # floor of 6). The helper MUST raise RepairError and leave
        # sections['vision'] unchanged.
        def _bad_repair(**kwargs):
            return _VISION_AR_4_ROWS_WITH_COMPLIANCE

        original = sections['vision']
        with mock.patch.object(
            _APP, 'ai_repair_strategy_section',
            side_effect=_bad_repair,
        ):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_objectives_depth(
                    sections, lang='ar', domain='Cyber Security',
                    fw_short='NCA ECC', generation_mode='consulting',
                )
        self.assertEqual(
            sections['vision'], original,
            'sections["vision"] must remain unchanged when AI repair '
            'returns fewer than the required minimum rows',
        )

    # ── 5. Repaired vision with 6 rows incl. ECC/TCC compliance passes ─
    @_skip_if_no_app
    def test_05_repaired_6_row_vision_with_compliance_objective_passes(self):
        sections = {'vision': _VISION_AR_4_ROWS_WITH_COMPLIANCE}

        def _good_repair(**kwargs):
            return _VISION_AR_6_ROWS_WITH_COMPLIANCE

        with mock.patch.object(
            _APP, 'ai_repair_strategy_section',
            side_effect=_good_repair,
        ):
            res = _APP.synthesize_objectives_depth(
                sections, lang='ar', domain='Cyber Security',
                fw_short='NCA ECC', generation_mode='consulting',
            )
        self.assertTrue(res.get('rebuilt'))
        self.assertEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6)
        # Compliance objective for both ECC + TCC must remain satisfied.
        missing = _APP._compute_missing_compliance_objective(
            sections, ['NCA ECC', 'NCA TCC'],
            domain='Cyber Security', lang='ar',
        )
        self.assertEqual(missing, [])

    # ── 7. Framework-compliance repair must not reduce existing valid
    #       objective count.  PR-5B.9G replaced the inline row-floor
    #       gate with the unified ``_assign_vision_if_valid_or_restore``
    #       safe-assign helper (which still enforces the row floor PLUS
    #       the rest of the contract — template markers, framework
    #       leakage, compliance objective).
    @_skip_if_no_app
    def test_07_repair_block_preserves_existing_row_count(self):
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, 'r', encoding='utf-8') as fh:
            src = fh.read()
        # The repair block must compute the prior valid row count, clamp
        # the effective minimum to it, pass it as ``min_rows`` to
        # ai_repair_strategy_section, and route the AI-repaired vision
        # through the safe-assign helper so a thinner repair cannot
        # overwrite a richer existing vision.
        self.assertIn('_v_before_rows', src)
        self.assertIn('count_valid_objective_rows(', src)
        self.assertIn('_vis_min_rows = max(', src)
        self.assertIn('min_rows=_vis_min_rows', src)
        # PR-5B.9G — safe-assign helper integration.
        self.assertIn('_assign_vision_if_valid_or_restore', src)
        self.assertIn("repair_label=(\n", src)
        self.assertIn("'fw-compliance-objective-repair'", src)

    # ── 8. Drafting mode preserves its intended lower threshold. ────────
    @_skip_if_no_app
    def test_08_drafting_mode_uses_lower_floor(self):
        # Drafting mode floor is _RICHNESS_MIN_SO_ROWS (4). When the
        # input already has 4 valid rows, no AI repair should be invoked.
        sections = {'vision': _VISION_AR_4_ROWS_WITH_COMPLIANCE}
        called = {'count': 0}

        def _spy(**kwargs):
            called['count'] += 1
            return _VISION_AR_6_ROWS_WITH_COMPLIANCE

        with mock.patch.object(
            _APP, 'ai_repair_strategy_section', side_effect=_spy,
        ):
            res = _APP.synthesize_objectives_depth(
                sections, lang='ar', domain='Cyber Security',
                fw_short='NCA ECC', generation_mode='drafting',
            )
        self.assertFalse(
            res.get('rebuilt'),
            'drafting mode with 4 valid rows must be a no-op '
            '(min floor is _RICHNESS_MIN_SO_ROWS=4)',
        )
        self.assertEqual(
            called['count'], 0,
            'AI repair must not be called when drafting-mode floor met',
        )
        self.assertEqual(res.get('min_rows'),
                         _APP._RICHNESS_MIN_SO_ROWS)


# ── 9. No deterministic objective rows are inserted by the repair path. ─
class NoDeterministicRowsTest(unittest.TestCase):

    @_skip_if_no_app
    def test_09_repair_path_uses_only_ai_no_deterministic_bank(self):
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, 'r', encoding='utf-8') as fh:
            src = fh.read()
        # The framework-compliance repair block must not call any of the
        # deterministic priority-bank helpers to fabricate objective
        # rows.  AI-first only.
        # We scope the assertion to the FW-COMPLIANCE block by slicing.
        marker_start = src.find('[FW-COMPLIANCE-OBJECTIVE-REPAIR]')
        self.assertNotEqual(
            marker_start, -1,
            'FW-COMPLIANCE-OBJECTIVE-REPAIR block must exist in app.py',
        )
        # Take a generous slice covering the full repair block.
        block = src[marker_start:marker_start + 12000]
        for forbidden in (
            '_build_domain_so_bank_ar(',
            '_build_domain_so_bank_en(',
            'priority_bank',
        ):
            self.assertNotIn(
                forbidden, block,
                f'FW-COMPLIANCE repair block must not call '
                f'{forbidden!r} (AI-first only)',
            )
        # And it must invoke ai_repair_strategy_section.
        self.assertIn(
            'ai_repair_strategy_section(', block,
            'FW-COMPLIANCE repair block must delegate to '
            'ai_repair_strategy_section (AI-first)',
        )

    # ── 10. PDF/export/auth/DB are untouched by the change. ─────────────
    @_skip_if_no_app
    def test_10_pdf_export_auth_db_untouched(self):
        # The fix is scoped strictly to the framework-compliance repair
        # block in api_generate_strategy. Verify the change did not add
        # imports or references to PDF/DOCX/export/auth/DB modules in
        # the affected region.
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, 'r', encoding='utf-8') as fh:
            src = fh.read()
        marker_start = src.find('[FW-COMPLIANCE-OBJECTIVE-REPAIR]')
        block = src[marker_start:marker_start + 12000]
        for forbidden in (
            'reportlab', 'fpdf', 'pdfkit', 'docx',
            'send_file(', 'login_required',
            'db.session', 'db.create_all',
        ):
            self.assertNotIn(
                forbidden, block,
                f'FW-COMPLIANCE repair block must not touch '
                f'{forbidden!r} (PDF/export/auth/DB out of scope)',
            )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
