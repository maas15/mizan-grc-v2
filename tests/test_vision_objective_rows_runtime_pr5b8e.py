"""PR-5B.8E — runtime alignment between AI repair, synth, and the
post-repair audit for the vision / Strategic Objectives section.

The original runtime regression surfaced as the Arabic console error
``فشل فحص ما بعد الإصلاح: رؤية vision_so_rows<6`` (the user-visible
"vision_so_rows<5" report was the same alignment failure rounded down).
Three layers each enforced a different SO floor — the AI prompt asked
for ``min_rows=5``, ``synthesize_objectives_depth`` accepted ≥4, but
``repair_vision_objectives_if_insufficient`` and the post-repair save
gate both required ≥6. The AI faithfully produced 5 rows, passed the
synth's internal floor, then the gate rejected the document.

These tests pin the alignment so the regression cannot return:

  * Arabic repaired vision with ≥6 valid SO rows ⇒ counter accepts it.
  * Arabic repaired vision with <6 valid SO rows ⇒ ``RepairError``
    whose message includes the actual + required row counts.
  * ``synthesize_objectives_depth`` in consulting mode forwards
    ``min_rows=6`` to ``ai_repair_strategy_section``.
  * ``repair_vision_objectives_if_insufficient`` rejects an AI repair
    that returns fewer than 6 valid rows.
  * No deterministic SO bank helper is called or reintroduced.

Run::

    python -m pytest tests/test_vision_objective_rows_runtime_pr5b8e.py -q
"""
import ast
import functools
import importlib.util
import os
import sys
import unittest
from unittest.mock import patch


os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_vision_so_pr5b8e.db')
# Ensure no AI provider is configured, so any unmocked AI call raises.
os.environ['OPENAI_API_KEY'] = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY'] = ''
os.environ['GROQ_API_KEY'] = ''
os.environ['DEEPSEEK_API_KEY'] = ''


_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
except Exception:
    _APP = None


def _skip_if_no_app(fn):
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *args, **kwargs)
    return wrapper


# ── Arabic vision fixtures ──────────────────────────────────────────────
# 6 valid SO rows, 5-column schema, all cells substantive, all timeframes
# parseable by count_valid_objective_rows (covers Arabic units).
_AR_VISION_6 = (
    "## 1. الرؤية والأهداف الاستراتيجية\n\n"
    "**الرؤية:** بناء وضع متين في مجال الأمن السيبراني.\n\n"
    "### الأهداف الاستراتيجية\n\n"
    "| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n"
    "|---|------|------------------|-------|---------------|\n"
    "| 1 | تأسيس لجنة حوكمة الأمن | اعتماد الميثاق | "
    "إغلاق فجوة الحوكمة | خلال 6 أشهر |\n"
    "| 2 | رفع نسبة اجتياز التوعية | >= 90% | "
    "إغلاق فجوة التوعية | خلال 9 أشهر |\n"
    "| 3 | تفعيل الاستجابة للحوادث | اعتماد دليل الاستجابة | "
    "إغلاق فجوة الاستجابة | خلال 12 شهراً |\n"
    "| 4 | تطبيق الضوابط الأساسية | 100% من الضوابط | "
    "إغلاق فجوة النضج | خلال 12 شهراً |\n"
    "| 5 | تفعيل برنامج مخاطر الأطراف الثالثة | "
    "100% من الموردين الحرجين | إغلاق فجوة سلسلة التوريد | "
    "خلال 12 شهراً |\n"
    "| 6 | تعزيز قدرات اكتشاف التهديدات | "
    "تغطية 95% من الأصول الحرجة | إغلاق فجوة المراقبة | "
    "خلال 18 شهراً |\n"
)

# Same fixture, truncated to 5 rows.
_AR_VISION_5 = (
    "## 1. الرؤية والأهداف الاستراتيجية\n\n"
    "**الرؤية:** بناء وضع متين في مجال الأمن السيبراني.\n\n"
    "### الأهداف الاستراتيجية\n\n"
    "| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n"
    "|---|------|------------------|-------|---------------|\n"
    "| 1 | تأسيس لجنة حوكمة الأمن | اعتماد الميثاق | "
    "إغلاق فجوة الحوكمة | خلال 6 أشهر |\n"
    "| 2 | رفع نسبة اجتياز التوعية | >= 90% | "
    "إغلاق فجوة التوعية | خلال 9 أشهر |\n"
    "| 3 | تفعيل الاستجابة للحوادث | اعتماد دليل الاستجابة | "
    "إغلاق فجوة الاستجابة | خلال 12 شهراً |\n"
    "| 4 | تطبيق الضوابط الأساسية | 100% من الضوابط | "
    "إغلاق فجوة النضج | خلال 12 شهراً |\n"
    "| 5 | تفعيل برنامج مخاطر الأطراف الثالثة | "
    "100% من الموردين الحرجين | إغلاق فجوة سلسلة التوريد | "
    "خلال 12 شهراً |\n"
)

# Insufficient (3 rows) — used to force the AI-repair branch.
_AR_VISION_3 = (
    "## 1. الرؤية والأهداف الاستراتيجية\n\n"
    "**الرؤية:** نص قصير.\n\n"
    "### الأهداف الاستراتيجية\n\n"
    "| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n"
    "|---|------|------------------|-------|---------------|\n"
    "| 1 | تأسيس لجنة حوكمة الأمن | اعتماد الميثاق | "
    "إغلاق فجوة الحوكمة | خلال 6 أشهر |\n"
    "| 2 | رفع نسبة اجتياز التوعية | >= 90% | "
    "إغلاق فجوة التوعية | خلال 9 أشهر |\n"
    "| 3 | تفعيل الاستجابة للحوادث | اعتماد دليل الاستجابة | "
    "إغلاق فجوة الاستجابة | خلال 12 شهراً |\n"
)


class TestArabicCounter(unittest.TestCase):
    """count_valid_objective_rows must accept the Arabic header / column
    names emitted by the AI repair schema."""

    @_skip_if_no_app
    def test_arabic_6_rows_counted(self):
        self.assertEqual(
            _APP.count_valid_objective_rows(_AR_VISION_6), 6)

    @_skip_if_no_app
    def test_arabic_5_rows_counted(self):
        self.assertEqual(
            _APP.count_valid_objective_rows(_AR_VISION_5), 5)

    @_skip_if_no_app
    def test_arabic_3_rows_counted(self):
        self.assertEqual(
            _APP.count_valid_objective_rows(_AR_VISION_3), 3)


class TestSynthObjectivesAlignment(unittest.TestCase):
    """synthesize_objectives_depth in consulting mode must demand the
    same floor (6) the post-repair audit enforces — both in the AI
    prompt's ``min_rows`` and in the post-AI count check."""

    @_skip_if_no_app
    def test_consulting_mode_forwards_min_rows_6_to_ai_repair(self):
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_6) as mock_ai:
            _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='consulting',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(
            kwargs.get('section_key'), 'vision',
            'must use section_key="vision"')
        self.assertEqual(
            kwargs.get('min_rows'), 6,
            'consulting mode must forward min_rows=6 to '
            'ai_repair_strategy_section so the AI prompt schema '
            'matches the post-repair audit floor')

    @_skip_if_no_app
    def test_consulting_mode_rejects_ai_returning_5_rows(self):
        """The historical regression: AI returns 5 rows, synth previously
        accepted them (floor was 4), then the audit rejected the doc.
        With aligned min_rows the synth must reject 5 rows itself."""
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_5):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.synthesize_objectives_depth(
                    sections, lang='ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    generation_mode='consulting',
                )
        msg = str(cm.exception)
        self.assertIn('5', msg, 'error must include actual row count')
        self.assertIn('6', msg, 'error must include required row count')

    @_skip_if_no_app
    def test_consulting_mode_accepts_ai_returning_6_rows(self):
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_6):
            result = _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='consulting',
            )
        self.assertTrue(result.get('rebuilt'))
        self.assertGreaterEqual(result.get('total_after', 0), 6)
        self.assertEqual(sections['vision'], _AR_VISION_6)

    @_skip_if_no_app
    def test_drafting_mode_keeps_legacy_floor(self):
        """Backwards compatibility — non-consulting modes must keep the
        previous _RICHNESS_MIN_SO_ROWS floor so existing
        drafting-mode call sites and tests do not regress."""
        # 5 rows is sufficient under the drafting/legacy floor (4),
        # so the synth must accept the AI repair without raising.
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_5):
            result = _APP.synthesize_objectives_depth(
                sections, lang='ar',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertTrue(result.get('rebuilt'))


class TestRepairVisionFloor(unittest.TestCase):
    """repair_vision_objectives_if_insufficient must (a) explicitly
    request ≥6 rows from the AI and (b) refuse to accept a repair that
    returns fewer than 6 rows."""

    @_skip_if_no_app
    def test_passes_min_rows_6_to_synth(self):
        """Verify the backstop hands an explicit min_rows=6 down through
        synthesize_objectives_depth → ai_repair_strategy_section."""
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_6) as mock_ai:
            _APP.repair_vision_objectives_if_insufficient(
                sections, lang='ar',
                domain='Cyber Security',
                org_name='منظمة الاختبار',
                frameworks=['NCA ECC'],
                sector='Government',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(
            kwargs.get('min_rows'), 6,
            'repair_vision_objectives_if_insufficient must request '
            'min_rows=6 from ai_repair_strategy_section')

    @_skip_if_no_app
    def test_rejects_ai_repair_with_5_rows(self):
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_5):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_vision_objectives_if_insufficient(
                    sections, lang='ar',
                    domain='Cyber Security',
                    org_name='منظمة الاختبار',
                    frameworks=['NCA ECC'],
                    sector='Government',
                )
        # The RepairError must carry section='vision' so the caller can
        # route through _mark_synth_failed.
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision')
        msg = str(cm.exception)
        # Must mention actual + required so operators can diagnose.
        self.assertTrue(
            '5' in msg or '/6' in msg,
            f'error message must include row counts; got: {msg!r}')
        self.assertIn('6', msg)

    @_skip_if_no_app
    def test_accepts_ai_repair_with_6_rows(self):
        sections = {'vision': _AR_VISION_3}
        with patch.object(
                _APP, 'ai_repair_strategy_section',
                return_value=_AR_VISION_6):
            added = _APP.repair_vision_objectives_if_insufficient(
                sections, lang='ar',
                domain='Cyber Security',
                org_name='منظمة الاختبار',
                frameworks=['NCA ECC'],
                sector='Government',
            )
        self.assertGreaterEqual(added, 0)
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(sections['vision']), 6)


class TestNoDeterministicBank(unittest.TestCase):
    """Confirm that the legacy deterministic SO bank helpers are neither
    exposed by app nor invoked from any production call site (PR-5B.5H
    + PR-5B.8E reaffirmation)."""

    @_skip_if_no_app
    def test_so_bank_helpers_not_exposed(self):
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_en'))

    @_skip_if_no_app
    def test_so_bank_helpers_not_called_anywhere(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(path, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=path)
        targets = {'_build_domain_so_bank_ar', '_build_domain_so_bank_en'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                self.assertNotIn(
                    name, targets,
                    f'PR-5B.8E: legacy SO bank helper {name!r} called '
                    f'at app.py:{node.lineno}')


if __name__ == '__main__':
    unittest.main()
