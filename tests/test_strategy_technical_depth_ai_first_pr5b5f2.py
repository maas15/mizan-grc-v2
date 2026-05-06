"""PR-5B.5F2: AI-first SO/KPI depth enrichment in
``enforce_technical_strategy_depth``.

Each scenario monkey-patches the migrated AI synth helpers
(``synthesize_objectives_depth`` / ``synthesize_kpi_depth``) to assert:

  * SO shortfall delegates to ``synthesize_objectives_depth``.
  * KPI shortfall delegates to ``synthesize_kpi_depth``.
  * ``_build_domain_so_bank_ar/en`` are NOT referenced from
    ``enforce_technical_strategy_depth`` (statically proven by AST scan
    after PR-5B.5H deletion of those helpers).
  * ``_build_domain_kpi_bank_ar/en`` are NOT referenced from
    ``enforce_technical_strategy_depth`` (same).
  * ``RepairError`` from objective synth is annotated with
    ``section="vision"`` and propagates out.
  * ``RepairError`` from KPI synth is annotated with ``section="kpis"``
    and propagates out.
  * The post-normalization gate (``_final_strategy_audit``) emits
    ``synth_failed:<section>`` defects when the caller records the
    failure into ``_synth_status``.

Run:  python -m pytest tests/test_strategy_technical_depth_ai_first_pr5b5f2.py -q
"""

import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py can be imported without a live DB / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL', 'sqlite:///tmp/test_depth_ai_first_pr5b5f2.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_APP = None
_APP_PY_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'app', _APP_PY_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception:  # pragma: no cover - environment-dependent
    _APP = None


class _Patch:
    """Lightweight context manager that swaps a module attribute."""

    def __init__(self, target, name, value):
        self.target = target
        self.name = name
        self.value = value
        self._original = None
        self._had = False

    def __enter__(self):
        self._had = hasattr(self.target, self.name)
        if self._had:
            self._original = getattr(self.target, self.name)
        setattr(self.target, self.name, self.value)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._had:
            setattr(self.target, self.name, self._original)
        else:  # pragma: no cover - defensive
            try:
                delattr(self.target, self.name)
            except AttributeError:
                pass
        return False


# ---------------------------------------------------------------------------
# Section payloads used to force the SO and KPI branches into shortfall.
# ---------------------------------------------------------------------------

# 1 SO row → below `_MIN_SO_DEPTH = 5`.
_THIN_VISION_AR = (
    "### الأهداف الاستراتيجية:\n\n"
    "| # | الهدف الاستراتيجي | المؤشر المستهدف | المبرر | الإطار الزمني |\n"
    "|---|--------------------|-----------------|--------|----------------|\n"
    "| 1 | تعزيز الحوكمة | 100% | NCA ECC | 12 شهراً |\n"
)

# 1 KPI row → below `_MIN_KPI_DEPTH = 6` (consulting mode).
_THIN_KPIS_AR = (
    "### مؤشرات الأداء الرئيسية:\n\n"
    "| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب |"
    " مصدر البيانات | المالك | التكرار | الإطار الزمني |\n"
    "|---|--------|---------------|-------------------|----------------|"
    "----------------|--------|---------|----------------|\n"
    "| 1 | تغطية ضوابط NCA | KPI | 100% | (مطبق/إجمالي)x100 |"
    " GRC | CISO | شهري | سنة |\n"
)

# Rich SO section (5 rows) so SO branch becomes a no-op.
_RICH_VISION_AR = (
    "### الأهداف الاستراتيجية:\n\n"
    "| # | الهدف الاستراتيجي | المؤشر المستهدف | المبرر | الإطار الزمني |\n"
    "|---|--------------------|-----------------|--------|----------------|\n"
    "| 1 | تعزيز الحوكمة | 100% | NCA ECC | 12 شهراً |\n"
    "| 2 | إدارة الهوية والصلاحيات | 100% | NCA ECC IAM | 12 شهراً |\n"
    "| 3 | المراقبة الأمنية المستمرة | 24/7 | NCA ECC SIEM | 12 شهراً |\n"
    "| 4 | الاستجابة للحوادث | < 4 ساعات | NCA ECC IR | 12 شهراً |\n"
    "| 5 | حماية البيانات | 100% | NCA ECC DP | 12 شهراً |\n"
)

# Rich KPI section (6 rows) so KPI branch becomes a no-op.
_RICH_KPIS_AR = (
    "### مؤشرات الأداء الرئيسية:\n\n"
    "| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب |"
    " مصدر البيانات | المالك | التكرار | الإطار الزمني |\n"
    "|---|--------|---------------|-------------------|----------------|"
    "----------------|--------|---------|----------------|\n"
    "| 1 | تغطية NCA | KPI | 100% | (مطبق/إجمالي)x100 | GRC | CISO | شهري | سنة |\n"
    "| 2 | تأهيل الكوادر | KPI | 100% | المُدرَّبون/الإجمالي | HR | CISO | ربعي | سنة |\n"
    "| 3 | جاهزية الاستجابة | KPI | < 4س | متوسط زمن الاستجابة | SOC | CISO | شهري | سنة |\n"
    "| 4 | جاهزية النسخ | KPI | 100% | اختبارات ناجحة/إجمالي | DR | CIO | ربعي | سنة |\n"
    "| 5 | التصحيح الأمني | KPI | 30 يوم | متوسط زمن التصحيح | VM | CISO | شهري | سنة |\n"
    "| 6 | أطراف ثالثة | KPI | 100% | المُقيّمون/الإجمالي | TPRM | CISO | ربعي | سنة |\n"
)


# Rich confidence section (5 risk rows) so PR-5B.6C.1 Section D AI-first
# risk top-up becomes a no-op for SO/KPI-focused tests.
_RICH_CONFIDENCE_AR = (
    "## 7. تقييم الثقة والمخاطر\n\n"
    "**درجة الثقة:** 65%\n\n"
    "### المخاطر الرئيسية:\n\n"
    "| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n"
    "|---|--------|-----------|--------|-------------|\n"
    "| 1 | تأخر اعتماد الحوكمة | متوسط | عالٍ | ورش تنفيذية مبكرة |\n"
    "| 2 | محدودية الميزانية | متوسط | عالٍ | جدولة متعددة السنوات |\n"
    "| 3 | عدم اكتمال جرد الأصول | متوسط | متوسط | جرد شامل قبل التطبيق |\n"
    "| 4 | فجوات الكفاءات | عالٍ | عالٍ | برامج تدريب وتوظيف |\n"
    "| 5 | تأخر تكامل الأنظمة | متوسط | عالٍ | تنفيذ مرحلي مع اختبار قبول |\n"
)


def _make_sections(*, vision='', kpis='', confidence=None):
    return {
        'vision': vision,
        'pillars': '',
        'environment': '',
        'gaps': '',
        'roadmap': '',
        'kpis': kpis,
        'confidence': _RICH_CONFIDENCE_AR if confidence is None else confidence,
    }


def _raise_repair(*_a, **_k):
    raise _APP.RepairError('forced for test')


@unittest.skipIf(_APP is None, 'app.py unavailable in this environment')
class EnforceTechnicalStrategyDepthAIFirst(unittest.TestCase):
    """SO + KPI branches of ``enforce_technical_strategy_depth`` are AI-first."""

    # ── 1. SO shortfall delegates to synthesize_objectives_depth ──────────
    def test_1_so_shortfall_delegates_to_synthesize_objectives_depth(self):
        calls = {'count': 0, 'kwargs': None}

        def _stub(sections, lang, **kwargs):
            calls['count'] += 1
            calls['kwargs'] = kwargs
            # Simulate AI repair filling the section to 5 rows so the
            # post-call recount produces a positive delta.
            sections['vision'] = _RICH_VISION_AR

        sections = _make_sections(vision=_THIN_VISION_AR, kpis=_RICH_KPIS_AR)
        with _Patch(_APP, 'synthesize_objectives_depth', _stub):
            summary = _APP.enforce_technical_strategy_depth(
                sections, 'ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting')
        self.assertEqual(calls['count'], 1,
                         'synthesize_objectives_depth was not called')
        self.assertGreaterEqual(summary.get('so_rows_added', 0), 1)

    # ── 2. KPI shortfall delegates to synthesize_kpi_depth ────────────────
    def test_2_kpi_shortfall_delegates_to_synthesize_kpi_depth(self):
        calls = {'count': 0, 'kwargs': None}

        def _stub(sections, lang, **kwargs):
            calls['count'] += 1
            calls['kwargs'] = kwargs
            sections['kpis'] = _RICH_KPIS_AR
            return 6

        sections = _make_sections(vision=_RICH_VISION_AR, kpis=_THIN_KPIS_AR)
        with _Patch(_APP, 'synthesize_kpi_depth', _stub):
            summary = _APP.enforce_technical_strategy_depth(
                sections, 'ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting')
        self.assertEqual(calls['count'], 1,
                         'synthesize_kpi_depth was not called')
        self.assertGreaterEqual(summary.get('kpi_rows_added', 0), 1)

    # ── 3. _build_domain_so_bank_ar/en NOT called ─────────────────────────
    def test_3_build_domain_so_bank_helpers_not_called(self):
        # PR-5B.5H: the four legacy bank helpers were physically deleted
        # from app.py, so a runtime spy on a symbol that no longer exists
        # has no value.  Replace with an AST scan that proves
        # enforce_technical_strategy_depth (and the rest of app.py) does
        # not reference either name as a Call, and that the names are
        # absent from the imported module.
        import ast
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=_APP_PY_PATH)
        targets = {'_build_domain_so_bank_ar', '_build_domain_so_bank_en'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                self.assertNotIn(
                    name, targets,
                    'enforce_technical_strategy_depth (or any production '
                    f'code) must not call legacy SO bank helper {name!r} '
                    f'at app.py:{node.lineno}')
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_en'))

    # ── 4. _build_domain_kpi_bank_ar/en NOT called ────────────────────────
    def test_4_build_domain_kpi_bank_helpers_not_called(self):
        # PR-5B.5H: see test_3 — switched to AST + symbol-absence after
        # the four helpers were deleted.
        import ast
        with open(_APP_PY_PATH, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=_APP_PY_PATH)
        targets = {'_build_domain_kpi_bank_ar', '_build_domain_kpi_bank_en'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                self.assertNotIn(
                    name, targets,
                    'enforce_technical_strategy_depth (or any production '
                    f'code) must not call legacy KPI bank helper {name!r} '
                    f'at app.py:{node.lineno}')
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_en'))

    # ── 5. RepairError from SO synth is annotated section="vision" ────────
    def test_5_repair_error_from_so_annotated_vision_and_propagates(self):
        sections = _make_sections(vision=_THIN_VISION_AR, kpis=_RICH_KPIS_AR)
        with _Patch(_APP, 'synthesize_objectives_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.enforce_technical_strategy_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting')
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision')
        # No deterministic fallback rows: vision unchanged.
        self.assertEqual(sections['vision'], _THIN_VISION_AR)

    # ── 6. RepairError from KPI synth is annotated section="kpis" ─────────
    def test_6_repair_error_from_kpi_annotated_kpis_and_propagates(self):
        sections = _make_sections(vision=_RICH_VISION_AR, kpis=_THIN_KPIS_AR)
        with _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.enforce_technical_strategy_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting')
        self.assertEqual(getattr(cm.exception, 'section', None), 'kpis')
        # No deterministic fallback rows: kpis unchanged.
        self.assertEqual(sections['kpis'], _THIN_KPIS_AR)

    # ── 7. Caller pattern: getattr(error,"section",...) → _mark_synth_failed
    def test_7_caller_pattern_records_synth_failed_using_section(self):
        """Mirror the request-handler caller's catch pattern; assert the
        annotated-section flow ends up in a synth_status dict."""
        sections = _make_sections(vision=_THIN_VISION_AR, kpis=_RICH_KPIS_AR)
        synth_status = {}
        with _Patch(_APP, 'synthesize_objectives_depth', _raise_repair):
            try:
                _APP.enforce_technical_strategy_depth(
                    sections, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting')
            except _APP.RepairError as _e:
                section = getattr(_e, 'section', 'strategy')
                _APP._mark_synth_failed(synth_status, section, _e)
        self.assertEqual(synth_status.get('synth_status', {}).get('vision'),
                         'failed')

        # Same for KPI shortfall.
        sections2 = _make_sections(vision=_RICH_VISION_AR, kpis=_THIN_KPIS_AR)
        synth_status2 = {}
        with _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            try:
                _APP.enforce_technical_strategy_depth(
                    sections2, 'ar',
                    domain='Cyber Security', fw_short='NCA ECC',
                    sector='Government', org_name='Acme',
                    maturity='initial', generation_mode='consulting')
            except _APP.RepairError as _e:
                section = getattr(_e, 'section', 'strategy')
                _APP._mark_synth_failed(synth_status2, section, _e)
        self.assertEqual(synth_status2.get('synth_status', {}).get('kpis'),
                         'failed')

    # ── 8. Final audit blocks when synth_status carries those failures ────
    def test_8_final_audit_emits_synth_failed_defects(self):
        """``_final_strategy_audit`` surfaces ``synth_failed:vision`` /
        ``synth_failed:kpis`` defects when the caller threads in the
        request-scoped status dict, which is what the post-normalization
        save gate consults."""
        sections = _make_sections(
            vision=_RICH_VISION_AR, kpis=_RICH_KPIS_AR)
        defects = _APP._final_strategy_audit(
            sections, 'ar', doc_subtype=None,
            synth_status={'vision': 'failed', 'kpis': 'failed'})
        tags = {(sec, tag) for sec, tag, _, _ in defects}
        self.assertIn(('vision', 'synth_failed:vision'), tags)
        self.assertIn(('kpis', 'synth_failed:kpis'), tags)

    # ── 9. Existing technical-depth behavior preserved with mocked AI ─────
    def test_9_existing_summary_shape_preserved(self):
        """When the AI synth succeeds, ``enforce_technical_strategy_depth``
        still returns the same summary-dict shape downstream consumers
        rely on (so existing tests that read ``so_rows_added`` /
        ``kpi_rows_added`` / ``capability_gaps`` keep working)."""

        def _ok_objs(sections, lang, **kwargs):
            sections['vision'] = _RICH_VISION_AR

        def _ok_kpis(sections, lang, **kwargs):
            sections['kpis'] = _RICH_KPIS_AR
            return 6

        sections = _make_sections(vision=_THIN_VISION_AR, kpis=_THIN_KPIS_AR)
        patches = [
            _Patch(_APP, 'synthesize_objectives_depth', _ok_objs),
            _Patch(_APP, 'synthesize_kpi_depth', _ok_kpis),
        ]
        for p in patches:
            p.__enter__()
        try:
            summary = _APP.enforce_technical_strategy_depth(
                sections, 'ar',
                domain='Cyber Security', fw_short='NCA ECC',
                sector='Government', org_name='Acme',
                maturity='initial', generation_mode='consulting')
        finally:
            for p in reversed(patches):
                p.__exit__(None, None, None)
        for key in ('pillar_initiatives_added', 'so_rows_added',
                    'kpi_rows_added', 'risk_rows_added', 'capability_gaps'):
            self.assertIn(key, summary)
        self.assertGreaterEqual(summary['so_rows_added'], 1)
        self.assertGreaterEqual(summary['kpi_rows_added'], 1)


if __name__ == '__main__':
    unittest.main()
