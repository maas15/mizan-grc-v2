"""PR-5B.5F3: AI-first migration of repair_vision_objectives_if_insufficient
and repair_kpi_section_if_missing_frequency.

Each scenario monkey-patches the migrated AI synth helpers
(``synthesize_objectives_depth`` / ``synthesize_kpi_depth``) to assert:

  1. Vision lede/subheading schema-only path still works without invoking AI
     when the section already has ≥ 6 valid objectives.
  2. Insufficient objectives delegate to ``synthesize_objectives_depth``.
  3. ``_build_domain_so_bank_ar/en`` are NOT referenced from
     ``repair_vision_objectives_if_insufficient`` (statically proven by
     AST scan after PR-5B.5H deletion of those helpers).
  4. AI-repaired objectives with < 6 rows are rejected with
     ``RepairError(section='vision')``.
  5. KPI with missing Frequency delegates to ``synthesize_kpi_depth`` for
     the cyber domain.
  6. KPI with missing Frequency delegates to ``synthesize_kpi_depth`` for
     non-cyber domains (single AI-first path).
  7. ``_build_domain_kpi_bank_ar/en`` are NOT referenced from
     ``repair_kpi_section_if_missing_frequency`` (statically proven by
     AST scan after PR-5B.5H deletion of those helpers).
  8. Hardcoded KPI rows / guide blocks are not inserted after a
     ``RepairError``; the original KPI section is preserved.
  9. ``RepairError`` from vision repair propagates with ``section='vision'``.
 10. ``RepairError`` from KPI repair propagates with ``section='kpis'``.
 11. Production-caller pattern records ``synth_failed:vision`` via
     ``_mark_synth_failed`` when the vision repair raises.
 12. Production-caller pattern records ``synth_failed:kpis`` when the KPI
     repair raises.
 13. ``_final_strategy_audit`` emits ``synth_failed:vision`` and
     ``synth_failed:kpis`` defects when the request-scoped status dict
     marks them failed.

Run:  python -m pytest tests/test_strategy_repair_ai_first_pr5b5f3.py -q
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
    'DATABASE_URL', 'sqlite:///tmp/test_repair_ai_first_pr5b5f3.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
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
# Section payloads.
# ---------------------------------------------------------------------------

# Rich vision: 6 valid SO rows → schema-only path (no AI call).
_RICH_VISION_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '**الرؤية:** رؤية شاملة للأمن السيبراني.\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|-------|-----------------|--------|---------------|\n'
    '| 1 | حوكمة | 100% | NCA ECC | خلال 6 أشهر |\n'
    '| 2 | ضوابط | ≥ 95% | الامتثال | خلال 12 شهراً |\n'
    '| 3 | IAM | 100% | تقليل المخاطر | خلال 9 أشهر |\n'
    '| 4 | SIEM | ≤ 60 دقيقة | الكشف | خلال 12 شهراً |\n'
    '| 5 | ثغرات | 100% | تقليص الهجوم | خلال 6 أشهر |\n'
    '| 6 | بيانات | 100% | الامتثال | خلال 12 شهراً |\n'
)

# Thin vision: 1 SO row → triggers AI delegation.
_THIN_VISION_AR = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
    '|---|-------|-----------------|--------|---------------|\n'
    '| 1 | حوكمة | 100% | NCA ECC | خلال 6 أشهر |\n'
)

# KPI section already has Frequency token → early return.
_KPI_WITH_FREQUENCY_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
    '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
    '|---|--------|---------------|-----------------|---------------|'
    '----------------|--------|----------|----------------|\n'
    '| 1 | تغطية NCA ECC | KPI | 100% | (المطبق ÷ الإجمالي) × 100 '
    '| سجل الضوابط | فريق الحوكمة | شهري | خلال 12 شهراً |\n'
)

# KPI section missing Frequency → triggers AI delegation.
_KPI_MISSING_FREQUENCY_AR = (
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | المبرر |\n'
    '|---|-----------|-----------------|--------|\n'
    '| 1 | نسبة الامتثال | 90% | NCA ECC |\n'
)

_KPI_MISSING_FREQUENCY_EN = (
    '## 6. Key Performance Indicators\n\n'
    '| # | KPI Description | Target | Justification |\n'
    '|---|-----------------|--------|---------------|\n'
    '| 1 | Compliance ratio | 90% | NCA ECC |\n'
)


def _stub_so_section(rows=8):
    header = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** رؤية شاملة.\n\n'
        '### الأهداف الاستراتيجية\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|-------|-----------------|--------|---------------|\n'
    )
    body = '\n'.join(
        f'| {i} | الهدف رقم {i} | ≥ 95% | متطلب NCA ECC | خلال 12 شهراً |'
        for i in range(1, rows + 1)
    )
    return header + body + '\n'


def _stub_kpi_section_with_frequency(rows=10):
    header = (
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة | صيغة الاحتساب '
        '| مصدر البيانات | المالك | التكرار | الإطار الزمني |\n'
        '|---|--------|---------------|-----------------|---------------|'
        '----------------|--------|----------|----------------|\n'
    )
    body = '\n'.join(
        f'| {i} | المؤشر {i} | KPI | ≥ 90% '
        f'| (المطبّق ÷ الإجمالي) × 100 | سجل الضوابط | فريق الحوكمة '
        f'| شهري | خلال 12 شهراً |'
        for i in range(1, rows + 1)
    )
    return header + body + '\n'


def _stub_kpi_section_with_frequency_en(rows=10):
    header = (
        '## 6. Key Performance Indicators\n\n'
        '| # | Metric | Type KPI/KRI | Target Value | Calculation Formula '
        '| Data Source | Owner | Frequency | Timeframe |\n'
        '|---|--------|--------------|--------------|---------------------|'
        '-------------|-------|-----------|-----------|\n'
    )
    body = '\n'.join(
        f'| {i} | Metric {i} | KPI | >= 90% | (X / Y) * 100 '
        f'| Source | Owner | Monthly | Within 12 months |'
        for i in range(1, rows + 1)
    )
    return header + body + '\n'


def _raise_repair(*_a, **_kw):
    raise _APP.RepairError('forced for test')


@unittest.skipIf(_APP is None, 'app.py unavailable in this environment')
class RepairVisionAndKpiAIFirst(unittest.TestCase):
    """PR-5B.5F3 contract for the two repair functions."""

    # ── 1. Schema-only path: ≥ 6 SO rows → no AI call ─────────────────────
    def test_1_schema_only_path_no_ai_call_when_six_or_more_objectives(self):
        calls = {'count': 0}

        def _spy(*_a, **_kw):
            calls['count'] += 1
            raise AssertionError(
                'synthesize_objectives_depth must NOT be called when the '
                'vision already has >= 6 valid SO rows')

        sections = {'vision': _RICH_VISION_AR}
        with _Patch(_APP, 'synthesize_objectives_depth', _spy):
            added = _APP.repair_vision_objectives_if_insufficient(
                sections, lang='ar',
                domain='Cyber Security', org_name='Acme',
                frameworks=['NCA ECC'], sector='Government',
            )
        self.assertEqual(calls['count'], 0)
        self.assertEqual(added, 0)
        # Schema-only contract: lede + الأهداف الاستراتيجية subheading present.
        self.assertIn('الرؤية', sections['vision'])
        self.assertIn('الأهداف الاستراتيجية', sections['vision'])

    # ── 2. Insufficient objectives delegate to synthesize_objectives_depth
    def test_2_insufficient_objectives_delegate_to_synth(self):
        calls = {'count': 0, 'lang': None}

        def _stub(sections, lang, **_kw):
            calls['count'] += 1
            calls['lang'] = lang
            sections['vision'] = _stub_so_section(rows=8)

        sections = {'vision': _THIN_VISION_AR}
        with _Patch(_APP, 'synthesize_objectives_depth', _stub):
            added = _APP.repair_vision_objectives_if_insufficient(
                sections, lang='ar',
                domain='Cyber Security', org_name='Acme',
                frameworks=['NCA ECC'], sector='Government',
            )
        self.assertEqual(calls['count'], 1)
        self.assertEqual(calls['lang'], 'ar')
        self.assertGreaterEqual(added, 1)

    # ── 3. _build_domain_so_bank_ar/en NOT called ─────────────────────────
    def test_3_build_domain_so_bank_helpers_not_called(self):
        # PR-5B.5H: legacy SO bank helpers deleted; switch from runtime
        # spies to AST scan + symbol-absence assertion.
        import ast
        import os
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
                    'repair_vision_objectives_if_insufficient (or any '
                    f'production code) must not call {name!r} at '
                    f'app.py:{node.lineno}')
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_so_bank_en'))

    # ── 4. AI-repaired vision with < 6 rows → RepairError section='vision'
    def test_4_ai_repair_below_six_rows_raises_repair_error_vision(self):
        def _short_stub(sections, lang, **_kw):
            # Produce only 5 valid SO rows — below the function's stricter
            # floor of 6.
            sections['vision'] = _stub_so_section(rows=5)

        sections = {'vision': _THIN_VISION_AR}
        with _Patch(_APP, 'synthesize_objectives_depth', _short_stub):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_vision_objectives_if_insufficient(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    frameworks=['NCA ECC'], sector='Government',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision')

    # ── 5. KPI missing Frequency → synthesize_kpi_depth (cyber) ───────────
    def test_5_kpi_missing_frequency_delegates_for_cyber(self):
        calls = {'count': 0, 'lang': None}

        def _stub(sections, lang, **_kw):
            calls['count'] += 1
            calls['lang'] = lang
            sections['kpis'] = _stub_kpi_section_with_frequency(rows=10)
            return 10

        sections = {'kpis': _KPI_MISSING_FREQUENCY_AR}
        with _Patch(_APP, 'synthesize_kpi_depth', _stub):
            n = _APP.repair_kpi_section_if_missing_frequency(
                sections, lang='ar',
                domain='Cyber Security', org_name='Acme',
                sector='Government', frameworks=['NCA ECC'],
            )
        self.assertEqual(calls['count'], 1)
        self.assertEqual(calls['lang'], 'ar')
        self.assertGreater(n, 0)
        self.assertIn('التكرار', sections['kpis'])

    # ── 6. KPI missing Frequency → synthesize_kpi_depth (non-cyber) ───────
    def test_6_kpi_missing_frequency_delegates_for_non_cyber(self):
        calls = {'count': 0}

        def _stub(sections, lang, **_kw):
            calls['count'] += 1
            sections['kpis'] = _stub_kpi_section_with_frequency_en(rows=10)
            return 10

        sections = {'kpis': _KPI_MISSING_FREQUENCY_EN}
        with _Patch(_APP, 'synthesize_kpi_depth', _stub):
            n = _APP.repair_kpi_section_if_missing_frequency(
                sections, lang='en',
                domain='Data Management', org_name='Acme',
                sector='Government', frameworks=[],
            )
        self.assertEqual(calls['count'], 1,
            'PR-5B.5F3: non-cyber domains must also use synthesize_kpi_depth')
        self.assertGreater(n, 0)
        self.assertIn('Frequency', sections['kpis'])

    # ── 7. _build_domain_kpi_bank_ar/en NOT called ────────────────────────
    def test_7_build_domain_kpi_bank_helpers_not_called(self):
        # PR-5B.5H: legacy KPI bank helpers deleted; switch from runtime
        # spies to AST scan + symbol-absence assertion.
        import ast
        import os
        path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(path, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=path)
        targets = {'_build_domain_kpi_bank_ar', '_build_domain_kpi_bank_en'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                self.assertNotIn(
                    name, targets,
                    'repair_kpi_section_if_missing_frequency (or any '
                    f'production code) must not call {name!r} at '
                    f'app.py:{node.lineno}')
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_en'))

    # ── 8. RepairError → original KPI section preserved (no injection) ────
    def test_8_repair_error_leaves_kpi_section_unchanged(self):
        sections = {'kpis': _KPI_MISSING_FREQUENCY_AR}
        original = sections['kpis']
        with _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError):
                _APP.repair_kpi_section_if_missing_frequency(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    sector='Government', frameworks=['NCA ECC'],
                )
        # Section unchanged — no deterministic rows / guides injected.
        self.assertEqual(sections['kpis'], original)
        for forbidden in ('MTTD',
                          'دليل تقييم المؤشر', 'KPI Assessment Guide'):
            self.assertNotIn(forbidden, sections['kpis'])

    # ── 9. RepairError from vision repair propagates section='vision' ─────
    def test_9_repair_error_from_vision_annotated_vision(self):
        sections = {'vision': _THIN_VISION_AR}
        with _Patch(_APP, 'synthesize_objectives_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_vision_objectives_if_insufficient(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    frameworks=['NCA ECC'], sector='Government',
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'vision')

    # ── 10. RepairError from KPI repair propagates section='kpis' ─────────
    def test_10_repair_error_from_kpi_annotated_kpis(self):
        sections = {'kpis': _KPI_MISSING_FREQUENCY_AR}
        with _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            with self.assertRaises(_APP.RepairError) as cm:
                _APP.repair_kpi_section_if_missing_frequency(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    sector='Government', frameworks=['NCA ECC'],
                )
        self.assertEqual(getattr(cm.exception, 'section', None), 'kpis')

    # ── 11. Production-caller pattern records synth_failed:vision ─────────
    def test_11_production_caller_marks_synth_failed_vision(self):
        """Mirror the request-handler caller's catch pattern; assert the
        annotated-section flow ends up in a synth_status dict."""
        sections = {'vision': _THIN_VISION_AR}
        synth_status = {}
        with _Patch(_APP, 'synthesize_objectives_depth', _raise_repair):
            try:
                _APP.repair_vision_objectives_if_insufficient(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    frameworks=['NCA ECC'], sector='Government',
                )
            except _APP.RepairError as _e:
                section = getattr(_e, 'section', 'vision')
                _APP._mark_synth_failed(synth_status, section, _e)
        self.assertEqual(
            synth_status.get('synth_status', {}).get('vision'), 'failed')

    # ── 12. Production-caller pattern records synth_failed:kpis ───────────
    def test_12_production_caller_marks_synth_failed_kpis(self):
        sections = {'kpis': _KPI_MISSING_FREQUENCY_AR}
        synth_status = {}
        with _Patch(_APP, 'synthesize_kpi_depth', _raise_repair):
            try:
                _APP.repair_kpi_section_if_missing_frequency(
                    sections, lang='ar',
                    domain='Cyber Security', org_name='Acme',
                    sector='Government', frameworks=['NCA ECC'],
                )
            except _APP.RepairError as _e:
                section = getattr(_e, 'section', 'kpis')
                _APP._mark_synth_failed(synth_status, section, _e)
        self.assertEqual(
            synth_status.get('synth_status', {}).get('kpis'), 'failed')

    # ── 13. Final audit blocks when synth_status carries those failures ───
    def test_13_final_audit_emits_synth_failed_defects(self):
        sections = {
            'vision': _RICH_VISION_AR,
            'pillars': '', 'environment': '', 'gaps': '', 'roadmap': '',
            'kpis': _KPI_WITH_FREQUENCY_AR,
            'confidence': '',
        }
        defects = _APP._final_strategy_audit(
            sections, 'ar', doc_subtype=None,
            synth_status={'vision': 'failed', 'kpis': 'failed'})
        tags = {(sec, tag) for sec, tag, _, _ in defects}
        self.assertIn(('vision', 'synth_failed:vision'), tags)
        self.assertIn(('kpis', 'synth_failed:kpis'), tags)


if __name__ == '__main__':
    unittest.main()
