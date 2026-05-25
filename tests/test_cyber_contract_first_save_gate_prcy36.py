"""PR-CY36 — Contract-first Cyber strategy generation.

Verifies that:

A. ``_cyber_final_export_contract`` returns a canonical
   ``final_contract_result`` object with the fields specified in the
   PR-CY36 spec (final_markdown, final_sections, final_hash,
   final_frameworks, final_metadata, diagnostics, blocking_errors,
   output_type).

D. ``_cyber_final_export_contract`` surfaces ``framework_context_valid``
   on the ``diag`` payload (so the [CYBER-FINAL-EXPORT-CONTRACT] log
   line carries it without operators having to cross-reference the
   [CYBER-FRAMEWORK-CONTEXT] diagnostic).

E. ``_cyber_final_blocking_gate`` classifies an unresolved
   ``[REQUIRES_AI_*]`` marker that lives in the KPI/KRI section as
   ``unresolved_kpi_canonical_rebuild`` instead of the generic
   ``unresolved_final_repair_marker`` code, so the diagnostic surfaces
   the architectural failure of the canonical rebuild path.

E. ``_prcy31_kpi_needs_canonical_rebuild`` now fires on ANY unresolved
   target or dash-only support cell (the legacy ``>= 2`` thresholds let
   single-row defects bypass the rebuild — the row_4 incident).

B. The [STRATEGY-PRE-SAVE-CONTRACT] diagnostic emitted by the live
   generation route includes the ``output_type`` /
   ``downstream_pipelines_allowed`` / ``preview_allowed`` /
   ``pre_contract_hash`` / ``post_contract_hash`` fields the PR-CY36
   spec mandates.
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_contract_first_save_gate_prcy36_')
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
_APP_SOURCE = ''
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    with open(_APP_PATH, 'r', encoding='utf-8') as _f:
        _APP_SOURCE = _f.read()
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


_CYBER_AR_WITH_KPI_MARKER = (
    '## 1. الرؤية الاستراتيجية\n\n'
    'تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني '
    'وفق NCA ECC و NCA DCC خلال 24 شهرًا.\n\n'
    '## 5. خارطة الطريق\n\n'
    '### المرحلة 1\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | حوكمة | 1-6 | CISO |\n\n'
    '### المرحلة 2\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | SOC | 7-18 | SOC |\n\n'
    '### المرحلة 3\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | SOAR | 19-24 | SOC |\n\n'
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | مؤشر تشغيلي مخصص | [REQUIRES_AI_TARGET_REPAIR] |'
    ' (x/y)*100 | إدارة الثغرات | شهري |\n\n'
    '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
    '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
    ' مصدر القياس | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الاستجابة | ≤ 4 ساعات | SOC | شهري |\n\n'
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n\n'
    '**درجة الثقة المُشتقة من العوامل:** 82%\n'
)


# ── A. Canonical final_contract_result object ──────────────────────
class FinalContractResultObjectTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_returns_final_contract_result_object(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_KPI_MARKER,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber',
            output_type='generation',
        )
        self.assertIn('final_contract_result', out)
        obj = out['final_contract_result']
        self.assertIsInstance(obj, dict)
        for k in ('final_markdown', 'final_sections', 'final_hash',
                  'final_frameworks', 'final_metadata', 'diagnostics',
                  'blocking_errors', 'output_type'):
            self.assertIn(k, obj, f'final_contract_result missing {k!r}')
        self.assertEqual(obj['output_type'], 'generation')
        # Frameworks must round-trip into the canonical object.
        self.assertEqual(
            sorted(obj['final_frameworks']),
            sorted(['nca_ecc', 'nca_dcc']))


# ── D. framework_context_valid on contract diag ────────────────────
class FrameworkContextValidOnContractDiagTests(unittest.TestCase):

    @_skip_if_no_app
    def test_framework_context_valid_surfaced_on_diag(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_KPI_MARKER,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber',
            output_type='generation',
        )
        self.assertIn('framework_context_valid', out['diag'])
        self.assertTrue(out['diag']['framework_context_valid'])


# ── E. KPI marker classification ──────────────────────────────────
class KpiMarkerClassifiedAsCanonicalRebuildTests(unittest.TestCase):

    @_skip_if_no_app
    def test_gate_emits_unresolved_kpi_canonical_rebuild_for_kpi_marker(self):
        # Drive the gate directly so the upstream PR-CY31 canonical
        # rebuild cannot heal the marker before the gate fires. The
        # gate is a pure classifier and must surface the canonical
        # rebuild blocking code for KPI/KRI section markers.
        kpi_body = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات | المالك | التكرار |\n'
            '|---|---|---|---|---|---|---|\n'
            '| 1 | مؤشر تشغيلي مخصص | [REQUIRES_AI_TARGET_REPAIR] |'
            ' (x/y)*100 | إدارة الثغرات | CISO | شهري |\n'
        )
        sections = {'kpis': kpi_body}
        content = kpi_body
        errors = _APP._cyber_final_blocking_gate(
            content, sections, 'ar', ['nca_ecc'], 'cyber')
        joined = ' | '.join(errors)
        self.assertIn(
            'unresolved_kpi_canonical_rebuild', joined,
            f'gate must classify KPI-section marker as canonical '
            f'rebuild failure — errors={errors}')
        # And it must NOT surface the legacy generic marker code
        # paired with ``kpis:row_N`` for KPI/KRI markers.
        for err in errors:
            if 'kpis' in err and 'REQUIRES_AI' in err:
                self.assertNotIn(
                    'unresolved_final_repair_marker', err,
                    'KPI section markers must NOT surface as the '
                    'legacy unresolved_final_repair_marker code')

    @_skip_if_no_app
    def test_gate_keeps_legacy_code_for_non_kpi_section_markers(self):
        # Non-KPI section markers continue to surface the legacy
        # ``unresolved_final_repair_marker`` code so the PR-CY27
        # row-target repair parser keeps routing them correctly.
        vision_body = (
            '## 1. الرؤية الاستراتيجية\n\n'
            'سياق رؤية يتضمن [REQUIRES_AI_VISION_REPAIR] غير محلول.\n'
        )
        sections = {'vision': vision_body}
        content = vision_body
        errors = _APP._cyber_final_blocking_gate(
            content, sections, 'ar', ['nca_ecc'], 'cyber')
        joined = ' | '.join(errors)
        self.assertIn('unresolved_final_repair_marker', joined,
                      f'errors={errors}')
        self.assertNotIn('unresolved_kpi_canonical_rebuild', joined,
                         f'errors={errors}')


# ── E. _prcy31_kpi_needs_canonical_rebuild trigger thresholds ──────
class KpiCanonicalRebuildTriggerThresholdTests(unittest.TestCase):

    _SINGLE_DEFECT_KPI_BODY_AR = (
        '## مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
        ' مصدر البيانات | المالك | التكرار |\n'
        '|---|---|---|---|---|---|---|\n'
        '| 1 | تغطية الترقيع | — | (x/y)*100 | إدارة الثغرات |'
        ' CISO | شهري |\n'
    )

    @_skip_if_no_app
    def test_single_unresolved_target_triggers_rebuild(self):
        sections = {'kpis': self._SINGLE_DEFECT_KPI_BODY_AR}
        needs, reasons = _APP._prcy31_kpi_needs_canonical_rebuild(
            sections, 'ar')
        self.assertTrue(
            needs,
            f'Single unresolved KPI target must trigger rebuild — '
            f'reasons={reasons}')
        self.assertTrue(
            any(r.startswith('unresolved_targets') for r in reasons),
            f'expected unresolved_targets reason, got {reasons}')


# ── B. [STRATEGY-PRE-SAVE-CONTRACT] diagnostic fields ─────────────
class StrategyPreSaveContractDiagnosticTests(unittest.TestCase):

    @_skip_if_no_app
    def test_pre_save_contract_diagnostic_carries_prcy36_fields(self):
        # Static-source proof: the live generation route emits the
        # PR-CY36 diagnostic fields (output_type / preview_allowed /
        # downstream_pipelines_allowed / pre_contract_hash /
        # post_contract_hash / strategy_saved / action_taken).
        # Asserting on the source keeps the test deterministic without
        # spinning up the full Flask request stack.
        self.assertIn('[STRATEGY-PRE-SAVE-CONTRACT]', _APP_SOURCE)
        # The block at the live generation route must reference the
        # mandatory PR-CY36 fields.
        idx = _APP_SOURCE.find('[STRATEGY-PRE-SAVE-CONTRACT]')
        window_start = max(0, idx - 4000)
        window_end = min(len(_APP_SOURCE), idx + 2000)
        window = _APP_SOURCE[window_start:window_end]
        for field in ("'output_type'", "'preview_allowed'",
                      "'downstream_pipelines_allowed'",
                      "'pre_contract_hash'", "'post_contract_hash'",
                      "'strategy_saved'", "'action_taken'"):
            self.assertIn(field, window,
                          f'{field} missing from pre-save diagnostic')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
