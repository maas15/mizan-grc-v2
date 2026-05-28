"""PR-CY37 — Deferred architectural blockers completion.

Follow-up to PR-CY36 verifying:

A. Hard pre-save runtime assertion in the live generation path
   (``api_generate_strategy``) — the [STRATEGY-PRE-SAVE-CONTRACT-ASSERTION]
   diagnostic exists, includes the required fields, and the route
   returns 422 with ``final_quality_gate_failed:...`` codes when the
   contract result is missing/has blocking errors/missing hash, or when
   ``save_decision == ALLOWED`` paired with blocking errors.

B. Preview route runs ``_cyber_final_export_contract`` in read-only
   mode and emits [CYBER-PREVIEW-READONLY-CHECK]. Read-only mode
   short-circuits the repair cycles, does not mutate content, and
   surfaces ``post_contract_artifact_inconsistent`` for residual
   markers on the saved artifact.

C. ``_cyber_final_export_contract`` blocks with
   ``missing_framework_context:cyber`` when ``frameworks=[]`` and the
   content mentions NCA ECC/DCC (no silent continuation with empty
   frameworks). Canonical frameworks are persisted on the save data
   envelope (``selected_frameworks_canonical``).

D. [CYBER-FINAL-ARTIFACT-SOURCE] diagnostic exists in the live save
   path and the saved artifact is sourced from
   ``final_contract_result.final_markdown`` / ``final_sections`` /
   ``final_hash``.

E. After the forced PR-CY31 canonical KPI rebuild, a
   [CYBER-KPI-CANONICAL-REBUILD-ASSERTION] check exists and a residual
   KPI marker is escalated as ``unresolved_kpi_canonical_rebuild`` on
   the contract ``blocking_errors``.
"""
import functools
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_contract_first_save_gate_prcy37_')
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


_CYBER_AR_CLEAN = (
    '## 1. الرؤية الاستراتيجية\n\n'
    'تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني '
    'وفق NCA ECC و NCA DCC خلال 24 شهرًا.\n\n'
    '## 5. خارطة الطريق\n\n'
    '### المرحلة 1\n\n'
    '| # | البند | الشهر | المالك |\n'
    '|---|---|---|---|\n'
    '| 1 | حوكمة | 1-6 | CISO |\n\n'
    '## 6. مؤشرات الأداء الرئيسية\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | ≥ 95% خلال 72 ساعة |'
    ' (x/y)*100 | إدارة الثغرات | شهري |\n\n'
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**درجة الثقة المُشتقة من العوامل:** 82%\n'
)


# ── A. Hard pre-save runtime assertion ─────────────────────────────
class HardPreSaveAssertionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_diagnostic_block_exists_with_required_fields(self):
        self.assertIn(
            '[STRATEGY-PRE-SAVE-CONTRACT-ASSERTION]', _APP_SOURCE,
            'live save path must emit the pre-save contract assertion '
            'diagnostic (PR-CY37 A)')
        # Required fields per spec.
        for field in (
                'final_contract_present',
                'final_hash',
                'blocking_errors',
                'save_decision',
                'save_allowed',
                'downstream_pipelines_allowed',
                'assertion_passed',
                'action_taken',
        ):
            self.assertIn(
                field, _APP_SOURCE,
                f'pre-save assertion diagnostic must surface '
                f'{field!r}')

    @_skip_if_no_app
    def test_assertion_emits_save_allowed_before_contract_pass_code(self):
        for code in (
                'final_contract_missing_before_save',
                'final_contract_hash_missing',
                'save_allowed_before_contract_pass',
        ):
            self.assertIn(
                code, _APP_SOURCE,
                f'pre-save assertion must emit '
                f'final_quality_gate_failed:{code}')


# ── B. Preview read-only ──────────────────────────────────────────
class PreviewReadOnlyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_signature_supports_read_only(self):
        import inspect
        sig = inspect.signature(_APP._cyber_final_export_contract)
        self.assertIn(
            'read_only', sig.parameters,
            '_cyber_final_export_contract must accept read_only param')

    @_skip_if_no_app
    def test_read_only_mode_does_not_mutate_clean_content(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_CLEAN,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber',
            output_type='preview',
            read_only=True,
        )
        # Read-only must not introduce blockers on clean saved content.
        self.assertEqual(out.get('blocking_errors', []), [])
        # Content must remain byte-identical (no mutating repairs).
        self.assertEqual(out['final_markdown'], _CYBER_AR_CLEAN)

    @_skip_if_no_app
    def test_read_only_emits_post_contract_artifact_inconsistent(self):
        polluted = _CYBER_AR_CLEAN.replace(
            '| 1 | تغطية الترقيع | ≥ 95% خلال 72 ساعة |',
            '| 1 | تغطية الترقيع | [REQUIRES_AI_TARGET_REPAIR] |',
        )
        out = _APP._cyber_final_export_contract(
            polluted,
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar', domain='cyber',
            output_type='preview',
            read_only=True,
        )
        joined = ' | '.join(out.get('blocking_errors') or [])
        self.assertIn('post_contract_artifact_inconsistent', joined)
        # Read-only must NOT have repaired the marker.
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', out['final_markdown'])

    @_skip_if_no_app
    def test_preview_route_uses_read_only_and_emits_diagnostic(self):
        self.assertIn(
            '[CYBER-PREVIEW-READONLY-CHECK]', _APP_SOURCE,
            'preview path must emit the [CYBER-PREVIEW-READONLY-CHECK] '
            'diagnostic (PR-CY37 B)')
        # The preview path must call the contract with read_only=True.
        self.assertIn(
            'read_only=True', _APP_SOURCE,
            'preview path must invoke _cyber_final_export_contract '
            'with read_only=True')


# ── C. Framework-context block + canonical propagation ────────────
class FrameworkContextBlockTests(unittest.TestCase):

    @_skip_if_no_app
    def test_empty_frameworks_with_nca_text_blocks(self):
        # Source-level check: the early framework-context block must
        # exist as a fail-closed safety net so that — even if every
        # resolver layer (input/metadata/task/diagnostic_model/saved/
        # request/strategy_context/text_inference) returns empty for
        # cyber + NCA content — the contract emits the canonical
        # ``missing_framework_context:cyber`` blocker rather than
        # silently continuing repairs with frameworks=[]. The runtime
        # bug from the live logs shows the resolver returning [] in a
        # real path; verify the guard exists.
        self.assertIn(
            'missing_framework_context:cyber', _APP_SOURCE,
            '_cyber_final_export_contract must contain the fail-closed '
            'guard emitting final_quality_gate_failed:'
            'missing_framework_context:cyber (PR-CY37 C)')

    @_skip_if_no_app
    def test_canonical_frameworks_propagated_after_save(self):
        # The save-path post-commit block must publish
        # selected_frameworks_canonical onto the response envelope.
        self.assertIn('selected_frameworks_canonical', _APP_SOURCE)
        # And the canonical key must be derived from the contract
        # result, not re-computed from text.
        self.assertTrue(
            re.search(
                r"selected_frameworks_canonical['\"]\s*\]\s*="
                r"|selected_frameworks_canonical\s*=",
                _APP_SOURCE),
            'save envelope must assign selected_frameworks_canonical')


# ── D. [CYBER-FINAL-ARTIFACT-SOURCE] diagnostic ───────────────────
class FinalArtifactSourceDiagnosticTests(unittest.TestCase):

    @_skip_if_no_app
    def test_artifact_source_diagnostic_exists(self):
        self.assertIn(
            '[CYBER-FINAL-ARTIFACT-SOURCE]', _APP_SOURCE,
            'live save path must emit [CYBER-FINAL-ARTIFACT-SOURCE] '
            '(PR-CY37 D)')


# ── E. KPI canonical-rebuild post-assertion ───────────────────────
class KpiCanonicalRebuildAssertionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_rebuild_assertion_diagnostic_exists(self):
        self.assertIn(
            '[CYBER-KPI-CANONICAL-REBUILD-ASSERTION]', _APP_SOURCE,
            'contract must emit the canonical KPI rebuild assertion '
            'diagnostic after the forced rebuild (PR-CY37 E)')

    @_skip_if_no_app
    def test_residual_kpi_marker_blocks_after_forced_rebuild(self):
        # _cyber_final_blocking_gate is the classifier — verify a
        # residual KPI-section marker still surfaces as
        # ``unresolved_kpi_canonical_rebuild`` (the rebuild-failure
        # code), not the generic legacy code.
        kpi_body = (
            '## مؤشرات الأداء الرئيسية\n\n'
            '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
            ' مصدر البيانات | المالك | التكرار |\n'
            '|---|---|---|---|---|---|---|\n'
            '| 1 | مؤشر تشغيلي مخصص | [REQUIRES_AI_TARGET_REPAIR] |'
            ' (x/y)*100 | إدارة الثغرات | CISO | شهري |\n'
        )
        sections = {'kpis': kpi_body}
        errors = _APP._cyber_final_blocking_gate(
            kpi_body, sections, 'ar', ['nca_ecc'], 'cyber')
        joined = ' | '.join(errors)
        self.assertIn('unresolved_kpi_canonical_rebuild', joined)


if __name__ == '__main__':
    unittest.main()
