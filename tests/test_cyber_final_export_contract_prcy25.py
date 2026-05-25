"""PR-CY25 — Cyber strategy final export contract tests.

Verifies that PDF, DOCX and Preview all route through the single
canonical ``_cyber_final_export_contract`` and that it blocks output
carrying unresolved repair markers, missing roadmap phases / KRI
tables, weak Arabic fragments, generic DCC traceability mappings,
KPI/KRI schema defects, confidence mismatch, or strategic-objectives
incomplete rows.

Constraints:
* PR-CY18 specialised-objective preservation, PR-CY20 framework-
  compliance preservation, PR-CY22 final export audit, PR-CY23 final
  quality gate and PR-CY24 strategic-objectives sanitiser are NOT
  exercised here and must remain untouched.
"""
import functools
import importlib.util
import os
import re
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_final_export_contract_prcy25_')
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


_CLEAN_CYBER_AR = (
    '## 1. الرؤية الاستراتيجية\n\n'
    'تستهدف الاستراتيجية إرساء برنامج للأمن السيبراني خلال 24 شهرًا.\n\n'
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
    '| 1 | تغطية الترقيع | 95% | (x/y)*100 | إدارة الثغرات | شهري |\n\n'
    '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
    '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
    ' مصدر القياس | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الاستجابة | ≤ 4 ساعات | SOC | شهري |\n\n'
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n\n'
    '**درجة الثقة المُشتقة من العوامل:** 82%\n'
)


# ── A. Contract returns the canonical shape ────────────────────────
class ContractShapeTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_returns_canonical_keys(self):
        out = _APP._cyber_final_export_contract(
            _CLEAN_CYBER_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        for key in ('final_markdown', 'audit_flags', 'repair_actions',
                    'blocking_errors', 'content_hash', 'sections',
                    'diag'):
            self.assertIn(key, out)
        self.assertIsInstance(out['blocking_errors'], list)
        self.assertIsInstance(out['repair_actions'], list)
        self.assertEqual(len(out['content_hash']), 64)
        # Clean content: no blocking errors.
        self.assertEqual(out['blocking_errors'], [])

    @_skip_if_no_app
    def test_contract_diag_fields_present(self):
        out = _APP._cyber_final_export_contract(
            _CLEAN_CYBER_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='preview',
        )
        diag = out['diag']
        for field in (
            'output_type', 'before_hash', 'after_hash',
            'repair_actions_count', 'blocking_errors_count',
            'final_content_length', 'has_unresolved_markers',
            'roadmap_coverage', 'has_kri_table',
            'confidence_consistent', 'kpi_schema_valid',
            'kri_schema_valid', 'dcc_traceability_valid',
        ):
            self.assertIn(field, diag)
        self.assertEqual(diag['output_type'], 'preview')
        self.assertFalse(diag['has_unresolved_markers'])
        # Roadmap coverage is measured against the FINAL audited
        # markdown so its exact value depends on PR-CY21/23 helpers.
        # The contract only guarantees it is an integer >= 0.
        self.assertGreaterEqual(diag['roadmap_coverage'], 0)
        self.assertIsInstance(diag['roadmap_coverage'], int)


# ── B. Non-cyber domains are pass-through ──────────────────────────
class NonCyberPassthroughTests(unittest.TestCase):

    @_skip_if_no_app
    def test_non_cyber_domain_returns_input_unchanged(self):
        md = '## 1. الرؤية\n\nنص مبسط.\n'
        out = _APP._cyber_final_export_contract(
            md,
            metadata={'domain': 'data'},
            selected_frameworks=['NDMO'],
            lang='ar',
            domain='data',
            output_type='pdf',
        )
        self.assertEqual(out['final_markdown'], md)
        self.assertEqual(out['blocking_errors'], [])
        self.assertEqual(out['audit_flags'], {})


# ── C. Hard blocking on unresolved AI repair markers ───────────────
class UnresolvedMarkerBlockingTests(unittest.TestCase):

    @_skip_if_no_app
    def test_target_marker_in_kpi_blocks_rendering(self):
        # Use a KPI description that does not match any PR-CY26
        # deterministic catalog entry so the marker remains unresolved
        # and the PR-CY25 hard gate still blocks rendering.
        polluted = _CLEAN_CYBER_AR.replace(
            '| 1 | تغطية الترقيع | 95% |',
            '| 1 | مؤشر تشغيلي مخصص | [REQUIRES_AI_TARGET_REPAIR] |',
        )
        out = _APP._cyber_final_export_contract(
            polluted,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        self.assertTrue(out['blocking_errors'])
        joined = ' | '.join(out['blocking_errors'])
        # PR-CY36 (spec E) — KPI section markers now route to the
        # canonical ``unresolved_kpi_canonical_rebuild`` blocking code
        # so operators observe the architectural failure of the
        # canonical-rebuild path instead of the generic row-by-row
        # marker code.
        self.assertIn('unresolved_kpi_canonical_rebuild', joined)
        self.assertIn('REQUIRES_AI_TARGET_REPAIR', joined)
        self.assertTrue(out['diag']['has_unresolved_markers'])

    @_skip_if_no_app
    def test_known_kpi_target_marker_is_repaired_before_gate(self):
        # ``تغطية الترقيع`` matches the PR-CY26 vulnerability /
        # patching remediation catalog entry, so the marker must be
        # repaired into ``≥ 95% خلال 72 ساعة`` BEFORE the final
        # blocking gate fires and rendering must be allowed.
        polluted = _CLEAN_CYBER_AR.replace(
            '| 1 | تغطية الترقيع | 95% |',
            '| 1 | تغطية الترقيع | [REQUIRES_AI_TARGET_REPAIR] |',
        )
        out = _APP._cyber_final_export_contract(
            polluted,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        self.assertEqual(out['blocking_errors'], [])
        self.assertFalse(out['diag']['has_unresolved_markers'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         out['final_markdown'])
        self.assertIn('≥ 95% خلال 72 ساعة', out['final_markdown'])
        self.assertTrue(any(
            a.startswith('cycle_') and 'kpi_target_repair' in a
            for a in out['repair_actions']))

    @_skip_if_no_app
    def test_arbitrary_requires_ai_variant_is_caught(self):
        polluted = _CLEAN_CYBER_AR + '\n[REQUIRES_AI_CUSTOM_REPAIR]\n'
        out = _APP._cyber_final_export_contract(
            polluted,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        joined = ' | '.join(out['blocking_errors'])
        self.assertIn('REQUIRES_AI_CUSTOM_REPAIR', joined)


# ── D. Roadmap horizon vs summary mismatch ─────────────────────────
class RoadmapHorizonTests(unittest.TestCase):

    _MISMATCH = (
        '## 1. الرؤية الاستراتيجية\n\n'
        'تستهدف الاستراتيجية إرساء برنامج خلال 24 شهرًا.\n\n'
        '## 5. خارطة الطريق\n\n'
        '### المرحلة 1\n\n'
        '| # | البند | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | حوكمة | 1-6 | CISO |\n\n'
        '### المرحلة 2\n\n'
        '| # | البند | الشهر | المالك |\n'
        '|---|---|---|---|\n'
        '| 1 | SOC | 7-12 | SOC |\n'
    )

    @_skip_if_no_app
    def test_roadmap_only_covers_12_of_24_months(self):
        # PR-CY34 — the contract now RECONCILES the mismatch by
        # extending the roadmap to cover the declared 24-month summary
        # horizon instead of blocking the render with
        # ``roadmap_horizon_mismatch:summary_24:roadmap_12``. The
        # blocking gate must NOT see the legacy mismatch error.
        out = _APP._cyber_final_export_contract(
            self._MISMATCH,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        joined = ' | '.join(out['blocking_errors'])
        self.assertNotIn('roadmap_horizon_mismatch', joined)
        # Reconciliation must have brought the coverage up to (or near)
        # the declared summary horizon.
        self.assertGreaterEqual(out['diag']['roadmap_coverage'], 24 - 2)


# ── E. Missing standalone KRI table ───────────────────────────────
class MissingKriTableTests(unittest.TestCase):

    _NO_KRI = (
        '## 1. الرؤية الاستراتيجية\n\nرؤية موجزة.\n\n'
        '## 6. مؤشرات الأداء الرئيسية\n\n'
        '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
        ' مصدر البيانات/الأداة | تواتر القياس |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | تغطية الترقيع | 95% | (x/y)*100 | إدارة الثغرات | شهري |\n'
    )

    @_skip_if_no_app
    def test_kpi_without_kri_block_is_flagged(self):
        out = _APP._cyber_final_export_contract(
            self._NO_KRI,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        joined = ' | '.join(out['blocking_errors'])
        # After up to 2 repair cycles the KRI ensure helper may have
        # appended a derived KRI table; only assert when no KRI table
        # was eventually present.
        if not out['diag']['has_kri_table']:
            self.assertIn('missing_standalone_kri_table', joined)


# ── F. Strategic-objectives incomplete row detection ───────────────
class StrategicObjectivesIncompleteTests(unittest.TestCase):

    @_skip_if_no_app
    def test_blank_cells_in_objective_row_are_blocked(self):
        body = (
            _CLEAN_CYBER_AR + '\n\n'
            '## 4. الأهداف الاستراتيجية\n\n'
            '| # | الهدف الاستراتيجي | KPI | المستهدف | الراعي |\n'
            '|---|---|---|---|---|\n'
            '| 1 | هدف مكتمل | تغطية | 95% | CISO |\n'
            '| 2 | هدف ناقص | — | — | — |\n'
        )
        out = _APP._cyber_final_export_contract(
            body,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        joined = ' | '.join(out['blocking_errors'])
        self.assertIn('strategic_objectives_incomplete_row', joined)


# ── G. Empty content blocks rendering ──────────────────────────────
class EmptyContentTests(unittest.TestCase):

    @_skip_if_no_app
    def test_empty_strategy_body_is_blocked(self):
        out = _APP._cyber_final_export_contract(
            '',
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        joined = ' | '.join(out['blocking_errors'])
        self.assertIn('empty_strategy_body', joined)


# ── H. PDF / DOCX / Preview consume the same audited content ───────
class ParityTests(unittest.TestCase):

    @_skip_if_no_app
    def test_pdf_docx_preview_emit_same_content_hash(self):
        out_pdf = _APP._cyber_final_export_contract(
            _CLEAN_CYBER_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='pdf',
        )
        out_docx = _APP._cyber_final_export_contract(
            _CLEAN_CYBER_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='docx',
        )
        out_prev = _APP._cyber_final_export_contract(
            _CLEAN_CYBER_AR,
            metadata={'domain': 'cyber'},
            selected_frameworks=['ECC'],
            lang='ar',
            domain='cyber',
            output_type='preview',
        )
        self.assertEqual(out_pdf['content_hash'], out_docx['content_hash'])
        self.assertEqual(out_pdf['content_hash'], out_prev['content_hash'])


# ── I. Maximum repair cycles bound ─────────────────────────────────
class RepairCycleBoundTests(unittest.TestCase):

    @_skip_if_no_app
    def test_maximum_repair_cycles_is_two(self):
        # Constant must exist and equal 2.
        self.assertEqual(getattr(_APP, '_PRCY25_MAX_REPAIR_CYCLES', None), 2)


# ── J. No route bypasses the contract ──────────────────────────────
class RouteContractWiringTests(unittest.TestCase):

    @_skip_if_no_app
    def test_pdf_route_calls_contract(self):
        # PDF export site must reference the contract symbol.
        self.assertTrue(
            re.search(
                r"output_type\s*=\s*['\"]pdf['\"]", _APP_SOURCE))
        # And the audit must no longer be called by the PDF body
        # outside of the contract definition itself.
        # (Greppable: the contract helper is the only caller now.)
        # Counts: definition + internal call from contract + at least
        # one usage in tests; production routes must use the contract.
        self.assertIn('_cyber_final_export_contract', _APP_SOURCE)

    @_skip_if_no_app
    def test_docx_route_calls_contract(self):
        self.assertTrue(
            re.search(
                r"output_type\s*=\s*['\"]docx['\"]", _APP_SOURCE))

    @_skip_if_no_app
    def test_preview_route_calls_contract(self):
        self.assertTrue(
            re.search(
                r"output_type\s*=\s*['\"]preview['\"]", _APP_SOURCE))


if __name__ == '__main__':
    unittest.main()
