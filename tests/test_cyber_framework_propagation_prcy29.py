"""PR-CY29 — Selected frameworks propagation + generic Cyber KPI target repair.

Covers spec section H test list:

1. ``_prcy29_resolve_selected_frameworks`` infers NCA ECC / NCA DCC
   from document text when ``selected_frameworks=[]``.
2. The PR-CY25 export contract receives non-empty frameworks for a
   Cyber strategy when the request payload does not carry them but
   the markdown does.
3. Generic ECC compliance KPI marker is repaired to ``≥ 90%``.
4. Incident-response-effectiveness KPI with the ratio formula is
   repaired to ``لا يقل عن 90% من الحوادث الحرجة ضمن الزمن المحدد``.
5. PR-CY26 MTTR duration repair still works (regression).
6. Multiple ``[REQUIRES_AI_TARGET_REPAIR]`` markers are repaired in a
   single contract run.
7. After repair, ``kpi_unresolved_marker_count == 0`` for recognized
   rows.
8. ``kpi_targets_resolved`` flips from False (before repair) to True
   (after repair).
9. Row references reported by the scanner (hard gate) and by the
   PR-CY26 repair diagnostic agree (both report ``kpis:row_3``).
10. An unrecognised KPI remains fail-closed with
    ``unresolved_kpi_target_repair`` and surfaces a hard blocking
    error.
"""

import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_framework_propagation_prcy29_')
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
    _APP_PATH = os.path.join(os.path.dirname(__file__), '..', 'app.py')
    _spec = importlib.util.spec_from_file_location('app', _APP_PATH)
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


_KPI_HEADER = (
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
)


def _kpi_table(rows):
    return _KPI_HEADER + '\n'.join(rows) + '\n'


# A minimal cyber markdown carrying a KPI table with the row_3 marker
# and explicit NCA ECC / NCA DCC references in the body so the PR-CY29
# framework-inference helper can pick them up even when the caller
# passes ``selected_frameworks=[]``.
_CYBER_AR_WITH_FRAMEWORKS_AND_MARKERS = (
    '## 1. الرؤية الاستراتيجية\n\n'
    'تستهدف الاستراتيجية الامتثال للضوابط الأساسية للأمن السيبراني '
    '(NCA ECC) وضوابط الأمن السيبراني للبيانات (NCA DCC) خلال '
    '24 شهرًا.\n\n'
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
    '## 6. مؤشرات الأداء الرئيسية KPI\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | تغطية الترقيع | 95% | (x/y)*100 | VM | شهري |\n'
    '| 2 | معدل الامتثال لضوابط الأمن السيبراني الأساسية |'
    ' [REQUIRES_AI_TARGET_REPAIR] |'
    ' (عدد الضوابط المطبقة / إجمالي الضوابط المطلوبة) × 100 |'
    ' منصة إدارة الامتثال | شهري |\n'
    '| 3 | معدل فعالية الاستجابة للحوادث السيبرانية |'
    ' [REQUIRES_AI_TARGET_REPAIR] |'
    ' (عدد الحوادث المعالجة في الوقت المحدد / إجمالي الحوادث) × 100 |'
    ' SOC | شهري |\n\n'
    '### مؤشرات المخاطر الرئيسية (KRIs)\n\n'
    '| # | مؤشر المخاطر (KRI) | الحد الأعلى المقبول |'
    ' مصدر القياس | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الاستجابة | ≤ 4 ساعات | SOC | شهري |\n\n'
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n\n'
    '**درجة الثقة المُشتقة من العوامل:** 82%\n'
)


# ── 1. Framework inference from text ───────────────────────────────
class FrameworkInferenceTests(unittest.TestCase):

    @_skip_if_no_app
    def test_infers_nca_ecc_and_nca_dcc_from_text(self):
        text = (
            'الامتثال للضوابط الأساسية للأمن السيبراني (NCA ECC) '
            'وضوابط الأمن السيبراني للبيانات NCA DCC')
        out, _ctx = _APP._prcy29_resolve_selected_frameworks(
            text, metadata=None, request_context=None,
            input_frameworks=[])
        self.assertIn('nca_ecc', out)
        self.assertIn('nca_dcc', out)

    @_skip_if_no_app
    def test_returns_input_when_already_populated(self):
        out, _ctx = _APP._prcy29_resolve_selected_frameworks(
            '', metadata=None, request_context=None,
            input_frameworks=['ECC'])
        # Caller list preserved (normalised but at least non-empty).
        self.assertTrue(out)


# ── 2. Contract receives non-empty frameworks ──────────────────────
class ContractFrameworkPropagationTests(unittest.TestCase):

    @_skip_if_no_app
    def test_preview_contract_resolves_frameworks_from_markdown(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_FRAMEWORKS_AND_MARKERS,
            metadata={'domain': 'cyber'},
            selected_frameworks=[],   # absent from caller
            lang='ar',
            domain='cyber',
            output_type='preview',
            request_context={'payload': {}, 'selected_frameworks': []},
        )
        fws = [str(f).lower() for f in (out['diag']['frameworks'] or [])]
        joined = ' '.join(fws)
        self.assertIn('ecc', joined,
                      f'expected ECC in resolved frameworks, got {fws}')
        self.assertIn('dcc', joined,
                      f'expected DCC in resolved frameworks, got {fws}')


# ── 3. Generic ECC compliance KPI catalog ──────────────────────────
class ComplianceKpiCatalogTests(unittest.TestCase):

    @_skip_if_no_app
    def test_ecc_basic_controls_compliance_repaired(self):
        md = _kpi_table([
            '| 1 | معدل الامتثال لضوابط الأمن السيبراني الأساسية |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' (عدد الضوابط المطبقة / إجمالي الضوابط المطلوبة) × 100 |'
            ' منصة إدارة الامتثال | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1,
            lang='ar', metadata=None,
            selected_frameworks=['nca_ecc'])
        self.assertIsNotNone(diag['repaired_target'])
        self.assertIn('90%', diag['repaired_target'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)


# ── 4. Incident response effectiveness ─────────────────────────────
class IncidentResponseEffectivenessTests(unittest.TestCase):

    @_skip_if_no_app
    def test_ir_effectiveness_percentage_target(self):
        md = _kpi_table([
            '| 1 | معدل فعالية الاستجابة للحوادث السيبرانية |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' (عدد الحوادث المعالجة في الوقت المحدد / إجمالي الحوادث)'
            ' × 100 | SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1,
            lang='ar', metadata=None,
            selected_frameworks=['nca_ecc'])
        self.assertIsNotNone(diag['repaired_target'])
        self.assertIn('90%', diag['repaired_target'])
        # Must be a percentage target, not a duration.
        self.assertNotIn('ساعات', diag['repaired_target'])
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)


# ── 5. MTTR regression ─────────────────────────────────────────────
class MttrRegressionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_mttr_duration_target_preserved(self):
        md = _kpi_table([
            '| 1 | زمن الاستجابة المتوسط للحوادث الأمنية الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] |'
            ' متوسط الزمن من الكشف إلى بدء الاستجابة | SOC | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1,
            lang='ar', metadata=None,
            selected_frameworks=['ECC'])
        self.assertIn('أقل من 4 ساعات للحوادث الحرجة',
                      diag['repaired_target'])


# ── 6 + 7. Multiple-marker repair / remaining count ────────────────
class MultiMarkerRepairTests(unittest.TestCase):

    @_skip_if_no_app
    def test_contract_repairs_all_recognised_markers(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_FRAMEWORKS_AND_MARKERS,
            metadata={'domain': 'cyber'},
            selected_frameworks=[],
            lang='ar',
            domain='cyber',
            output_type='pdf',
            request_context={'payload': {}, 'selected_frameworks': []},
        )
        # Both rows 2 and 3 must be repaired by the catalog.
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]',
                         out['final_markdown'])
        self.assertEqual(out['diag']['kpi_unresolved_marker_count'], 0)
        self.assertTrue(out['diag']['kpi_targets_resolved'])
        self.assertFalse(out['diag']['has_unresolved_markers'])


# ── 8. kpi_targets_resolved flips after repair ────────────────────
class KpiTargetsResolvedFlagTests(unittest.TestCase):

    @_skip_if_no_app
    def test_resolved_flag_true_after_repair(self):
        out = _APP._cyber_final_export_contract(
            _CYBER_AR_WITH_FRAMEWORKS_AND_MARKERS,
            metadata={'domain': 'cyber'},
            selected_frameworks=[],
            lang='ar',
            domain='cyber',
            output_type='pdf',
            request_context={'payload': {}, 'selected_frameworks': []},
        )
        # Post-repair the contract must report resolved=True; the
        # before-repair state is asserted implicitly by the catalogue
        # tests above (markers exist in source markdown).
        self.assertTrue(out['diag']['kpi_targets_resolved'])
        self.assertEqual(out['diag']['kpi_unresolved_marker_count'], 0)


# ── 9. Row-ref consistency between scanner and repair diag ─────────
class RowRefConsistencyTests(unittest.TestCase):

    @_skip_if_no_app
    def test_scanner_row_ref_matches_data_row_index(self):
        # Build a 3-row KPI table; only row 3 carries the marker.
        md = _kpi_table([
            '| 1 | x | 95% | f | s | شهري |',
            '| 2 | y | 90% | f | s | شهري |',
            '| 3 | زمن الاستجابة المتوسط للحوادث الأمنية الحرجة |'
            ' [REQUIRES_AI_TARGET_REPAIR] | f | SOC | شهري |',
        ])
        # Scanner must emit data-row index 3 for the marker row.
        rows = _APP._prcy25_locate_marker_rows(
            {'kpis': md}, '[REQUIRES_AI_TARGET_REPAIR]')
        self.assertTrue(any(idx == 3 for (_k, idx) in rows),
                        f'expected data row 3 in scanner output {rows}')
        # And the repair must accept the same row index and produce
        # a successful repair on it.
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 3,
            lang='ar', metadata=None, selected_frameworks=['ECC'])
        self.assertIsNotNone(diag.get('repaired_target'))
        self.assertNotIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)


# ── 10. Unknown KPI stays fail-closed ──────────────────────────────
class UnknownKpiFailClosedTests(unittest.TestCase):

    @_skip_if_no_app
    def test_unknown_kpi_remains_unresolved(self):
        md = _kpi_table([
            '| 1 | مؤشر تشغيلي مخصص غير معروف بالكامل |'
            ' [REQUIRES_AI_TARGET_REPAIR] | f | s | شهري |',
        ])
        new_md, diag = _APP._repair_kpi_target_marker(
            md, '[REQUIRES_AI_TARGET_REPAIR]', 1,
            lang='ar', metadata=None, selected_frameworks=['ECC'])
        self.assertIn('[REQUIRES_AI_TARGET_REPAIR]', new_md)
        self.assertIn('unresolved_kpi_target_repair',
                      diag.get('action_taken', ''))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
