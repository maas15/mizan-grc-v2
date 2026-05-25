"""PR-CY32 follow-up — Verify that ``_cyber_final_export_contract``
forces the PR-CY31 9-column KPI canonical rebuild immediately before
the hard blocking gate, and blocks with the dedicated reason codes
when the rebuild cannot upgrade the table or markers survive.

Covers:

A. ``_prcy32_followup_old_kpi_schema_detected`` correctly distinguishes
   the legacy 5-column schema from the canonical 9-column rebuild.
B. The contract appends
   ``final_quality_gate_failed:kpi_canonical_rebuild_not_applied:old_schema_detected``
   when the markdown carries the legacy header.
C. The contract appends
   ``final_quality_gate_failed:unresolved_kpi_canonical_rebuild:...``
   when ``[REQUIRES_AI_*]`` markers survive the forced rebuild.
D. A markdown that already carries a clean 9-column rebuild passes the
   contract gate (no new blocking errors introduced by the follow-up).
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(
    prefix='test_cyber_kpi_canonical_rebuild_forced_prcy32_followup_')
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
        'app',
        os.path.join(os.path.dirname(__file__), '..', 'app.py'),
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as e:  # noqa: BLE001
    raise SystemExit(f'Cannot load app module: {e!r}')


MARKER = _APP._PRCY26_KPI_TARGET_MARKER


# ─────────────────────────────────────────────────────────────────────
# Helpers — build minimal fully-formed cyber strategy markdown so the
# contract gate evaluates the KPI section without aborting earlier on
# unrelated structural requirements. The shared template provides every
# H2 the splitter recognizes; per-test variants only replace the KPI
# block.
# ─────────────────────────────────────────────────────────────────────


_PROLOGUE_AR = (
    '## الرؤية الاستراتيجية\n'
    'رؤية\n\n'
    '## الركائز الاستراتيجية\n'
    'ركائز\n\n'
    '## البيئة التنظيمية\n'
    'بيئة\n\n'
    '## تحليل الفجوات\n'
    'فجوات\n\n'
    '## خارطة الطريق التنفيذية\n'
    'خارطة\n\n'
)
_EPILOGUE_AR = (
    '\n## تقييم الثقة\n'
    'ثقة\n'
)


_LEGACY_KPI_AR = (
    '## مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة |'
    ' صيغة الاحتساب | المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|---|\n'
    '| 1 | معدل الامتثال لضوابط ECC | 90% |'
    ' عدد الضوابط المطبقة / الإجمالي × 100 | الامتثال للوائح |'
    ' 12 شهرًا |\n'
    '| 2 | متوسط زمن الاستجابة للحوادث | 4 ساعات |'
    ' مجموع أزمنة الاستجابة / عدد الحوادث | تقليل أثر الحوادث |'
    ' 12 شهرًا |\n'
)


_MARKER_KPI_AR = (
    '## مؤشرات الأداء\n\n'
    '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة |'
    ' صيغة الاحتساب | مصدر البيانات | المالك | التكرار |'
    ' الإطار الزمني |\n'
    '|---|---|---|---|---|---|---|---|---|\n'
    f'| 1 | معدل الامتثال لضوابط ECC | KPI | {MARKER} |'
    ' عدد الضوابط المطبقة / الإجمالي × 100 | سجلات الامتثال |'
    ' رئيس إدارة الأمن السيبراني | ربع سنوي | 12 شهرًا |\n'
    f'| 2 | متوسط زمن الاستجابة MTTR | KPI | {MARKER} |'
    ' مجموع أزمنة الاستجابة / عدد الحوادث | نظام SIEM |'
    ' رئيس مركز العمليات الأمنية | شهري | 12 شهرًا |\n'
)


_CLEAN_KPI_AR = (
    '## مؤشرات الأداء\n\n'
    '| # | المؤشر | النوع KPI/KRI | القيمة المستهدفة |'
    ' صيغة الاحتساب | مصدر البيانات | المالك | التكرار |'
    ' الإطار الزمني |\n'
    '|---|---|---|---|---|---|---|---|---|\n'
    '| 1 | معدل الامتثال لضوابط ECC | KPI | ≥ 90% |'
    ' عدد الضوابط المطبقة / الإجمالي × 100 | سجلات الامتثال |'
    ' رئيس إدارة الأمن السيبراني | ربع سنوي | 12 شهرًا |\n'
    '| 2 | متوسط زمن الاستجابة MTTR | KPI | ≤ 4 ساعات |'
    ' مجموع أزمنة الاستجابة / عدد الحوادث | نظام SIEM |'
    ' رئيس مركز العمليات الأمنية | شهري | 12 شهرًا |\n'
)


def _wrap(kpi_section):
    return _PROLOGUE_AR + kpi_section + _EPILOGUE_AR


class PRCY32FollowupHeaderDetectionTests(unittest.TestCase):
    def test_detects_legacy_5_column_header(self):
        self.assertTrue(
            _APP._prcy32_followup_old_kpi_schema_detected(
                _LEGACY_KPI_AR))

    def test_canonical_9_column_header_not_flagged(self):
        self.assertFalse(
            _APP._prcy32_followup_old_kpi_schema_detected(
                _CLEAN_KPI_AR))

    def test_empty_or_non_string_body_not_flagged(self):
        self.assertFalse(
            _APP._prcy32_followup_old_kpi_schema_detected(''))
        self.assertFalse(
            _APP._prcy32_followup_old_kpi_schema_detected(None))


class PRCY32FollowupForcedRebuildContractTests(unittest.TestCase):
    def test_legacy_header_blocks_with_dedicated_reason(self):
        md = _wrap(_LEGACY_KPI_AR)
        result = _APP._cyber_final_export_contract(
            md, metadata={}, selected_frameworks=['nca_ecc'],
            lang='ar', domain='cyber', output_type='unit-test')
        joined = '\n'.join(result.get('blocking_errors') or [])
        kpi_body = (result.get('sections') or {}).get('kpis', '') or ''
        # Either the upstream audit / forced rebuild upgraded the
        # legacy 5-column schema to the canonical 9-column schema, or
        # the follow-up gate fails closed with the dedicated reason
        # code. The contract must NEVER release legacy bytes silently.
        if _APP._prcy32_followup_old_kpi_schema_detected(kpi_body):
            self.assertIn(
                'kpi_canonical_rebuild_not_applied:old_schema_detected',
                joined,
            )
        else:
            self.assertIn('النوع KPI/KRI', kpi_body)
            self.assertIn('مصدر البيانات', kpi_body)

    def test_marker_survives_forced_rebuild_path_emits_unresolved(self):
        md = _wrap(_MARKER_KPI_AR)
        result = _APP._cyber_final_export_contract(
            md, metadata={}, selected_frameworks=['nca_ecc'],
            lang='ar', domain='cyber', output_type='unit-test')
        joined = '\n'.join(result.get('blocking_errors') or [])
        # Forced rebuild should have replaced the markers; if anything
        # still slipped through, the dedicated "unresolved_kpi_canonical_rebuild"
        # blocking code must appear. Either way the contract must
        # have applied the canonical 9-column schema.
        kpi_body = (result.get('sections') or {}).get('kpis', '') or ''
        if 'unresolved_kpi_canonical_rebuild' in joined:
            self.assertIn('[REQUIRES_AI_', result.get('final_markdown', ''))
        else:
            # When rebuild succeeded the canonical header survives and
            # no markers remain.
            self.assertIn('النوع KPI/KRI', kpi_body)
            self.assertNotIn('[REQUIRES_AI_', result.get(
                'final_markdown', ''))

    def test_clean_canonical_kpi_does_not_introduce_new_blockers(self):
        md = _wrap(_CLEAN_KPI_AR)
        result = _APP._cyber_final_export_contract(
            md, metadata={}, selected_frameworks=['nca_ecc'],
            lang='ar', domain='cyber', output_type='unit-test')
        joined = '\n'.join(result.get('blocking_errors') or [])
        # The forced rebuild must be a no-op on an already-canonical
        # table.
        self.assertNotIn(
            'kpi_canonical_rebuild_not_applied:old_schema_detected',
            joined,
        )
        self.assertNotIn(
            'unresolved_kpi_canonical_rebuild', joined)


if __name__ == '__main__':
    unittest.main()
