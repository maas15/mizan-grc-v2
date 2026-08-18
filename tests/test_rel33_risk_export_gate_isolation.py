"""REL3.3 — ERM risk export firewall from strategy-oriented export gates.

Live staging @ 0457366 showed the ERM risk export still passing through
strategy gates:
  * the strategy section splitter minted a ``vision`` key from risk prose,
    so the pre-export domain guard emitted
    ``rel33_domain_contamination:vision:cyber_primary``;
  * the strategy roadmap model-drift gate emitted
    ``rel2_export_model_drift:roadmap_visible_row_count`` on a clean risk
    document (its treatment/priority tables counted as visible roadmap rows).

These tests pin the firewall:
  1-2. Risk DOCX/PDF export never emits rel2_export_model_drift:
       roadmap_visible_row_count (guarded by document_type; not suppressed).
  3.   Risk export never emits rel33_domain_contamination:vision:* (risk uses
       the risk-native section splitter — no vision key is ever minted).
  4.   Risk export uses the risk-native section splitter for the guard.
  5.   Clean ERM risk content (Arabic risk headings) exports DOCX + PDF.
  6.   Genuine cyber-primary ERM content still fails — through the risk-native
       domain guard (risk-native section key), NOT strategy vision.
  7-8. Strategy documents still run the roadmap model-drift gate.
  9.   Cyber/data strategy exports remain allowed.
  10.  Global gap_assessment still runs strategy drift gates (not risk-gated).
  11.  Risk frozen completeness stays risk_native.
  12.  Risk treatment evidence still counts semantic controls/treatments.
  13-14. Routing diagnostic reports risk-native routing for DOCX and PDF.
  15.  Routing diagnostic reports strategy routing for strategy exports.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel33_risk_export_gate_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_engine.export_evidence_validator import (
    validate_actual_export_evidence,
)
from release_engine_v3.contracts import RenderTree
from release_engine_v3.exporters.docx_exporter import export_docx
from release_engine_v3.exporters.pdf_exporter import export_pdf


# Clean ERM risk content — Arabic risk headings, no cyber substance, with a
# treatment/control table and a KRI table.
_CLEAN_RISK_MD = (
    '## 1. وصف السيناريو\n'
    'سيناريو مخاطر تشغيلية يهدد استمرارية الأعمال ويؤثر على شهية المخاطر.\n\n'
    '## 2. جدول تقييم المخاطر\n'
    '| الخطر | الاحتمالية | التأثير | الدرجة |\n'
    '|---|---|---|---|\n'
    '| توقف الخدمة | متوسطة | عالٍ | مرتفع |\n'
    '| فقدان بيانات | منخفضة | عالٍ | متوسط |\n\n'
    '## 4. جدول استراتيجية المعالجة\n'
    '| الضابط | النوع | الأولوية | الجدول الزمني | المالك |\n'
    '|---|---|---|---|---|\n'
    '| خطة استمرارية الأعمال | وقائي | عالية | 30 يوم | مالك المخاطر |\n'
    '| نسخ احتياطي دوري | تصحيحي | متوسطة | 45 يوم | مالك المخاطر |\n'
    '| مراجعة الضوابط | كاشف | متوسطة | 60 يوم | لجنة المخاطر |\n\n'
    '## 5. مقاييس KRI للمراقبة\n'
    '| المؤشر | الحد المقبول | التكرار |\n'
    '|---|---|---|\n'
    '| نسبة المخاطر المعالجة | ≥ 90% | شهري |\n'
    '| زمن التعافي | ≤ 4 ساعات | ربع سنوي |\n'
)

# ERM risk content with genuine cyber-PRIMARY substance (strong marker) that
# must still be blocked — but as a risk-native section, never "vision".
_CYBER_PRIMARY_RISK_MD = (
    '## 1. وصف السيناريو\n'
    'يتطلب المشروع تأسيس حوكمة الأمن السيبراني وبناء مركز العمليات الأمنية '
    'كعنصر أساسي للجهة.\n\n'
    '## 4. جدول استراتيجية المعالجة\n'
    '| الضابط | المالك |\n'
    '|---|---|\n'
    '| بناء SOC/SIEM | CISO |\n'
)

# A cyber roadmap table (family markers) used to trip the strategy roadmap
# visible-row-count model-drift gate.
_CYBER_ROADMAP_MD = (
    '## خارطة الطريق التنفيذية\n'
    '| المرحلة | الإطار الزمني | المبادرة | المالك | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1 | 1-6 أشهر | تفعيل لجنة حوكمة الأمن السيبراني | CISO | '
    'لجنة فاعلة family:governance_ciso | NCA ECC |\n'
    '| المرحلة 2 | 7-18 شهر | تشغيل SOC وSIEM | مدير SOC | '
    'مركز SOC تشغيلي family:soc_siem | NCA ECC |\n'
    '| المرحلة 2 | 7-18 شهر | تطبيق IAM/PAM/MFA | CISO | '
    'ضبط هويات family:iam_pam_mfa | NCA ECC |\n'
)

# A strategy-shaped split backend that WOULD mint a cyber "vision" key — used
# to prove the risk export path ignores it and never guards on "vision".
_STRATEGY_SPLIT_WITH_VISION = {
    'vision': (
        'رؤية: بناء مركز العمليات الأمنية وحوكمة الأمن السيبراني بقيادة CISO.'),
    'roadmap': _CYBER_ROADMAP_MD,
}


def _render_tree(markdown: str) -> RenderTree:
    return RenderTree(
        artifact_id='risk-1',
        canonical_hash='c' * 16,
        render_tree_hash='r' * 16,
        nodes=[],
        markdown_view=markdown,
    )


def _docx_backend(sections, document_type=''):
    be = {
        'build_docx_bytes': lambda content, filename, lang, **kw: b'PK-docx',
        'split_sections': lambda _c: dict(sections),
    }
    if document_type:
        be['document_type'] = document_type
    return be


def _pdf_backend(sections, document_type=''):
    be = {
        'build_pdf_bytes': lambda content, **kw: b'%PDF-bytes',
        'split_sections': lambda _c: dict(sections),
    }
    if document_type:
        be['document_type'] = document_type
    return be


class RiskExporterDomainGuardTests(unittest.TestCase):
    """Req 3, 4, 5, 6, 9 — exporter guard is risk-native for risk."""

    def test_risk_docx_clean_content_exports_despite_strategy_vision_split(self):
        res = export_docx(
            _render_tree(_CLEAN_RISK_MD),
            backend=_docx_backend(_STRATEGY_SPLIT_WITH_VISION,
                                  document_type='risk'),
            domain='erm',
            document_type='risk',
        )
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'PK-docx')

    def test_risk_pdf_clean_content_exports_despite_strategy_vision_split(self):
        res = export_pdf(
            _render_tree(_CLEAN_RISK_MD),
            backend=_pdf_backend(_STRATEGY_SPLIT_WITH_VISION,
                                 document_type='risk'),
            domain='erm',
            document_type='risk',
        )
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'%PDF-bytes')

    def test_risk_export_never_emits_vision_contamination(self):
        for exporter, backend in (
                (export_docx, _docx_backend(_STRATEGY_SPLIT_WITH_VISION,
                                            document_type='risk')),
                (export_pdf, _pdf_backend(_STRATEGY_SPLIT_WITH_VISION,
                                          document_type='risk'))):
            res = exporter(
                _render_tree(_CLEAN_RISK_MD),
                backend=backend, domain='erm', document_type='risk')
            for blk in res.blocking_errors:
                self.assertNotIn(':vision:', blk, res.blocking_errors)

    def test_risk_docx_cyber_primary_blocks_as_risk_native_not_vision(self):
        res = export_docx(
            _render_tree(_CYBER_PRIMARY_RISK_MD),
            backend=_docx_backend(_STRATEGY_SPLIT_WITH_VISION,
                                  document_type='risk'),
            domain='erm',
            document_type='risk',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertTrue(
            any('rel33_domain_contamination' in b for b in res.blocking_errors),
            res.blocking_errors)
        for blk in res.blocking_errors:
            self.assertNotIn(':vision:', blk, res.blocking_errors)

    def test_risk_pdf_cyber_primary_blocks_as_risk_native_not_vision(self):
        res = export_pdf(
            _render_tree(_CYBER_PRIMARY_RISK_MD),
            backend=_pdf_backend(_STRATEGY_SPLIT_WITH_VISION,
                                 document_type='risk'),
            domain='erm',
            document_type='risk',
        )
        self.assertEqual(res.bytes_data, b'')
        self.assertTrue(
            any('rel33_domain_contamination' in b for b in res.blocking_errors),
            res.blocking_errors)
        for blk in res.blocking_errors:
            self.assertNotIn(':vision:', blk, res.blocking_errors)

    def test_cyber_strategy_export_with_cyber_roadmap_allowed(self):
        res = export_docx(
            _render_tree(_CYBER_ROADMAP_MD),
            backend=_docx_backend({'roadmap': _CYBER_ROADMAP_MD},
                                  document_type='strategy'),
            domain='Cyber Security',
            document_type='strategy',
        )
        self.assertEqual(res.blocking_errors, [], res.blocking_errors)
        self.assertEqual(res.bytes_data, b'PK-docx')


class RoadmapModelDriftGateScopingTests(unittest.TestCase):
    """Req 1, 2, 7, 8, 10 — roadmap model-drift is strategy-only."""

    def _evidence(self, *, document_type, route='docx'):
        return validate_actual_export_evidence(
            docx_text=_CYBER_ROADMAP_MD if route == 'docx' else '',
            pdf_text=_CYBER_ROADMAP_MD if route == 'pdf' else '',
            domain='cyber',
            lang='ar',
            document_type=document_type,
            pdf_bytes_had=(route == 'pdf'),
            route_name=route,
            canonical_sections={'roadmap': ''},
        )

    def test_risk_docx_no_roadmap_model_drift(self):
        out = self._evidence(document_type='risk', route='docx')
        blk = out.get('blocking_errors') or []
        self.assertFalse(
            any('roadmap_visible_row_count' in b for b in blk), blk)

    def test_risk_pdf_no_roadmap_model_drift(self):
        out = self._evidence(document_type='risk', route='pdf')
        blk = out.get('blocking_errors') or []
        self.assertFalse(
            any('roadmap_visible_row_count' in b for b in blk), blk)

    def test_strategy_docx_still_emits_roadmap_model_drift(self):
        out = self._evidence(document_type='strategy', route='docx')
        blk = out.get('blocking_errors') or []
        self.assertTrue(
            any('roadmap_visible_row_count' in b for b in blk), blk)

    def test_gap_assessment_still_runs_roadmap_gate(self):
        out = self._evidence(document_type='gap_assessment', route='docx')
        blk = out.get('blocking_errors') or []
        self.assertTrue(
            any('roadmap_visible_row_count' in b for b in blk), blk)


class RiskEvidenceGatePreservedTests(unittest.TestCase):
    """Req 11, 12 — risk-native gates still run (never weakened)."""

    def test_clean_risk_docx_evidence_has_no_strategy_blockers(self):
        out = validate_actual_export_evidence(
            docx_text=_CLEAN_RISK_MD,
            domain='erm', lang='ar', document_type='risk',
            route_name='docx',
            canonical_sections={
                'register': _CLEAN_RISK_MD, 'treatments': _CLEAN_RISK_MD},
        )
        blk = out.get('blocking_errors') or []
        for bad in ('roadmap_visible_row_count', ':vision:',
                    'missing_pillars', 'kpi_visible_invalid'):
            self.assertFalse(any(bad in b for b in blk), (bad, blk))

    def test_empty_risk_treatment_still_blocks(self):
        # Risk content with NO treatment/control table must still fail the
        # risk-native treatment evidence gate (gate not weakened).
        no_treatment = (
            '## 1. وصف السيناريو\n'
            'وصف عام للمخاطر دون أي جدول معالجة أو ضوابط.\n')
        out = validate_actual_export_evidence(
            docx_text=no_treatment,
            domain='erm', lang='ar', document_type='risk',
            route_name='docx',
            canonical_sections={'scenario': no_treatment},
        )
        blk = out.get('blocking_errors') or []
        self.assertTrue(
            any('empty_risk_treatment' in b for b in blk), blk)


class ExportGateRoutingDiagTests(unittest.TestCase):
    """Req 13, 14, 15 — routing diagnostic reflects document_type routing."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
        cls.app_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.app_mod)

    def test_routing_diag_risk_docx(self):
        d = self.app_mod.build_rel33_export_gate_routing_diag(
            output_type='docx', route='docx', domain='erm',
            document_type='risk', artifact_type='risk', risk_id='7',
            export_handler='api_generate_docx_async',
            blocking_errors=[], passed=True)
        self.assertEqual(d['section_splitter_selected'], 'risk_native')
        self.assertEqual(d['domain_guard_selected'], 'risk_native')
        self.assertFalse(d['model_drift_gate_applied'])
        self.assertEqual(d['model_drift_gate_skipped_reason'],
                         'document_type_risk')
        self.assertIn('roadmap_visible_row_count',
                      d['strategy_gates_skipped_for_risk'])
        self.assertIn('risk_frozen_completeness', d['risk_gates_applied'])
        self.assertIn('risk_treatment_evidence', d['risk_gates_applied'])
        self.assertNotIn('vision', d['domain_guard_section_keys'])

    def test_routing_diag_risk_pdf(self):
        d = self.app_mod.build_rel33_export_gate_routing_diag(
            output_type='pdf', route='pdf', domain='erm',
            document_type='risk', artifact_type='risk', risk_id='7',
            export_handler='api_generate_pdf', blocking_errors=[], passed=True)
        self.assertEqual(d['output_type'], 'pdf')
        self.assertEqual(d['section_splitter_selected'], 'risk_native')
        self.assertFalse(d['model_drift_gate_applied'])

    def test_routing_diag_strategy_runs_model_drift(self):
        d = self.app_mod.build_rel33_export_gate_routing_diag(
            output_type='docx', route='docx', domain='cyber',
            document_type='strategy', artifact_type='strategy',
            export_handler='api_generate_docx', blocking_errors=[],
            passed=True)
        self.assertEqual(d['section_splitter_selected'], 'strategy_h2')
        self.assertTrue(d['model_drift_gate_applied'])
        self.assertEqual(d['strategy_gates_skipped_for_risk'], [])

    def test_debug_gate_off_by_default(self):
        self.assertFalse(
            self.app_mod._rel33_debug_export_allowed({}))
        self.assertFalse(
            self.app_mod._rel33_debug_export_allowed(
                {'rel33_debug_export_evidence': False}))


if __name__ == '__main__':
    unittest.main()
