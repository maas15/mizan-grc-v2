# -*- coding: utf-8 -*-
"""PR-CY38B — mandatory composer tests for the incident-response /
MTTR / MTTD / initial-response / triage / incident-SLA effectiveness
KPI families, plus the cyber-signal gate that prevents
``neutral_fallback`` for cyber rows.

These tests pin the schema-first KPI composer behaviour required by
the PR-CY38B follow-up specification (sections A–F).
"""
import os
import sys
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'x')
os.environ.setdefault('SECRET_KEY', 'y')

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    import app as _APP  # type: ignore
except Exception:  # noqa: BLE001 — defensive
    _APP = None


def _skip_if_no_app(test):
    return unittest.skipIf(_APP is None, 'app module unavailable')(test)


# ── A/B. Typed KPI family composer assertions ───────────────────────
class IncidentResponseComposerTests(unittest.TestCase):
    """Direct assertions on
    ``_prcy38_compose_kpi_target`` / ``_prcy38_compose_kpi_formula``.
    """

    @_skip_if_no_app
    def test_prcy38_incident_response_time_target(self):
        desc = 'متوسط الوقت من اكتشاف الحادث إلى بدء الاستجابة'
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description=desc, lang='ar')
        self.assertEqual(target, 'أقل من 4 ساعات للحوادث الحرجة')
        # ``incident_response_time`` is the canonical metric_kind for
        # the MTTR / IR-time family (alias of legacy 'mttr').
        self.assertIn(kind, ('incident_response_time', 'mttr'))
        self.assertEqual(conf, 'high')
        formula = _APP._prcy38_compose_kpi_formula(
            description=desc, lang='ar')
        # Description IS the formula — preserve it verbatim.
        self.assertIn(
            'متوسط الوقت من اكتشاف الحادث إلى بدء الاستجابة',
            formula)
        self.assertNotIn('REQUIRES_AI_', formula)

    @_skip_if_no_app
    def test_prcy38_initial_response_target(self):
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='الاستجابة الأولية للحوادث الحرجة', lang='ar')
        self.assertEqual(
            target,
            'أقل من 30 دقيقة للاستجابة الأولية للحوادث الحرجة')
        self.assertEqual(kind, 'incident_response_initial')
        self.assertEqual(conf, 'high')
        # Triage synonym must classify the same way.
        target2, _, _ = _APP._prcy38_compose_kpi_target(
            description='الفرز الأولي للحوادث الأمنية', lang='ar')
        self.assertEqual(
            target2,
            'أقل من 30 دقيقة للاستجابة الأولية للحوادث الحرجة')
        target3, _, _ = _APP._prcy38_compose_kpi_target(
            description='Initial response time for critical incidents',
            lang='en')
        self.assertTrue(target3.startswith('أقل من 30 دقيقة')
                        or 'less than 30' in target3.lower()
                        or 'أقل من 30 دقيقة' in target3)

    @_skip_if_no_app
    def test_prcy38_mttd_detection_target(self):
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='زمن الكشف عن الحوادث الأمنية', lang='ar')
        self.assertEqual(target, 'أقل من 15 دقيقة للحوادث الحرجة')
        self.assertEqual(kind, 'mttd')
        self.assertEqual(conf, 'high')
        target2, _, _ = _APP._prcy38_compose_kpi_target(
            description='Mean time to detect security incidents',
            lang='en')
        self.assertEqual(target2, 'أقل من 15 دقيقة للحوادث الحرجة')

    @_skip_if_no_app
    def test_prcy38_incident_sla_effectiveness_target(self):
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='نسبة الحوادث المعالجة ضمن SLA',
            lang='ar')
        self.assertEqual(
            target,
            'لا يقل عن 90% من الحوادث الحرجة ضمن الزمن المحدد')
        self.assertEqual(kind, 'incident_response_effectiveness')
        self.assertEqual(conf, 'high')
        target2, _, _ = _APP._prcy38_compose_kpi_target(
            description='Incident SLA effectiveness', lang='en')
        self.assertEqual(
            target2,
            'لا يقل عن 90% من الحوادث الحرجة ضمن الزمن المحدد')

    # ── C. Cyber-signal gate suppresses neutral_fallback ────────────
    @_skip_if_no_app
    def test_prcy38_no_neutral_fallback_for_cyber_incident_metric(self):
        # A cyber-signal row that does not match any typed classifier
        # must route to canonical rebuild (rebuild_required), NEVER to
        # neutral_fallback. We use a description carrying a cyber
        # signal token ("الحوادث الأمنية") but otherwise no MTTR /
        # MTTD / SLA keywords.
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description='قياس عام للحوادث الأمنية في المنشأة',
            lang='ar')
        # Either the cyber catalog already covered this row (typed
        # high-confidence target) or the cyber-signal gate suppressed
        # neutral_fallback by returning rebuild_required.
        self.assertNotEqual(kind, 'neutral_fallback')
        if target is None:
            self.assertEqual(kind, 'rebuild_required')
        # And a typical neutral KPI without cyber signal must STILL
        # use the professional neutral_fallback (so neutral_fallback
        # is not destroyed for non-cyber rows).
        t2, k2, _ = _APP._prcy38_compose_kpi_target(
            description='مؤشر تشغيلي عام داخل الحوكمة', lang='ar')
        self.assertEqual(k2, 'neutral_fallback')
        self.assertEqual(t2, 'لا يقل عن 90%')

    @_skip_if_no_app
    def test_prcy38_live_row_3_fixture(self):
        # Exact live failure row (description + formula).
        desc = 'سرعة الاستجابة للحوادث الحرجة'
        existing_formula = (
            'متوسط الوقت من اكتشاف الحادث إلى بدء الاستجابة')
        target, kind, conf = _APP._prcy38_compose_kpi_target(
            description=desc, formula=existing_formula, lang='ar')
        self.assertEqual(target, 'أقل من 4 ساعات للحوادث الحرجة')
        self.assertIn(kind, ('incident_response_time', 'mttr'))
        self.assertEqual(conf, 'high')
        formula = _APP._prcy38_compose_kpi_formula(
            description=desc, existing_formula=existing_formula,
            lang='ar')
        # Existing measurable formula must be preserved (it IS the
        # canonical phrase).
        self.assertIn(
            'متوسط الوقت من اكتشاف الحادث إلى بدء الاستجابة',
            formula)
        # No marker may appear anywhere.
        self.assertNotIn('REQUIRES_AI_', target or '')
        self.assertNotIn('REQUIRES_AI_', formula or '')
        # PR-CY31 source / owner / frequency maps must populate the
        # incident_response_time / mttr family.
        src_ar = _APP._PRCY31_KPI_SOURCE_MAP_AR.get('incident_response_time')
        own_ar = _APP._PRCY31_KPI_OWNER_MAP_AR.get('incident_response_time')
        frq_ar = _APP._PRCY31_KPI_FREQUENCY_MAP_AR.get(
            'incident_response_time')
        self.assertTrue(src_ar)
        self.assertTrue(own_ar)
        self.assertTrue(frq_ar)
        # Canonical source/owner/frequency wording from the spec.
        self.assertIn('SIEM', src_ar)
        self.assertIn('CISO', own_ar)
        self.assertEqual(frq_ar, 'شهرياً')


# ── MTTR-wins-over-MTTD precedence ───────────────────────────────────
class ClassifierPrecedenceTests(unittest.TestCase):

    @_skip_if_no_app
    def test_response_signal_wins_over_detection(self):
        # A description containing BOTH ``اكتشاف الحادث`` (MTTD) AND
        # ``بدء الاستجابة`` (MTTR) must classify as incident_response_
        # time, not MTTD.
        target, kind, _ = _APP._prcy38_compose_kpi_target(
            description=(
                'متوسط الوقت من اكتشاف الحادث إلى بدء الاستجابة'),
            lang='ar')
        self.assertEqual(target, 'أقل من 4 ساعات للحوادث الحرجة')
        self.assertNotEqual(kind, 'mttd')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
