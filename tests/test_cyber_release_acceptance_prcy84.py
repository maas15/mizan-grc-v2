"""PR-CY84 — Canonicalize roadmap timeline period values before final artifact seal."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_release_acceptance_prcy84_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
_PSR = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import professional_strategy_render as _PSR
    _spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except Exception as _e:
    raise SystemExit(f'Cannot load app module: {_e!r}')


def _require_app(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


def _require_sealed(art, context='artifact'):
    if art.get('sealed') and not (art.get('blocking_errors') or []):
        return
    raise AssertionError(
        f'{context} not sealed: blocking_errors={art.get("blocking_errors")!r}')


_CANON_SO_HEADER = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
)
_VISION_SEALABLE = (
    '## 1. الرؤية والأهداف الاستراتيجية\n\n'
    '### الأهداف الاستراتيجية\n\n'
    + _CANON_SO_HEADER
    + '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO | 100% | حوكمة | 6 أشهر |\n'
    + '| 2 | SOC/CSIRT | 100% | تشغيل | 12 شهر |\n'
    + '| 3 | IAM/PAM/MFA | 95% | هوية | 12 شهر |\n'
    + '| 4 | DCC حماية البيانات | 90% | امتثال | 18 شهر |\n'
    + '| 5 | إطار ECC/DCC | 90% | تنظيمي | 18 شهر |\n'
)

_ROADMAP_CANONICAL_OK = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين وتشغيل | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
    '| المرحلة 3: تحسين واستدامة | 19-24 شهر | CSIRT | CISO | فريق | NCA ECC |\n'
)

_ROADMAP_NONCANONICAL_PERIODS = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-2 | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 1: تأسيس | 4-5 | IAM | CISO | هوية | NCA ECC |\n'
    '| المرحلة 2: تمكين | 5-6 | SOC | مدير SOC | مركز | NCA ECC |\n'
    '| المرحلة 2: تمكين وتشغيل | الشهر 10-12 | SIEM | مدير SOC | منصة | NCA ECC |\n'
    '| المرحلة 3: تحسين | 19-24 | CSIRT | CISO | فريق | NCA ECC |\n'
)

_KPI_SEALABLE = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الكشف MTTD | ≤ 60 د | كشف/SIEM | SIEM/SOC | شهري |\n'
    '| 2 | متوسط زمن الاستجابة MTTR | ≤ 4 س | استجابة | ITSM/SOAR | شهري |\n'
    '| 3 | امتثال DCC | ≥ 90% | f | DCC | ربع |\n'
)

_CONF = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص مبرر.\n'
)


def _sections(**kw):
    base = {
        'vision': _VISION_SEALABLE,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nتصنيف DLP تشفير.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP_CANONICAL_OK,
        'kpis': _KPI_SEALABLE,
        'confidence': _CONF,
    }
    base.update(kw)
    return base


def _content(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    return '\n\n'.join(
        sections[k] for k in (
            'vision', 'pillars', 'environment', 'gaps',
            'roadmap', 'kpis', 'confidence')
        if sections.get(k))


def _artifact(sections, output_type='generation', read_only=False, meta=None):
    _APP._PRCY82_CONTRACT_BYPASS_EVENTS.clear()
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata=meta or {'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type=output_type,
            read_only=read_only,
            request_context={'route_name': output_type},
            generation_mode='consulting',
        )
    return art, buf.getvalue()


def _normalize_periods(sections):
    md = _content(sections)
    return _APP._prcy84_normalize_roadmap_timeline_periods(
        sections, md, {'domain': 'cyber'},
        ['nca_ecc', 'nca_dcc'], 'ar', 'cyber',
        task_id='prcy84_unit', output_type='prcy84_unit',
        repair_actions=[])


def _roadmap_periods(sections):
    rows = _APP._prcy81_roadmap_canonical_rows(sections)
    return [(list(r) + [''] * 6)[1].strip() for r in rows]


class Prcy84PeriodNormalizationUnitTests(unittest.TestCase):
    """Direct PR-CY84 period/phase normalization (no full artifact)."""

    @_require_app
    def test_numeric_only_periods_gain_arabic_month_units(self):
        for raw in ('1-2', '4-5', '5-6'):
            phase, period = _APP._prcy84_normalize_period_cell(
                raw, 'المرحلة 1: تأسيس', 'ar')
            self.assertIn('أشهر', period, msg=f'raw={raw!r} -> {period!r}')
            self.assertNotEqual(period.strip(), raw)
            self.assertTrue(_APP._prcy84_period_satisfies_bucket(period, 1))
            self.assertEqual(phase, 'المرحلة 1: تأسيس')

    @_require_app
    def test_month_prefix_10_12_normalized_to_canonical(self):
        phase, period = _APP._prcy84_normalize_period_cell(
            'الشهر 10-12', 'المرحلة 2: تمكين', 'ar')
        self.assertEqual(period, '10-12 شهر')
        self.assertEqual(phase, 'المرحلة 2: تمكين وتشغيل')
        self.assertTrue(_APP._prcy84_period_satisfies_bucket(period, 2))

    @_require_app
    def test_parenthetical_range_moved_from_phase_to_period(self):
        phase, period = _APP._prcy84_normalize_period_cell(
            '', 'المرحلة 1: تأسيس (1-6 أشهر)', 'ar')
        self.assertEqual(phase, 'المرحلة 1: تأسيس')
        self.assertNotIn('(', phase)
        self.assertIn('أشهر', period)
        self.assertTrue(_APP._prcy84_period_satisfies_bucket(period, 1))


class Prcy84AggregateTimelineConsistencyTests(unittest.TestCase):

    @_require_app
    def test_all_phase_timeline_valid_implies_aggregate_true(self):
        rows = [
            ['المرحلة 1: تأسيس', '1-6 أشهر', 'حوكمة', 'CISO', 'هيكل', 'ECC'],
            ['المرحلة 2: تمكين وتشغيل', '7-18 شهر', 'SOC', 'SOC', 'مركز', 'ECC'],
            ['المرحلة 3: تحسين واستدامة', '19-24 شهر', 'CSIRT', 'CISO', 'فريق', 'ECC'],
        ]
        flags = _APP._prcy84_roadmap_timeline_flags_from_rows(rows)
        self.assertTrue(flags['phase_1_timeline_valid'])
        self.assertTrue(flags['phase_2_timeline_valid'])
        self.assertTrue(flags['phase_3_timeline_valid'])
        self.assertTrue(flags['roadmap_phase_timeline_valid'])
        self.assertTrue(
            _APP._prcy81_roadmap_phase_timeline_valid(
                {'roadmap': _ROADMAP_CANONICAL_OK}, 'ar'))

    @_require_app
    def test_aggregate_false_includes_invalid_rows_diagnostics(self):
        # Phase-2 row with numeric-only period (no month unit) must fail aggregate.
        rows = [
            ['المرحلة 1: تأسيس', '1-6 أشهر', 'a', 'b', 'c', 'd'],
            ['المرحلة 2: تمكين وتشغيل', '10-12', 'x', 'y', 'z', 'w'],
            ['المرحلة 3: تحسين واستدامة', '19-24 شهر', 'p', 'q', 'r', 's'],
        ]
        flags = _APP._prcy84_roadmap_timeline_flags_from_rows(rows)
        self.assertFalse(flags['roadmap_phase_timeline_valid'])
        self.assertFalse(flags['phase_2_timeline_valid'])
        inv = _APP._prcy84_collect_timeline_invalid_rows(rows)
        self.assertTrue(inv)
        self.assertEqual(inv[0]['row_index'], 1)
        self.assertIn('reason', inv[0])


class Prcy84ReleaseAcceptanceTests(unittest.TestCase):

    @_require_app
    def test_prcy84_flag_and_fingerprint(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy84'))
        fp = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        self.assertTrue(fp.get('prcy84'))

    @_require_app
    def test_live_noncanonical_roadmap_periods_normalized_before_seal(self):
        secs = _sections(roadmap=_ROADMAP_NONCANONICAL_PERIODS)
        before = _roadmap_periods(secs)
        self.assertIn('1-2', before)
        self.assertIn('الشهر 10-12', before)

        buf = io.StringIO()
        with redirect_stdout(buf):
            secs2, md2, diag, _, blocking = _normalize_periods(secs)
        log = buf.getvalue()
        self.assertIn('[ROADMAP-TIMELINE-PERIOD-NORMALIZATION]', log)
        self.assertIsNone(blocking)

        after = _roadmap_periods(secs2)
        for bad in ('1-2', '4-5', '5-6', 'الشهر 10-12'):
            self.assertNotIn(bad, after, msg=f'periods after={after!r}')
        for p in after:
            self.assertTrue(
                'شهر' in p or 'أشهر' in p,
                msg=f'missing month unit in {p!r}')

        art, out = _artifact(_sections(roadmap=secs2['roadmap']))
        _require_sealed(art, 'noncanonical fixture')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('missing_phase_timeline', joined)
        self.assertNotIn('roadmap_phase_missing_timeline:canonical_table', joined)
        self.assertIn("'prcy84': True", out)

    @_require_app
    def test_canonical_roadmap_with_normalized_periods_seals(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_CANONICAL_OK))
        _require_sealed(art)
        rows = _APP._prcy81_roadmap_canonical_rows(art.get('sections') or {})
        periods = [(list(r) + [''] * 6)[1] for r in rows]
        self.assertTrue(all('شهر' in p or 'أشهر' in p for p in periods))

    @_require_app
    def test_missing_phase_timeline_blocker_absent_after_normalization(self):
        art, log = _artifact(_sections(roadmap=_ROADMAP_NONCANONICAL_PERIODS))
        _require_sealed(art, 'normalized seal')
        errs = art.get('blocking_errors') or []
        self.assertFalse(
            any('missing_phase_timeline' in e for e in errs),
            msg=f'blocking_errors={errs!r}')
        self.assertFalse(
            any('roadmap_phase_missing_timeline:canonical_table' in e for e in errs))
        contract = re.search(
            r"\[CYBER-FINAL-ARTIFACT-CONTRACT-V2\]\s*(\{.*?\})",
            log,
            re.DOTALL)
        if contract:
            import ast
            payload = ast.literal_eval(contract.group(1))
            self.assertTrue(payload.get('roadmap_phase_timeline_valid'))
            self.assertTrue(payload.get('sealed'))

    @_require_app
    def test_aggregate_validator_is_prcy81_roadmap_phase_timeline_valid(self):
        """Documented contract: aggregate false comes from _prcy81_* (PR-CY84 path)."""
        secs = _sections(roadmap=_ROADMAP_NONCANONICAL_PERIODS)
        self.assertFalse(
            _APP._prcy81_roadmap_phase_timeline_valid(secs, 'ar'))
        secs2, _, diag, _, _ = _normalize_periods(secs)
        self.assertTrue(
            _APP._prcy81_roadmap_phase_timeline_valid(secs2, 'ar'))
        self.assertGreater(int(diag.get('normalized_cells', 0)), 0)


if __name__ == '__main__':
    unittest.main()
