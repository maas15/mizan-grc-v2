"""PR-CY85 — Scope Strategic Objectives validation to canonical vision table."""

import functools
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_release_acceptance_prcy85_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault(
    'DATABASE_URL',
    'sqlite:///' + os.path.join(_TMP, 'test.db'),
)
os.environ.setdefault('OPENAI_API_KEY', '')

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
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

_ROADMAP_RESOURCE_ROW = (
    '## 5. خارطة الطريق\n\n'
    '| # | البند | الوصف | التوقيت | التكلفة |\n'
    '|---|---|---|---|---|\n'
    '| 1 | الأجهزة | معدات أمنية | حسب الحاجة | '
    '1.2 مليون ريال <!-- trace:section=roadmap;src=bank_fallback;key=row_1 --> |\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين وتشغيل | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
    '| المرحلة 3: تحسين واستدامة | 19-24 شهر | CSIRT | CISO | فريق | NCA ECC |\n'
)

# Canonical 6-col roadmap table (resource row lives only in 5-col table above).
_ROADMAP_CANONICAL = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين وتشغيل | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
    '| المرحلة 3: تحسين واستدامة | 19-24 شهر | CSIRT | CISO | فريق | NCA ECC |\n'
    '\n'
    '| # | البند | الوصف | التوقيت | التكلفة |\n'
    '|---|---|---|---|---|\n'
    '| 1 | الأجهزة | معدات أمنية | حسب الحاجة | '
    '1.2 مليون ريال <!-- trace:section=roadmap;src=bank_fallback;key=row_1 --> |\n'
)

_KPI_TRACE = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف | قيمة | صيغة | مصدر | تواتر |\n'
    '|---|---|---|---|---|\n'
    '| 1 | MTTD | ≤ 60 د | f | SIEM <!-- trace:section=kpis --> | شهري |\n'
    '| 2 | MTTR | ≤ 4 س | f | ITSM | شهري |\n'
    '| 3 | DCC | ≥ 90% | f | DCC | ربع |\n'
)

_GAPS_TRACE = (
    '## 4. الفجوات\n\n'
    '| # | فجوة | خطوة |\n'
    '|---|---|---|\n'
    '| 1 | Gap | step <!-- trace:section=gaps --> |\n'
    '\nGap #1 Implementation Guide steps.\n'
)

_CONF = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص <!-- trace:section=confidence -->\n'
)

_KPI_SEALABLE = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساس |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الكشف MTTD | ≤ 60 د | كشف/SIEM | SIEM/SOC | شهري |\n'
    '| 2 | متوسط زمن الاستجابة MTTR | ≤ 4 س | استجابة | ITSM/SOAR | شهري |\n'
    '| 3 | امتثال DCC | ≥ 90% | f | DCC | ربع |\n'
)


def _sections(**kw):
    base = {
        'vision': _VISION_SEALABLE,
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nتصنيف DLP.\n',
        'gaps': _GAPS_TRACE,
        'roadmap': _ROADMAP_CANONICAL,
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


def _artifact(sections, output_type='generation'):
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            _content(sections),
            sections=dict(sections),
            metadata={'domain': 'cyber'},
            selected_frameworks=['nca_ecc', 'nca_dcc'],
            lang='ar',
            domain='cyber',
            output_type=output_type,
            request_context={'route_name': output_type},
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class Prcy85ScopeGuardUnitTests(unittest.TestCase):

    @_require_app
    def test_roadmap_resource_row_ignored_by_so_validation(self):
        secs = _sections(roadmap=_ROADMAP_CANONICAL)
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertFalse(
            any('strategic_objectives_incomplete_row:1' in i for i in issues),
            msg=f'issues={issues!r}')
        ignored, traces = _APP._prcy85_collect_ignored_cross_section_rows(secs)
        self.assertGreaterEqual(len(ignored), 1)
        self.assertIn('roadmap', traces)

    @_require_app
    def test_kpi_trace_row_ignored(self):
        secs = _sections(kpis=_KPI_TRACE)
        canon = _APP._extract_canonical_strategic_objective_rows(
            secs['vision'], lang='ar')
        self.assertEqual(len(canon), 5)
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertFalse(
            any('incomplete_row' in i and ':1' in i for i in issues
                if 'roadmap' in str(secs)))

    @_require_app
    def test_gaps_trace_row_ignored(self):
        gaps_5col = (
            '## 4. الفجوات\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            '| 1 | فجوة | خطوة | سبب | 6 أشهر '
            '<!-- trace:section=gaps --> |\n'
        )
        secs = _sections(gaps=gaps_5col)
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertFalse(
            any('strategic_objectives_incomplete_row:1' in i for i in issues))
        ignored, traces = _APP._prcy85_collect_ignored_cross_section_rows(secs)
        self.assertIn('gaps', traces)

    @_require_app
    def test_confidence_section_ignored_for_so_rows(self):
        secs = _sections()
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertFalse(
            any('confidence' in i for i in issues))

    @_require_app
    def test_only_canonical_vision_rows_validated(self):
        secs = _sections()
        canon = _APP._extract_canonical_strategic_objective_rows(
            secs['vision'], lang='ar')
        self.assertEqual(len(canon), 5)
        self.assertTrue(all(r['source_section'] == 'vision' for r in canon))

    @_require_app
    def test_true_incomplete_canonical_row_detected(self):
        bad_vision = _VISION_SEALABLE + (
            '| 6 | هدف ناقص |  | مبرر | 6 أشهر |\n')
        secs = _sections(vision=bad_vision)
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertTrue(
            any(i.startswith('strategic_objectives_incomplete_row:')
                for i in issues))

    @_require_app
    def test_cannot_emit_incomplete_for_roadmap_trace(self):
        row = (
            '| 1 | الأجهزة | معدات أمنية | حسب الحاجة | '
            '1.2 مليون ريال <!-- trace:section=roadmap --> |')
        secs = {
            'vision': _VISION_SEALABLE,
            'roadmap': '## 5.\n\n' + row + '\n',
        }
        issues = _APP._prcy85_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertNotIn('strategic_objectives_incomplete_row:1', issues)

    @_require_app
    def test_scope_guard_diag_fields_for_live_pattern(self):
        secs = _sections()
        diag = _APP._prcy85_scope_guard_snapshot(
            secs, 'ar', phase='unit', domain='cyber')
        self.assertTrue(diag['canonical_so_header_found'])
        self.assertGreaterEqual(diag['ignored_cross_section_rows_count'], 1)
        self.assertIn('roadmap', diag['ignored_trace_sections'])
        self.assertIsNone(diag['blocking_error_if_any'])


class Prcy85ReleaseAcceptanceTests(unittest.TestCase):

    @_require_app
    def test_prcy85_flag_and_fingerprint(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy85'))
        fp = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        self.assertTrue(fp.get('prcy85'))

    @_require_app
    def test_live_pattern_fixture_seals(self):
        art, log = _artifact(_sections())
        _require_sealed(art, 'live_pattern')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('strategic_objectives_incomplete_row:1', joined)
        self.assertNotIn('strategic_objectives_incomplete_row', joined)
        self.assertIn('[STRATEGIC-OBJECTIVES-SCOPE-GUARD]', log)
        self.assertIn("'prcy85': True", log)

    @_require_app
    def test_stale_incomplete_stripped_when_canonical_valid(self):
        secs = _sections()
        stale = [
            'strategic_objectives_incomplete_row:1',
            'kpi_assessment_guides_missing',
        ]
        refined = _APP._prcy85_strip_stale_cross_section_so_issues(
            stale, secs, 'ar')
        self.assertNotIn('strategic_objectives_incomplete_row:1', refined)
        self.assertIn('kpi_assessment_guides_missing', refined)

    @_require_app
    def test_incomplete_canonical_row_still_detected(self):
        bad = _VISION_SEALABLE + '| 6 |  |  |  |  |\n'
        secs = _sections(vision=bad)
        issues = _APP._prcy80_strategic_objectives_incomplete_rows(secs, 'ar')
        self.assertTrue(
            any(i.startswith('strategic_objectives_incomplete_row:')
                for i in issues))
        diag = _APP._prcy63_collect_invalid_so_row_diag(secs['vision'], 'ar')
        self.assertTrue(diag)


if __name__ == '__main__':
    unittest.main()
