"""PR-5B.9AG — Data roadmap balance repair: ACCUMULATE AI top-up rows
across attempts so partial wins compound.

Runtime evidence before PR-5B.9AG:

  - PR-5B.9AF already preserved every previously-covered ORIGINAL
    roadmap row by splicing AI top-up rows into ``before_text`` each
    attempt.
  - However, partial wins from EARLIER ATTEMPTS were still lost: the
    convergence repair has a 2-attempt budget, and each attempt's
    splice used ONLY that attempt's extracted rows. So when attempt 1
    contained consent_management + data_subject_rights but missed
    breach_notification, the strict-second-pass prompt would focus
    attempt 2 on the residual (breach_notification +/or
    personal_data_classification). Attempt 2's AI response then
    contained only the residual family rows. The PR-5B.9AF splice
    rebuilt ``merged_text`` from ``before_text`` + attempt-2 rows
    alone, LOSING the consent + DSR rows attempt 1 had produced, and
    the all-or-nothing acceptance gate rejected the candidate.

PR-5B.9AG fixes this by accumulating AI-extracted top-up rows across
all attempts (first-found row wins per family). The splice is rebuilt
each attempt from ``before_text`` + the **accumulated** rows, so a
partial win on attempt 1 plus a partial win on attempt 2 produces a
fully-covered merged roadmap that the acceptance gate accepts.

Validation strategy: monkeypatch ``ai_repair_strategy_section`` on the
app module to return two scripted AI responses (attempt 1 covers
consent + DSR; attempt 2 covers breach + classification), then drive
``_convergence_data_roadmap_balance_repair`` directly and assert the
final roadmap contains all four PDPL family terms AND that the
``synth_status`` does NOT contain a ``roadmap: failed`` marker.

Run::

    python -m pytest \\
        tests/test_data_pdpl_roadmap_topup_accumulate_pr5b9ag.py -q
"""
import importlib.util
import inspect
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_data_pr5b9ag_')
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
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
except (ImportError, ModuleNotFoundError) as _e:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_e}')
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


_FRAMEWORKS = ['NDMO', 'PDPL']


# Original roadmap covers the non-PDPL balance topics (data quality,
# data catalog, data lifecycle, privacy_governance via "حوكمة الخصوصية")
# and the governance-office setup, but NONE of the PDPL DSR / breach /
# consent / classification literal terms. Both attempts will therefore
# see the same 4 PDPL families as unmet at entry.
_ORIGINAL_ROADMAP = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المالك | الإطار الزمني | المخرج |\n'
    '|---|------|------|------|------|\n'
    '| 1 | تأسيس مكتب إدارة البيانات وتعيين رئيس البيانات (CDO) '
    '| الإدارة العليا | Q1 | ميثاق مكتب البيانات |\n'
    '| 2 | إطلاق برنامج إدارة جودة البيانات | CDO | Q2 | مقاييس |\n'
    '| 3 | بناء كتالوج البيانات والبيانات الوصفية | CDO | Q2 | كتالوج |\n'
    '| 4 | دورة حياة البيانات والاحتفاظ والإتلاف | CDO | Q3 | سياسة |\n'
    '| 5 | حوكمة الخصوصية | CDO | Q3 | سياسة |\n'
)


# Attempt-1 AI response: covers consent_management + data_subject_rights
# (two of the four PDPL families) but NOT breach_notification or
# personal_data_classification.
_AI_ATTEMPT_1 = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
    '|---|--------|---------|----------------|--------|\n'
    '| A1 | إدارة الموافقات وسجل الموافقات والموافقة الصريحة '
    '| CDO | Q1 | سجل الموافقات |\n'
    '| A2 | تفعيل آلية حقوق صاحب البيانات: حق الوصول، حق التصحيح، '
    'حق الحذف، طلبات أصحاب البيانات '
    '| مسؤول حماية البيانات | Q2 | آلية حقوق صاحب البيانات |\n'
)


# Attempt-2 AI response (under the second-pass strict prompt): covers
# breach_notification + personal_data_classification but does NOT
# repeat the consent / DSR rows. Without PR-5B.9AG, splicing only
# these rows into ``before_text`` would lose the attempt-1 wins and
# the all-or-nothing acceptance gate would reject the candidate.
_AI_ATTEMPT_2 = (
    '## 5. خارطة الطريق\n\n'
    '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
    '|---|--------|---------|----------------|--------|\n'
    '| B1 | تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات '
    '| مسؤول حماية البيانات | Q2 | آلية إخطار الخروقات |\n'
    '| B2 | تطبيق تصنيف البيانات الشخصية وربطه بضوابط PDPL '
    '| مسؤول حماية البيانات | Q2 | إطار تصنيف البيانات الشخصية معتمد |\n'
)


class _ScriptedAIRepair:
    """Callable used to monkeypatch ``ai_repair_strategy_section`` on
    the app module. Returns the next scripted AI response per call and
    records the validation_error each call received so tests can
    assert that the second-pass strict prompt is delivered on
    attempt 2.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if not self._responses:
            raise _APP.RepairError(
                'scripted_ai_repair_exhausted')
        return self._responses.pop(0)


def _walk_status_failed(node, section='roadmap'):
    if isinstance(node, dict):
        if node.get(section) == 'failed':
            return True
        for v in node.values():
            if _walk_status_failed(v, section):
                return True
    return False


def _build_sections():
    return {
        'vision': '## 1. الرؤية\n',
        'pillars': '## 2. الركائز الاستراتيجية\n',
        'environment': '## 3. السياق التنظيمي\nNDMO and PDPL.\n',
        'gaps': '## 4. تحليل الفجوات\n',
        'roadmap': _ORIGINAL_ROADMAP,
        'kpis': '## 6. مؤشرات الأداء\n',
        'confidence': '## 7. تقييم الجاهزية\n',
    }


def _build_ctx():
    return {'frameworks': _FRAMEWORKS,
            'org_structure_is_none': False,
            'org_name': 'Test', 'sector': 'General',
            'maturity': 'initial',
            'generation_mode': 'drafting'}


class TestSourceWiring(unittest.TestCase):
    """Source-level assertions: the PR-5B.9AG accumulator is wired
    into the convergence balance repair and does not regress prior
    contracts.
    """

    @_skip_if_no_app
    def test_01_source_references_accumulator(self):
        src = inspect.getsource(
            _APP._convergence_data_roadmap_balance_repair)
        # PR-5B.9AG marker + accumulator initialization + per-family
        # first-found-wins merge + accumulated splice.
        self.assertIn('PR-5B.9AG', src)
        self.assertIn('_accumulated_extracted', src)
        # The splice uses the accumulator, not the current attempt's
        # extraction alone.
        self.assertIn('_accumulated_extracted[f]', src)
        self.assertIn(
            '_splice_data_roadmap_topup_rows(\n                before_text',
            src.replace('\r', ''))
        # PR-5B.9AF / 9AA / 9AD / 9AE contracts are preserved.
        self.assertIn('PR-5B.9AF', src)
        self.assertIn('_data_roadmap_topup_required_terms_map(', src)
        self.assertIn('_extract_data_roadmap_topup_rows(', src)
        self.assertIn('_splice_data_roadmap_topup_rows(', src)
        self.assertIn('while attempt < 2 and not accepted', src)
        self.assertIn('SECOND-PASS STRICT REQUIREMENT', src)
        self.assertIn('_pdpl_save_guard_required_terms(_ufam)', src)
        self.assertIn('_mark_synth_failed', src)


class TestAccumulationAcceptance(unittest.TestCase):
    """End-to-end: with scripted AI responses where attempt 1 covers
    consent+DSR and attempt 2 covers breach+classification, the
    accumulator must yield a fully-covered roadmap that the
    acceptance gate accepts (no ``synth_failed:roadmap`` marker, and
    the final roadmap contains all four PDPL family terms verbatim).
    """

    @_skip_if_no_app
    def test_02_partial_wins_compound_across_attempts(self):
        scripted = _ScriptedAIRepair([_AI_ATTEMPT_1, _AI_ATTEMPT_2])
        _orig = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = scripted
        try:
            sections = _build_sections()
            ctx = _build_ctx()
            log = {'synth_status': {}}
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_data_roadmap_balance_repair(
                    sections, 'ar', 'Data Management', ctx, log, 1)
            out = buf.getvalue()
        finally:
            _APP.ai_repair_strategy_section = _orig

        # Both attempts were invoked (proving partial-win on attempt 1
        # did not short-circuit acceptance).
        self.assertEqual(
            len(scripted.calls), 2,
            f'expected 2 AI attempts, got {len(scripted.calls)}; '
            f'log out:\n{out}')
        # The second call must carry the second-pass strict prompt.
        self.assertIn(
            'SECOND-PASS STRICT REQUIREMENT',
            scripted.calls[1].get('validation_error', ''),
            'attempt 2 prompt missing the second-pass strict clause')

        final_roadmap = sections['roadmap']
        # All four PDPL family literal AR terms appear verbatim in the
        # final spliced roadmap (consent + DSR from attempt 1; breach +
        # classification from attempt 2). Without PR-5B.9AG only the
        # attempt-2 rows would have survived the splice.
        for needle, family in (
            ('إدارة الموافقات', 'consent_management'),
            ('حقوق صاحب البيانات', 'data_subject_rights'),
            ('إخطار الخروقات', 'breach_notification'),
            ('تصنيف البيانات الشخصية',
             'personal_data_classification'),
        ):
            self.assertIn(
                needle, final_roadmap,
                f'final roadmap missing required term for {family}: '
                f'{needle!r}; log out:\n{out}')

        # Every original roadmap line is preserved verbatim
        # (PR-5B.9AF guarantee, still in force).
        for ln in _ORIGINAL_ROADMAP.split('\n'):
            if not ln.strip():
                continue
            self.assertIn(
                ln, final_roadmap,
                f'original roadmap line dropped: {ln!r}')

        # Acceptance gate passed — no roadmap synth_failed marker.
        self.assertFalse(
            _walk_status_failed(log, 'roadmap'),
            'expected acceptance (no synth_failed:roadmap), '
            f'log={log}; out=\n{out}')

        # PR-5B.9AG accumulator diagnostic must surface in the log:
        # the accumulated_families set on attempt 2 should be the
        # union of both attempts.
        self.assertIn('mode=topup', out)
        self.assertIn('accumulated_families=', out)

    @_skip_if_no_app
    def test_03_accumulator_records_first_found_per_family(self):
        """When both attempts emit a row for the same family, the
        accumulator keeps the first one (first-found wins). This is
        the conservative semantics: an already-accepted row cannot
        regress because a later attempt re-emits it differently.
        """
        # Attempt 1 covers consent + DSR; attempt 2 RE-emits consent
        # with a different filler plus breach + classification. The
        # accumulator must retain attempt-1's consent row verbatim.
        ai_attempt_2_with_dup = (
            '## 5. خارطة الطريق\n\n'
            '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
            '|---|--------|---------|----------------|--------|\n'
            '| C1 | إدارة الموافقات بصياغة بديلة | DPO | Q4 | بديل |\n'
            '| B1 | تفعيل إخطار الخروقات والإبلاغ عن الانتهاكات '
            '| مسؤول حماية البيانات | Q2 | آلية |\n'
            '| B2 | تطبيق تصنيف البيانات الشخصية وربطه بضوابط PDPL '
            '| مسؤول حماية البيانات | Q2 | إطار |\n'
        )
        scripted = _ScriptedAIRepair(
            [_AI_ATTEMPT_1, ai_attempt_2_with_dup])
        _orig = _APP.ai_repair_strategy_section
        _APP.ai_repair_strategy_section = scripted
        try:
            sections = _build_sections()
            ctx = _build_ctx()
            log = {'synth_status': {}}
            buf = io.StringIO()
            with redirect_stdout(buf):
                _APP._convergence_data_roadmap_balance_repair(
                    sections, 'ar', 'Data Management', ctx, log, 1)
        finally:
            _APP.ai_repair_strategy_section = _orig

        final_roadmap = sections['roadmap']
        # First-found wins: the attempt-1 consent row (with "سجل
        # الموافقات") must be the consent row that survived, not the
        # attempt-2 "بصياغة بديلة" variant.
        self.assertIn('سجل الموافقات', final_roadmap)
        self.assertNotIn('بصياغة بديلة', final_roadmap)
        # And the other three families are still covered.
        for needle in ('حقوق صاحب البيانات', 'إخطار الخروقات',
                       'تصنيف البيانات الشخصية'):
            self.assertIn(needle, final_roadmap)
        self.assertFalse(_walk_status_failed(log, 'roadmap'))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
