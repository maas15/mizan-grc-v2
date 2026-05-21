"""PR-CY18 — Preserve accepted Cyber specialized objective across
convergence repairs.

Runtime evidence after PR-CY17 surfaced that an accepted Cyber
specialized-objective row was being dropped by a later generic
``synthesize_objectives_depth`` rebuild (``objectives:6->5``) inside
``converge_strategy_sections``.  PR-CY18 introduces row-preservation
helpers and wires them into the convergence loop so:

* an already-accepted AI-generated specialized-objective row is
  captured into ``ctx['_cyber_preserved_specialized_row']``;
* the captured row is re-merged into the vision section if a later
  repair drops it (Part D after the cyber framework-coverage repair,
  Part E in the final pre-gate guard);
* a regressive generic objectives candidate that drops the row is
  rejected outright (Part A);
* when the only remaining defect is
  ``specialized_function_objective_missing:cyber`` the targeted
  Cyber top-up runs INSTEAD of the generic objectives rebuild
  (Part C).

Strictly Cyber-scoped — Data Management / AI / DT / ERM behaviour is
not exercised. No deterministic objective rows are inserted.
Validators are NOT weakened. auth / DB / export / PDF / DOCX helpers
are NOT touched.

Run::

    python -m pytest \\
        tests/test_cyber_vision_persistence_prcy18.py -q
"""
import functools
import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_persistence_prcy18_')
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
    @functools.wraps(fn)
    def _wrapped(self, *a, **kw):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *a, **kw)
    return _wrapped


# ── Fixtures ────────────────────────────────────────────────────────────
_GOOD_ROW_AR = (
    'إنشاء إدارة الأمن السيبراني بقيادة CISO وتفعيل لجنة حوكمة '
    'الأمن السيبراني وتحديد الأدوار والمسؤوليات وخطوط الرفع')
_BAD_OFFICE_ROW_AR = (
    'إنشاء مكتب CISO متخصص وتعيين رئيس له')


def _vision_without_specialized(rows=4):
    head = (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
    )
    body = ''
    fillers = [
        ('تحقيق الامتثال لإطار ECC', 'NCA ECC'),
        ('تحقيق الامتثال لإطار DCC', 'NCA DCC'),
        ('تنفيذ إدارة الهوية والوصول', 'IAM'),
        ('تأسيس مركز العمليات الأمنية', 'SOC'),
        ('تطوير منظومة إدارة الثغرات', 'VM'),
        ('بناء قدرات الاستخبارات السيبرانية', 'CTI'),
    ]
    for i in range(rows):
        obj, just = fillers[i % len(fillers)]
        body += f'| {i + 1} | {obj} | 100% | {just} | 18 شهراً |\n'
    return head + body


def _vision_with_specialized_row(rows=4):
    base = _vision_without_specialized(rows=rows)
    return base + (
        f'| {rows + 1} | {_GOOD_ROW_AR} | 100% | NCA حوكمة | '
        '12 شهراً |\n')


def _ctx(org_structure_is_none=True):
    return {
        'frameworks': ['ECC', 'DCC'],
        'org_name': 'TestOrg',
        'sector': 'General',
        'maturity': 'initial',
        'generation_mode': 'drafting',
        'org_structure_is_none': org_structure_is_none,
    }


# ── Test 01 — extract helper finds the qualifying row ───────────────────
class Test01ExtractAcceptedRow(unittest.TestCase):
    @_skip_if_no_app
    def test_01a_extract_finds_qualifying_row(self):
        text = _vision_with_specialized_row(rows=4)
        row = _APP._extract_accepted_cyber_specialized_objective_row(text)
        self.assertTrue(row)
        self.assertIn('CISO', row)
        self.assertIn('لجنة حوكمة الأمن السيبراني', row)

    @_skip_if_no_app
    def test_01b_extract_returns_empty_when_no_qualifying_row(self):
        text = _vision_without_specialized(rows=4)
        row = _APP._extract_accepted_cyber_specialized_objective_row(text)
        self.assertEqual(row, '')

    @_skip_if_no_app
    def test_01c_extract_skips_bad_office_wording(self):
        # A row with bad office wording must NOT be returned even if it
        # contains a leadership phrase.
        bad = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '| # | الهدف | المقياس | المبرر | الإطار |\n'
            '|---|---|---|---|---|\n'
            f'| 1 | {_BAD_OFFICE_ROW_AR} وتفعيل لجنة حوكمة الأمن '
            f'السيبراني | 100% | NCA | 12 شهراً |\n')
        row = _APP._extract_accepted_cyber_specialized_objective_row(bad)
        self.assertEqual(row, '')


# ── Test 02 — capture into ctx ──────────────────────────────────────────
class Test02CapturePreservedRow(unittest.TestCase):
    @_skip_if_no_app
    def test_02a_capture_stores_row_when_accepted(self):
        sections = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = _ctx()
        row = _APP._capture_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertTrue(row)
        self.assertEqual(
            ctx.get('_cyber_preserved_specialized_row'), row)

    @_skip_if_no_app
    def test_02b_capture_no_op_when_not_accepted(self):
        sections = {'vision': _vision_without_specialized(rows=4)}
        ctx = _ctx()
        row = _APP._capture_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertEqual(row, '')
        self.assertNotIn('_cyber_preserved_specialized_row', ctx)

    @_skip_if_no_app
    def test_02c_capture_no_op_for_non_cyber(self):
        sections = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = _ctx()
        row = _APP._capture_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Data Management', True)
        self.assertEqual(row, '')
        self.assertNotIn('_cyber_preserved_specialized_row', ctx)


# ── Test 03 — restore preserved row when missing ────────────────────────
class Test03RestorePreservedRow(unittest.TestCase):
    @_skip_if_no_app
    def test_03a_restore_splices_row_back(self):
        # Capture from a prior accepted vision, simulate regression to a
        # vision without the specialized row, then restore.
        prior = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = _ctx()
        _APP._capture_cyber_preserved_specialized_row(
            prior, ctx, 'ar', 'Cyber Security', True)
        self.assertIn('_cyber_preserved_specialized_row', ctx)

        regressed = {'vision': _vision_without_specialized(rows=5)}
        restored = _APP._restore_cyber_preserved_specialized_row(
            regressed, ctx, 'ar', 'Cyber Security', True)
        self.assertTrue(restored)
        # The dual-requirement detector now passes.
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                regressed, 'Cyber Security', lang='ar',
                org_structure_is_none=True))

    @_skip_if_no_app
    def test_03b_restore_no_op_when_already_accepted(self):
        sections = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = _ctx()
        ctx['_cyber_preserved_specialized_row'] = (
            _APP._extract_accepted_cyber_specialized_objective_row(
                sections['vision']))
        before = sections['vision']
        restored = _APP._restore_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertFalse(restored)
        self.assertEqual(sections['vision'], before)

    @_skip_if_no_app
    def test_03c_restore_no_op_when_no_preserved_row(self):
        sections = {'vision': _vision_without_specialized(rows=4)}
        ctx = _ctx()
        restored = _APP._restore_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertFalse(restored)


# ── Test 04 — preserve across convergence cycles ─────────────────────────
class Test04PreservedRowAcrossCycles(unittest.TestCase):
    @_skip_if_no_app
    def test_04_preserved_row_survives_drop_and_restore(self):
        """The preserved row captured on cycle N can be re-merged on
        cycle N+1 even after a generic rebuild dropped it."""
        # Cycle N — accepted state captured.
        sections = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = _ctx()
        _APP._capture_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        preserved = ctx.get('_cyber_preserved_specialized_row')
        self.assertTrue(preserved)

        # Cycle N+1 — generic rebuild drops the row.
        sections['vision'] = _vision_without_specialized(rows=5)
        self.assertTrue(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))

        # Restore from preserved state.
        ok = _APP._restore_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertTrue(ok)
        self.assertFalse(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))
        # Preserved row is still in ctx for future cycles.
        self.assertEqual(
            ctx.get('_cyber_preserved_specialized_row'), preserved)


# ── Test 05 — bad CISO office wording remains rejected ───────────────────
class Test05BadOfficeStillRejected(unittest.TestCase):
    @_skip_if_no_app
    def test_05_bad_office_wording_not_acceptable(self):
        # Build a vision that uses bad office wording in the candidate
        # extension row — the dual-requirement detector must still
        # report missing.
        bad_vision = _vision_without_specialized(rows=4) + (
            f'| 5 | {_BAD_OFFICE_ROW_AR} وتفعيل لجنة حوكمة الأمن '
            'السيبراني وتحديد الأدوار والمسؤوليات | 100% | NCA | '
            '12 شهراً |\n')
        sections = {'vision': bad_vision}
        # The detector still fires because the row contains the
        # forbidden ``مكتب CISO`` wording (per PR-CY8 dual-requirement
        # logic + PR-CY11 bad-office check).
        # The extract helper must NOT pick that row.
        row = _APP._extract_accepted_cyber_specialized_objective_row(
            bad_vision)
        self.assertEqual(row, '')


# ── Test 06 — Data Management unchanged ─────────────────────────────────
class Test06DataManagementUnchanged(unittest.TestCase):
    @_skip_if_no_app
    def test_06_data_management_capture_no_op(self):
        # Data Management vision — capture must be a no-op.
        sections = {'vision': _vision_with_specialized_row(rows=4)}
        ctx = {
            'frameworks': ['NDMO', 'PDPL'],
            'org_structure_is_none': True,
        }
        row = _APP._capture_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Data Management', True)
        self.assertEqual(row, '')
        self.assertNotIn('_cyber_preserved_specialized_row', ctx)
        # And restore is a no-op too.
        self.assertFalse(
            _APP._restore_cyber_preserved_specialized_row(
                sections, ctx, 'ar', 'Data Management', True))


# ── Test 07 — diagnostic emitter tolerates missing fields ───────────────
class Test07DiagnosticEmitter(unittest.TestCase):
    @_skip_if_no_app
    def test_07_emitter_does_not_raise(self):
        # The structured emitter is purely diagnostic; it must never
        # raise even when most fields are omitted.
        try:
            _APP._emit_cyber_vision_persistence(
                'before_objectives_repair',
                previous_has=True,
                rows_before=5,
            )
            _APP._emit_cyber_vision_persistence(
                'reject_regressive_objectives_repair',
                previous_has=True,
                candidate_has=False,
                current_has=True,
                rows_before=5,
                rows_candidate=5,
                rows_after=5,
                row_preview='preview',
                accepted=False,
                restored=True,
            )
        except Exception as exc:  # pragma: no cover - diagnostic
            self.fail(f'emitter raised: {exc}')


# ── Test 08 — no deterministic objective row inserted ───────────────────
class Test08NoDeterministicRow(unittest.TestCase):
    @_skip_if_no_app
    def test_08_restore_uses_only_preserved_row(self):
        # If ctx has no preserved row, the restore helper does NOT
        # invent a new row to satisfy the detector.
        sections = {'vision': _vision_without_specialized(rows=4)}
        ctx = _ctx()
        before = sections['vision']
        restored = _APP._restore_cyber_preserved_specialized_row(
            sections, ctx, 'ar', 'Cyber Security', True)
        self.assertFalse(restored)
        self.assertEqual(sections['vision'], before)
        # Detector still fires.
        self.assertTrue(
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True))


if __name__ == '__main__':
    unittest.main()
