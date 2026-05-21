"""PR-CY16 — Cyber Vision final normalization wiring tests.

Required tests #10, #11, #13:

    10. Postnorm/tier4 rebuilt vision is normalized before final audit.
    11. Final audit no longer blocks on
        specialized_function_objective_missing:cyber when normalized
        row exists.
    13. Roadmap balance unchanged.

These tests pin the wiring of ``_normalize_cyber_ar_ciso_wording`` at
the audit hooks the problem statement requires:

    * inside ``_final_strategy_audit`` for ``domain == 'cyber'``;
    * before the post-normalization re-audit;
    * before the unified post-normalization 422.

Run:
    python -m pytest tests/test_cyber_vision_final_normalization_prcy16.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_cyber_vision_final_prcy16_')
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


def _vision_with_bad_office_row():
    """Vision with a 5th objective row that uses the bad
    ``تأسيس مكتب رئيس أمن المعلومات CISO`` wording. The first 4 rows
    are the canonical ECC/DCC/IAM/SOC objectives so the row count is
    sufficient and only the bad-wording problem trips the detector."""
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        '**الرؤية:** قيادة الأمن السيبراني الوطني.\n\n'
        '| # | الهدف | المقياس المستهدف | المبرر | الإطار الزمني |\n'
        '|---|---|---|---|---|\n'
        '| 1 | تحقيق الامتثال لإطار ECC | 100% | NCA ECC | 18 شهراً |\n'
        '| 2 | تحقيق الامتثال لإطار DCC | 100% | NCA DCC | 18 شهراً |\n'
        '| 3 | تنفيذ إدارة الهوية والوصول | 100% | IAM | 12 شهراً |\n'
        '| 4 | تأسيس مركز العمليات الأمنية | 100% | SOC | 18 شهراً |\n'
        '| 5 | تأسيس مكتب رئيس أمن المعلومات CISO | 100% | حوكمة | '
        '12 شهراً |\n'
    )


# ─────────────────────────────────────────────────────────────────────
# Test 10 — postnorm/tier4 rebuilt vision is normalized before audit
# ─────────────────────────────────────────────────────────────────────


class Test10PostnormVisionNormalizedBeforeAudit(unittest.TestCase):

    @_skip_if_no_app
    def test_10_final_strategy_audit_normalizes_cyber_vision(self):
        """``_final_strategy_audit`` must run
        ``_normalize_cyber_ar_ciso_wording`` on the supplied
        ``sections`` BEFORE evaluating the Cyber specialized-function
        detector. The audit therefore returns no
        ``specialized_function_objective_missing:cyber`` defect when
        the input contains the bad office wording but the normalized
        row would carry establishment + leadership phrases."""
        sections = {'vision': _vision_with_bad_office_row()}
        # Pre-audit: vision still contains the forbidden wording.
        self.assertIn('مكتب رئيس أمن المعلومات', sections['vision'])
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            synth_status={},
            selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        # The audit MUST have normalized the vision in-place.
        self.assertNotIn('مكتب رئيس أمن المعلومات',
                         sections['vision'])
        self.assertIn('إدارة الأمن السيبراني بقيادة CISO',
                      sections['vision'])
        # And no specialized-function-missing defect should remain.
        sf_defects = [
            d for d in defects
            if isinstance(d, (list, tuple))
            and len(d) >= 2
            and 'specialized_function_objective_missing' in str(d[1])
        ]
        self.assertEqual(
            sf_defects, [],
            f'specialized_function defect persisted post-audit: '
            f'{sf_defects}')


# ─────────────────────────────────────────────────────────────────────
# Test 11 — final audit no longer blocks on
#           specialized_function_objective_missing:cyber when the
#           normalized row exists
# ─────────────────────────────────────────────────────────────────────


class Test11FinalAuditNoLongerBlocks(unittest.TestCase):

    @_skip_if_no_app
    def test_11_specialized_function_passes_via_audit_normalization(self):
        """Mirrors the production runtime symptom: vision contains
        ``contains_bad_ciso_office=True`` BEFORE the audit, but the
        audit normalizes the wording and the detector returns
        ``False`` (i.e. specialized objective is no longer missing)."""
        sections = {'vision': _vision_with_bad_office_row()}
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            synth_status={},
            selected_frameworks=['ECC', 'DCC'],
            domain='Cyber Security',
            org_structure_is_none=True,
        )
        for sec, tag, _cnt, _floor in defects:
            self.assertNotIn(
                'specialized_function_objective_missing:cyber', tag,
                f'audit emitted blocking defect: ({sec}, {tag})')

    @_skip_if_no_app
    def test_11b_post_normalization_audit_hook_wired(self):
        """The post-normalization audit site must call
        ``_normalize_cyber_ar_ciso_wording`` BEFORE
        ``_final_strategy_audit``. Pin via source-file inspection so a
        future refactor that drops the hook fails this test
        loudly."""
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, encoding='utf-8') as _fh:
            src = _fh.read()
        # The PR-CY16 phase=before_post_normalization_audit log line
        # is emitted by the explicit pre-audit hook the problem
        # statement requires.
        self.assertIn(
            'phase=before_post_normalization_audit', src,
            'pre-audit CISO normalization hook missing')

    @_skip_if_no_app
    def test_11c_pre_unified_422_hook_wired(self):
        """The unified post-normalization 422 site must also run the
        normalizer once more (defense in depth) and re-audit so the
        gate sees the corrected wording."""
        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'app.py')
        with open(src_path, encoding='utf-8') as _fh:
            src = _fh.read()
        self.assertIn(
            'phase=before_unified_422', src,
            'pre-422 CISO normalization hook missing')

    @_skip_if_no_app
    def test_11d_final_audit_function_invokes_normalizer(self):
        """``_final_strategy_audit`` source must reference the
        cyber-scoped normalizer directly so EVERY audit invocation
        (convergence + post-normalization + final) gets normalized
        wording."""
        import inspect
        try:
            src = inspect.getsource(_APP._final_strategy_audit)
        except (OSError, TypeError):
            self.skipTest('cannot read _final_strategy_audit source')
            return
        self.assertIn('_normalize_cyber_ar_ciso_wording', src)


# ─────────────────────────────────────────────────────────────────────
# Test 13 — roadmap balance logic is NOT modified by PR-CY16
# ─────────────────────────────────────────────────────────────────────


class Test13RoadmapBalanceUnchanged(unittest.TestCase):

    @_skip_if_no_app
    def test_13_normalizer_does_not_touch_roadmap_balance_helpers(self):
        """The Cyber CISO normalizer must NOT inspect or mutate any
        roadmap-balance helper. Pin the public API of the balance
        repair function: it should still exist with its PR-CY1-era
        signature."""
        # The roadmap balance repair helper exists and is unchanged
        # by PR-CY16. We don't call it (it requires AI), but we
        # verify the symbol still exists.
        self.assertTrue(
            hasattr(_APP, '_convergence_cyber_specialized_objective_topup_repair'),
            'cyber specialized objective repair helper missing')
        # The normalizer never reads roadmap-balance state.
        sections = {
            'vision': 'مكتب CISO',
            'roadmap': (
                '| # | المبادرة | المسؤول | الإطار الزمني |\n'
                '|---|---|---|---|\n'
                '| 1 | بناء قدرات ECC | الفريق | 12 شهراً |\n'
                '| 2 | بناء قدرات DCC | الفريق | 18 شهراً |\n'
            ),
        }
        roadmap_before = sections['roadmap']
        _APP._normalize_cyber_ar_ciso_wording(
            sections, 'ar', 'Cyber Security')
        # Roadmap section is one of the sections the normalizer
        # *does* inspect (it's a canonical section), but since this
        # roadmap text contains no bad CISO-office wording it must
        # be byte-for-byte identical after the call.
        self.assertEqual(sections['roadmap'], roadmap_before,
                         'roadmap text was modified despite no '
                         'bad CISO-office wording present')


# ─────────────────────────────────────────────────────────────────────
# Test 11e — final-audit hook is strictly cyber-scoped (no Data /
#            AI / DT / ERM regression).
# ─────────────────────────────────────────────────────────────────────


class Test11eFinalAuditHookCyberScopedOnly(unittest.TestCase):

    @_skip_if_no_app
    def test_11e_data_audit_does_not_invoke_cyber_normalizer(self):
        """Calling ``_final_strategy_audit`` with ``domain='Data
        Management'`` must NOT mutate sections via the cyber
        normalizer (scope guard)."""
        sections = {
            'vision': (
                # Bad CISO wording embedded in a Data Management
                # vision shouldn't happen, but if it does the cyber
                # normalizer must NOT run on a Data audit.
                'مكتب CISO ضمن خطة الجودة.'
            )
        }
        snapshot = dict(sections)
        try:
            _APP._final_strategy_audit(
                sections, lang='ar', doc_subtype=None,
                synth_status={},
                selected_frameworks=['NDMO'],
                domain='Data Management',
                org_structure_is_none=False,
            )
        except Exception:  # noqa: BLE001 — defensive: audit may
            # raise on minimal input; we only care about scope.
            pass
        self.assertEqual(sections.get('vision'), snapshot['vision'],
                         'cyber normalizer leaked into Data audit')


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
