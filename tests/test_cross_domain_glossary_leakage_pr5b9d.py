"""PR-5B.9D — Cross-domain glossary leakage fix.

Pins the appendix glossary contract: only the selected frameworks, the
current domain baseline, and terms materially present in the document
AND relevant to that domain may appear. Cross-domain framework acronyms
(SOC, CSIRT, VPN, ZTNA, NDMO, PDPL, ISO31000, COSO ERM, ISO27001,
NIST AI RMF, etc.) MUST NOT auto-inject into a non-matching domain's
appendix simply because they exist in the global registry.

These tests assert:

  1. Data appendix does NOT include NIST AI RMF, AI Governance,
     ISO31000, COSO ERM, ISO27001 unless explicitly selected.
  2. AI appendix does NOT include NDMO, ISO31000, COSO ERM, ISO27001
     unless explicitly selected.
  3. Cyber appendix does NOT include NDMO, PDPL, AI Governance, COSO
     ERM, ISO31000 unless explicitly selected.
  4. DT appendix does NOT include SOC, CSIRT, VPN, ZTNA, DLP unless
     explicitly selected or literally present in content.
  5. ERM appendix does NOT include SOC, CSIRT, VPN, ZTNA, AI
     Governance, NDMO unless explicitly selected or literally present.
  6. Selecting a framework on its native domain DOES include it (the
     filter must not over-strip).
  7. ``_export_quality_gate_check`` emits ``glossary_cross_domain_leak``
     warning when an unrelated acronym auto-injects despite the strip.

Run:
    python -m pytest tests/test_cross_domain_glossary_leakage_pr5b9d.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_glossary_pr5b9d_')
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


def _appendix_acronyms(appendix_entries):
    """Return the set of acronym labels (text after '• ') from an
    appendix entries list."""
    out = set()
    for label, _body in (appendix_entries or []):
        if isinstance(label, str) and label.startswith('•'):
            ac = label.lstrip('• ').strip()
            if ac:
                out.add(ac)
    return out


# A neutral content blob that does NOT literally cite any cross-domain
# acronym so the strip pass should remove all forbidden auto-baseline
# entries.
_NEUTRAL_CONTENT_AR = (
    'استراتيجية تركز على القدرات التشغيلية وحوكمة المجال المحدد. '
    'تقتصر على المصطلحات ذات الصلة بالمجال المختار.'
)


# ── Tests ────────────────────────────────────────────────────────────────
class CrossDomainGlossaryLeakageTests(unittest.TestCase):

    @_skip_if_no_app
    def test_01_data_glossary_does_not_leak_ai_erm_iso27001_terms(self):
        """Per PR-5B.9D Part E: Data appendix must not include NIST AI
        RMF, ISO31000, COSO ERM, ISO27001, AI_GOV unless selected.
        Acronyms are checked using their *display* form (the appendix
        emits human-friendly labels)."""
        appendix = _APP._build_appendices_block(
            selected_fws_keys=[],  # NDMO/PDPL not selected either
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='data',
        )
        acronyms = _appendix_acronyms(appendix)
        for forbidden in ('NIST AI RMF', 'AI Governance', 'ISO 31000',
                          'COSO ERM', 'ISO 27001'):
            self.assertNotIn(
                forbidden, acronyms,
                f'data glossary leaked {forbidden}: {acronyms}',
            )

    @_skip_if_no_app
    def test_02_ai_glossary_does_not_leak_ndmo_erm_iso27001_terms(self):
        appendix = _APP._build_appendices_block(
            selected_fws_keys=[],
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='ai',
        )
        acronyms = _appendix_acronyms(appendix)
        for forbidden in ('NDMO', 'ISO 31000', 'COSO ERM', 'ISO 27001'):
            self.assertNotIn(
                forbidden, acronyms,
                f'ai glossary leaked {forbidden}: {acronyms}',
            )

    @_skip_if_no_app
    def test_03_cyber_glossary_does_not_leak_ndmo_pdpl_ai_erm_terms(self):
        appendix = _APP._build_appendices_block(
            selected_fws_keys=[],
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='cyber',
        )
        acronyms = _appendix_acronyms(appendix)
        for forbidden in ('NDMO', 'PDPL', 'AI Governance', 'COSO ERM',
                          'ISO 31000'):
            self.assertNotIn(
                forbidden, acronyms,
                f'cyber glossary leaked {forbidden}: {acronyms}',
            )

    @_skip_if_no_app
    def test_04_dt_glossary_does_not_leak_cyber_terms(self):
        appendix = _APP._build_appendices_block(
            selected_fws_keys=[],
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='dt',
        )
        acronyms = _appendix_acronyms(appendix)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'DLP'):
            self.assertNotIn(
                forbidden, acronyms,
                f'dt glossary leaked {forbidden}: {acronyms}',
            )

    @_skip_if_no_app
    def test_05_erm_glossary_does_not_leak_cyber_ai_data_terms(self):
        appendix = _APP._build_appendices_block(
            selected_fws_keys=[],
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='erm',
        )
        acronyms = _appendix_acronyms(appendix)
        for forbidden in ('SOC', 'CSIRT', 'VPN', 'ZTNA', 'AI Governance',
                          'NDMO'):
            self.assertNotIn(
                forbidden, acronyms,
                f'erm glossary leaked {forbidden}: {acronyms}',
            )

    @_skip_if_no_app
    def test_06_native_domain_baseline_still_appears(self):
        """Filter must not over-strip the domain's own baseline. We
        check the *display* acronym (the appendix uses the human-
        friendly form via ``_GLOSSARY_DISPLAY_ACRONYM``)."""
        cases = [
            ('data', 'NDMO'),
            ('data', 'PDPL'),
            ('erm',  'ISO 31000'),
            ('erm',  'Risk Register'),
            ('cyber', 'IAM'),
            ('cyber', 'SOC'),
            ('ai',   'SDAIA'),
            ('dt',   'DGA'),
        ]
        for code, expected in cases:
            with self.subTest(domain=code, acronym=expected):
                appendix = _APP._build_appendices_block(
                    selected_fws_keys=[],
                    lang='ar',
                    content_sections={'body': _NEUTRAL_CONTENT_AR},
                    domain_code=code,
                )
                acronyms = _appendix_acronyms(appendix)
                self.assertIn(
                    expected, acronyms,
                    f'{code}: native baseline acronym {expected} missing '
                    f'(got {sorted(acronyms)})',
                )

    @_skip_if_no_app
    def test_07_selected_framework_overrides_forbidden(self):
        """If the user explicitly selects a framework, it MUST appear
        in the appendix even if listed as forbidden by domain."""
        # ISO27001 is forbidden on Data domain by default, but if
        # selected it should still appear in Appendix A.
        appendix = _APP._build_appendices_block(
            selected_fws_keys=['ISO27001'],
            lang='ar',
            content_sections={'body': _NEUTRAL_CONTENT_AR},
            domain_code='data',
        )
        acronyms = _appendix_acronyms(appendix)
        self.assertIn(
            'ISO27001', acronyms,
            'selected framework ISO27001 must appear in data appendix '
            'even though it is normally forbidden on data',
        )


class GlossaryLeakageQualityWarningTests(unittest.TestCase):
    """``_export_quality_gate_check`` emits the
    ``glossary_cross_domain_leak:<acronym>`` warning when a forbidden
    acronym ends up in the appendix despite not being literally cited
    in the strategy content."""

    @_skip_if_no_app
    def test_08_quality_gate_emits_cross_domain_leak_warning(self):
        # Hand-construct an appendix list with a leaked ('SOC') acronym
        # that the strategy content does NOT literally cite.
        leaked_appendix = [
            ('Appendix A — Reference Frameworks', '...'),
            ('• NDMO', 'NDMO'),
            ('• SOC', 'Security Operations Center'),  # leaked into data
        ]
        fn = getattr(_APP, '_export_quality_gate_check', None)
        if fn is None:
            self.skipTest('_export_quality_gate_check not exported')
        # The function logs warnings to stdout (it does not return them).
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            fn(
                domain_code='data',
                lang='ar',
                content=_NEUTRAL_CONTENT_AR,
                doc_control_rows=[],
                methodology_rows=[],
                scope_items=[],
                traceability={'rows': [{}]},
                appendices=leaked_appendix,
                fws_keys=[],
                frameworks_inferred=[],
            )
        out = buf.getvalue()
        self.assertIn(
            'glossary_cross_domain_leak:SOC', out,
            f'expected glossary_cross_domain_leak:SOC in stdout, got '
            f'{out!r}',
        )


if __name__ == '__main__':
    unittest.main()
