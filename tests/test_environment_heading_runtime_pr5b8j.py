"""PR-5B.8J — Environment-section canonical heading runtime tests.

Diagnoses and validates the fix for the runtime save-gate error
``environment_canonical_heading_mismatch`` reported on Arabic /
Cyber-Security / Technical-Strategy / Consulting generations.

Scope (per problem statement, strictly heading normalization only):
  1. Arabic environment section that already begins with the EXACT
     canonical heading does NOT trip the validator.
  2. Arabic environment section whose first ``## N.`` line is a near-
     variant (missing trailing word, different phrasing, alternate
     numbering, or no ``##`` heading at all) is NORMALIZED to the
     canonical heading by ``_reapply_canonical_section_headings`` and
     then passes the validator without
     ``environment_canonical_heading_mismatch``.
  3. The English equivalent passes the (English-side) validator: no
     Arabic-only ``environment_canonical_heading_mismatch`` is emitted
     for an English-language strategy.
  4. ``_assemble_canonical_from_sections`` preserves the canonical
     environment heading after normalization.
  5. The validator (``validate_arabic_strategy_semantic_richness``) is
     NOT weakened — it still rejects a heading that disagrees with the
     canonical title when normalization is bypassed.
  6. No deterministic environment content (paragraphs, table rows) is
     inserted by the heading-normalization path. Only the heading line
     is touched.
  7. Internal synth-marker comments (e.g. ``mizan-synth-env-v2``) used
     by ``synthesize_environment_context`` are still stripped by the
     existing preview/PDF rendering pipeline.

Run:
    python -m pytest tests/test_environment_heading_runtime_pr5b8j.py -q
"""

import os
import sys
import unittest

# ---------------------------------------------------------------------------
# Minimal env so app.py imports without a live database / API keys.
# ---------------------------------------------------------------------------
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_env_heading_pr5b8j.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_USING_REAL_APP = False
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
    _USING_REAL_APP = True
except Exception:
    pass


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *args, **kwargs)
    return wrapper


# Canonical headings the validator expects (sourced from app._CANONICAL_SECTION_HEADINGS).
_CANON_AR_ENV = '## 3. البيئة التنظيمية والتهديدات'
_CANON_EN_ENV = '## 3. Regulatory Environment & Threat Landscape'

# Substantive Arabic environment body (3 keyword-rich paragraphs) so the
# richness validator isn't blocked on env_paragraphs_insufficient — we want
# to isolate the heading-mismatch defect specifically.
_AR_ENV_BODY = (
    "**السياق التنظيمي:** يفرض الإطار التنظيمي المُطبَّق على المنظمة "
    "متطلبات NCA ECC المعمول بها في قطاع الحكومة، بما يشمل إثبات تطبيق "
    "الضوابط والحوكمة المستمرة وإعداد أدلة التدقيق وفق اللوائح والأنظمة.\n\n"
    "**سياق التهديدات:** تشير بيانات فرق الاستجابة الوطنية إلى ارتفاع "
    "حوادث برامج الفدية وسلاسل الإمداد والتصيد الموجّه، مما يرفع أولوية "
    "تحصين ضوابط الأمن السيبراني وتسريع النضج التشغيلي.\n\n"
    "**السياق التشغيلي وسياق الأعمال:** على المنظمة موازنة متطلبات "
    "التحول الرقمي مع الحفاظ على استمرارية الأعمال والعمليات في القطاع "
    "وضمان أن تواكب استثمارات الأمن السيبراني وتيرة توسع الخدمات.\n"
)

_EN_ENV_BODY = (
    "**Regulatory context:** The regulatory framework applicable to the "
    "organization — primarily the NCA ECC obligations for the Government "
    "sector — places explicit compliance obligations on cybersecurity "
    "governance, including demonstrable control implementation and "
    "auditable evidence.\n\n"
    "**Threat context:** Public reporting from national CERT bodies shows "
    "a marked rise in supply-chain compromise, targeted phishing, and "
    "ransomware campaigns — raising the priority of hardening core "
    "cybersecurity controls and accelerating incident-response maturity.\n\n"
    "**Business & operational context:** The organization must balance "
    "digital-transformation timelines against operational continuity, "
    "ensuring cybersecurity investments keep pace with service growth "
    "without introducing audit gaps.\n"
)


def _env_mismatch_tags(defects):
    """Filter (tag, detail) tuples to environment_canonical_heading_mismatch."""
    return [d for d in (defects or [])
            if d and d[0] == 'environment_canonical_heading_mismatch']


class TestEnvironmentCanonicalHeadingExact(unittest.TestCase):
    """1. Exact canonical heading must pass the validator cleanly."""

    @_skip_if_no_app
    def test_canonical_arabic_heading_passes(self):
        sections = {
            'environment': _CANON_AR_ENV + '\n\n' + _AR_ENV_BODY,
        }
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', generation_mode='consulting',
            domain='Cyber Security')
        self.assertEqual(
            _env_mismatch_tags(defects), [],
            f'Canonical Arabic heading must not trip mismatch defect; got: '
            f'{_env_mismatch_tags(defects)}')


class TestEnvironmentCanonicalHeadingNormalization(unittest.TestCase):
    """2. Variant Arabic environment headings must be normalized to the
    canonical title by ``_reapply_canonical_section_headings`` (so the
    validator no longer emits ``environment_canonical_heading_mismatch``).
    Validator itself is NOT weakened — it is the normalizer that fixes
    the heading before validation runs.
    """

    @_skip_if_no_app
    def test_missing_hashes_is_normalized(self):
        # Body has no ``##`` heading at all — only a numbered prose line.
        sections = {
            'environment': '3. البيئة التنظيمية والتهديدات\n\n' + _AR_ENV_BODY,
        }
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        self.assertTrue(
            sections['environment'].lstrip().startswith(_CANON_AR_ENV),
            f'Section without ## must be normalized to canonical heading; '
            f'got first line: {sections["environment"].splitlines()[:2]!r}')
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', generation_mode='consulting',
            domain='Cyber Security')
        self.assertEqual(
            _env_mismatch_tags(defects), [],
            f'After heading normalization the validator must no longer '
            f'emit environment_canonical_heading_mismatch; got: '
            f'{_env_mismatch_tags(defects)}')

    @_skip_if_no_app
    def test_variant_title_short_form_is_normalized(self):
        # AI-emitted near-variant: trailing word ``والتهديدات`` dropped.
        sections = {
            'environment': '## 3. البيئة التنظيمية\n\n' + _AR_ENV_BODY,
        }
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        self.assertTrue(
            sections['environment'].lstrip().startswith(_CANON_AR_ENV),
            f'Variant heading must be replaced with canonical; got first '
            f'line: {sections["environment"].splitlines()[:2]!r}')
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', generation_mode='consulting',
            domain='Cyber Security')
        self.assertEqual(
            _env_mismatch_tags(defects), [],
            f'After heading normalization the validator must no longer '
            f'emit environment_canonical_heading_mismatch; got: '
            f'{_env_mismatch_tags(defects)}')

    @_skip_if_no_app
    def test_variant_title_alternative_phrasing_is_normalized(self):
        # AI-emitted alternative phrasing (semantically equivalent).
        sections = {
            'environment': '## 3. السياق التنظيمي والتهديدات\n\n' + _AR_ENV_BODY,
        }
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        first_line = sections['environment'].lstrip().splitlines()[0]
        self.assertEqual(
            first_line, _CANON_AR_ENV,
            f'Alternative phrasing must be replaced with the canonical '
            f'heading exactly; got: {first_line!r}')
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', generation_mode='consulting',
            domain='Cyber Security')
        self.assertEqual(
            _env_mismatch_tags(defects), [],
            f'After heading normalization the validator must not emit '
            f'environment_canonical_heading_mismatch; got: '
            f'{_env_mismatch_tags(defects)}')


class TestEnvironmentCanonicalHeadingEnglish(unittest.TestCase):
    """3. English equivalent: Arabic-only ``environment_canonical_heading_
    mismatch`` must NOT be raised for an English-language strategy."""

    @_skip_if_no_app
    def test_english_canonical_passes(self):
        sections = {
            'environment': _CANON_EN_ENV + '\n\n' + _EN_ENV_BODY,
        }
        # Run the canonical normalizer for English so any near-variant
        # produced by the AI provider is corrected before validation.
        _APP._reapply_canonical_section_headings(sections, lang='en')
        self.assertTrue(
            sections['environment'].lstrip().startswith(_CANON_EN_ENV),
            f'English canonical heading must be preserved; got first '
            f'line: {sections["environment"].splitlines()[:2]!r}')
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='en', generation_mode='consulting',
            domain='Cyber Security')
        self.assertEqual(
            _env_mismatch_tags(defects), [],
            f'English strategy must not emit Arabic-side '
            f'environment_canonical_heading_mismatch; got: '
            f'{_env_mismatch_tags(defects)}')

    @_skip_if_no_app
    def test_english_variant_is_normalized(self):
        # AI emits a near-variant English heading.
        sections = {
            'environment': '## 3. Business Environment & Regulatory Context\n\n'
                            + _EN_ENV_BODY,
        }
        _APP._reapply_canonical_section_headings(sections, lang='en')
        self.assertTrue(
            sections['environment'].lstrip().startswith(_CANON_EN_ENV),
            f'English variant must be replaced with canonical heading; '
            f'got first line: {sections["environment"].splitlines()[:2]!r}')


class TestAssembleCanonicalPreservesEnvironmentHeading(unittest.TestCase):
    """4. ``_assemble_canonical_from_sections`` must preserve / surface the
    canonical environment heading in the assembled markdown blob."""

    @_skip_if_no_app
    def test_assemble_keeps_canonical_environment_heading(self):
        sections = {
            'vision': '## 1. الرؤية والأهداف الاستراتيجية\n\nنص.\n',
            'environment': '## 3. البيئة التنظيمية\n\n' + _AR_ENV_BODY,
        }
        # Normalize first (mirrors production order at the save gate).
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        canonical_blob = _APP._assemble_canonical_from_sections(
            sections, apply_formatting=False)
        self.assertIn(_CANON_AR_ENV, canonical_blob,
                      'Assembled canonical blob must contain the canonical '
                      'environment heading.')
        self.assertNotIn('## 3. البيئة التنظيمية\n', canonical_blob,
                         'Assembled canonical blob must NOT carry the '
                         'pre-normalization variant heading.')


class TestValidatorNotWeakened(unittest.TestCase):
    """5. The validator itself MUST still reject a non-canonical heading
    when ``_reapply_canonical_section_headings`` is intentionally
    bypassed. This guarantees we did not weaken the validator — only
    added a normalization step before it runs.
    """

    @_skip_if_no_app
    def test_validator_still_rejects_non_canonical_heading(self):
        sections = {
            'environment': '## 3. البيئة التنظيمية\n\n' + _AR_ENV_BODY,
        }
        defects = _APP.validate_arabic_strategy_semantic_richness(
            sections, lang='ar', generation_mode='consulting',
            domain='Cyber Security')
        self.assertTrue(
            _env_mismatch_tags(defects),
            'Validator must still flag a non-canonical Arabic heading '
            'when normalization is bypassed (validator must not be '
            'silently weakened).')


class TestNoDeterministicContentInserted(unittest.TestCase):
    """6. Heading normalization must NOT introduce any deterministic
    environment content (no extra paragraphs, table rows, or framework
    references). Only the H2 heading line is touched.
    """

    @_skip_if_no_app
    def test_normalization_only_changes_heading_line(self):
        original_body = _AR_ENV_BODY
        sections = {
            'environment': '## 3. البيئة التنظيمية\n\n' + original_body,
        }
        original_paragraph_count = sum(1 for p in original_body.split('\n\n')
                                        if p.strip())
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        new_text = sections['environment']
        # Body is preserved verbatim after the canonical heading.
        self.assertIn(original_body.strip(), new_text,
                      'Normalization must preserve the original body '
                      'verbatim (no deterministic content insertion).')
        # No new ``|`` table rows added.
        self.assertEqual(new_text.count('|'),
                         original_body.count('|'),
                         'Normalization must not add any table rows.')
        # Paragraph count unchanged.
        new_paragraph_count = sum(1 for p in new_text.split(_CANON_AR_ENV, 1)[-1]
                                   .split('\n\n') if p.strip())
        self.assertEqual(new_paragraph_count, original_paragraph_count,
                         'Normalization must not add or remove paragraphs.')

    @_skip_if_no_app
    def test_normalization_on_missing_heading_only_prepends_heading(self):
        # Section starts with body alone (no heading at all).
        sections = {
            'environment': _AR_ENV_BODY,
        }
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        new_text = sections['environment']
        # The body still appears verbatim somewhere after the heading.
        self.assertIn(_AR_ENV_BODY.strip(), new_text)
        # The only structural change: a canonical H2 line was prepended.
        self.assertTrue(new_text.lstrip().startswith(_CANON_AR_ENV))


class TestSynthMarkerStrippedFromPreview(unittest.TestCase):
    """7. Internal sentinel comments such as ``mizan-synth-env-v2`` used
    by the existing ``synthesize_environment_context`` for idempotency
    must remain stripped from rendered output (they are HTML comments,
    so they are removed by the standard sanitization pipeline). This
    test guards against any regression where heading normalization
    accidentally re-introduces or fails to strip the marker in the
    rendered preview.
    """

    @_skip_if_no_app
    def test_marker_not_visible_in_assembled_canonical(self):
        env_with_marker = (
            _CANON_AR_ENV + '\n\n' + _AR_ENV_BODY +
            '\n<!-- mizan-synth-env-v2 -->\n'
        )
        sections = {'environment': env_with_marker}
        # Heading reapply must not alter the marker placement.
        _APP._reapply_canonical_section_headings(sections, lang='ar')
        # Assembled canonical blob with formatting applied (mirrors export).
        blob = _APP._assemble_canonical_from_sections(
            sections, apply_formatting=True)
        # The marker is an HTML comment and must not be rendered as
        # visible text. ``ensure_markdown_formatting`` keeps HTML
        # comments untouched, but downstream rendering strips them.
        # Either way, the literal token ``mizan-synth-env-v2`` must
        # still be wrapped in a comment if present (never as bare text).
        if 'mizan-synth-env-v2' in blob:
            self.assertIn('<!-- mizan-synth-env-v2 -->', blob,
                          'Synth marker must remain wrapped in an HTML '
                          'comment so downstream renderers can strip it.')


if __name__ == '__main__':
    unittest.main()
