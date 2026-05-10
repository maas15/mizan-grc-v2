"""Tests for standalone bold pillar heading normalization in
ensure_markdown_formatting.

Addresses: Arabic strategy preview/export shows pillar headings such as
  "**الركيزة 2: عمليات مركز العمليات الأمنية (SOC)**"
as highlighted/inline bold blocks instead of clean full-width H3
subheadings. The PRE-PILLAR pass must convert standalone bold pillar
titles (alone on their line) to "### الركيزة N: ..." H3 form.
"""

import sys
import os
import importlib.util
import unittest

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///tmp/test_pillar_headings.db')
os.environ.setdefault('OPENAI_API_KEY', 'dummy')
os.environ.setdefault('ANTHROPIC_API_KEY', 'dummy')
os.environ.setdefault('GOOGLE_API_KEY', 'dummy')

_USING_REAL_APP = False
_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
    _USING_REAL_APP = True
except Exception as _import_err:  # pragma: no cover
    print(f'[WARN] Could not import app.py: {_import_err}')


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not _USING_REAL_APP:
            self.skipTest('app.py not importable in this environment')
        return fn(self, *args, **kwargs)

    return wrapper


class TestStandaloneBoldPillarHeadingNormalization(unittest.TestCase):
    @_skip_if_no_app
    def test_arabic_standalone_bold_pillar_becomes_h3(self):
        src = (
            "نص تمهيدي قبل الركائز.\n\n"
            "**الركيزة 2: عمليات مركز العمليات الأمنية (SOC)**\n\n"
            "فقرة سرد للركيزة الثانية.\n\n"
            "**الركيزة 3: الاستجابة للحوادث واستمرارية الأعمال**\n\n"
            "فقرة سرد للركيزة الثالثة.\n"
        )
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn(
            "### الركيزة 2: عمليات مركز العمليات الأمنية (SOC)",
            out,
        )
        self.assertIn(
            "### الركيزة 3: الاستجابة للحوادث واستمرارية الأعمال",
            out,
        )
        # Bold-only forms must be removed (no longer inline highlighted blocks)
        self.assertNotIn(
            "**الركيزة 2: عمليات مركز العمليات الأمنية (SOC)**",
            out,
        )
        self.assertNotIn(
            "**الركيزة 3: الاستجابة للحوادث واستمرارية الأعمال**",
            out,
        )

    @_skip_if_no_app
    def test_english_standalone_bold_pillar_becomes_h3(self):
        src = (
            "Intro narrative.\n\n"
            "**Pillar 2: SOC Operations**\n\n"
            "Pillar narrative paragraph.\n"
        )
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn("### Pillar 2: SOC Operations", out)
        self.assertNotIn("**Pillar 2: SOC Operations**", out)

    @_skip_if_no_app
    def test_existing_merged_bold_pillar_plus_narrative_still_works(self):
        # Regression: the original PRE-PILLAR rule (bold heading merged with
        # following narrative on same line) must still split correctly.
        src = "**الركيزة 4: الامتثال والضمان** فقرة سرد متبوعة مباشرة.\n"
        out = _APP.ensure_markdown_formatting(src)
        self.assertIn("### الركيزة 4: الامتثال والضمان", out)
        self.assertIn("فقرة سرد متبوعة مباشرة", out)


if __name__ == '__main__':
    unittest.main()
