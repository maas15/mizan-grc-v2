"""PR-5B.9E — SAMA framework compliance objective.

Pins:
  * ``_FRAMEWORK_COVERAGE_REQUIREMENTS['SAMA']`` declares the AR/EN
    aliases listed in the runtime requirement so
    ``_compute_missing_compliance_objective`` recognises a SAMA
    compliance row whether the AI used "SAMA Cybersecurity Framework",
    "ضوابط ساما", "إطار ساما للأمن السيبراني", or
    "compliance with SAMA requirements".
  * A vision lacking any SAMA-aligned objective row produces
    ``selected_framework_compliance_objective_missing:SAMA`` in
    ``_final_strategy_audit``.
  * A vision that includes both a SAMA compliance row AND a
    specialized-function row coexists without either erasing the
    other (org_structure_is_none=True).

Run:
    python -m pytest tests/test_framework_compliance_sama_pr5b9e.py -q
"""

import importlib.util
import os
import sys
import tempfile
import unittest


_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_sama_pr5b9e_')
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


def _vision_no_sama():
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'الرؤية: تعزيز الأمن السيبراني للمنظمة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        '| 1 | تطوير قدرات الأمن | 100% | تعزيز القدرات | 12 شهراً |\n'
        '| 2 | بناء فريق متخصص | 100% | الاستجابة السريعة | 12 شهراً |\n'
        '| 3 | اعتماد ضوابط SOC | 100% | المراقبة الأمنية | 12 شهراً |\n'
        '| 4 | تطبيق MFA | 100% | الحماية | 12 شهراً |\n'
        '| 5 | تدريب الموظفين | 100% | الوعي | 12 شهراً |\n'
        '| 6 | تحسين الاستجابة | 100% | إدارة الحوادث | 12 شهراً |\n'
    )


def _vision_with_sama_alias(alias_text):
    return (
        '## 1. الرؤية والأهداف الاستراتيجية\n\n'
        'الرؤية: تعزيز الأمن السيبراني للمنظمة.\n\n'
        '### الأهداف الاستراتيجية:\n\n'
        '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار الزمني |\n'
        '|---|------------------|-------|--------|---------------|\n'
        f'| 1 | الالتزام والامتثال بـ {alias_text} '
        '| 100% | تحقيق المتطلبات التنظيمية | 12 شهراً |\n'
        '| 2 | بناء فريق متخصص | 100% | الاستجابة السريعة | 12 شهراً |\n'
        '| 3 | اعتماد ضوابط SOC | 100% | المراقبة الأمنية | 12 شهراً |\n'
        '| 4 | تطبيق MFA | 100% | الحماية | 12 شهراً |\n'
        '| 5 | تدريب الموظفين | 100% | الوعي | 12 شهراً |\n'
        '| 6 | تحسين الاستجابة | 100% | إدارة الحوادث | 12 شهراً |\n'
    )


class SAMAAliasRegistryTests(unittest.TestCase):

    @_skip_if_no_app
    def test_sama_registry_present(self):
        spec = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS.get('SAMA')
        self.assertIsNotNone(spec, 'SAMA registry entry missing')
        aliases = [a.lower() for a in spec.get('aliases', [])]
        # The widened alias list must include each AR + EN token
        # listed in the runtime requirement.
        for tok in (
                'sama',
                'sama cybersecurity framework',
                'compliance with sama requirements',
                'ساما',
                'ضوابط ساما',
                'إطار ساما للأمن السيبراني',
                'الالتزام بمتطلبات ساما',
        ):
            with self.subTest(token=tok):
                # Compare lowercased for both AR and EN: AR tokens are
                # not lowercased meaningfully but inclusion check
                # still matches.
                self.assertIn(tok, aliases, f'SAMA alias missing: {tok!r}')


class SAMAComplianceObjectiveDetectionTests(unittest.TestCase):

    @_skip_if_no_app
    def test_missing_sama_objective_emits_defect(self):
        sections = {'vision': _vision_no_sama()}
        missing = _APP._compute_missing_compliance_objective(
            sections, ['SAMA'], domain='Cyber Security', lang='ar',
        )
        self.assertIn('SAMA', missing)

    @_skip_if_no_app
    def test_each_alias_satisfies_compliance_objective(self):
        for alias in (
                'SAMA Cybersecurity Framework',
                'ضوابط ساما',
                'إطار ساما للأمن السيبراني',
                'متطلبات ساما',
        ):
            with self.subTest(alias=alias):
                sections = {
                    'vision': _vision_with_sama_alias(alias),
                }
                missing = _APP._compute_missing_compliance_objective(
                    sections, ['SAMA'],
                    domain='Cyber Security', lang='ar',
                )
                self.assertNotIn(
                    'SAMA', missing,
                    f'SAMA compliance not detected for alias {alias!r}',
                )

    @_skip_if_no_app
    def test_audit_emits_sama_missing_in_defect_list(self):
        sections = {
            'vision': _vision_no_sama(),
            'pillars': '## 2. الركائز\n\n### الركيزة 1\n',
            'environment': '## 3. البيئة\n\nنص.\n',
            'gaps': '## 4. الفجوات\n',
            'roadmap': '## 5. الخارطة\n',
            'kpis': '## 6. مؤشرات\n',
            'confidence': '## 7. الثقة\n',
        }
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype=None,
            selected_frameworks=['SAMA'], domain='Cyber Security',
            org_structure_is_none=False,
        )
        tags = [d[1] for d in defects]
        self.assertTrue(
            any(
                t.startswith('selected_framework_compliance_objective_missing:')
                and 'SAMA' in t for t in tags
            ),
            f'SAMA compliance defect not emitted; tags={tags}',
        )

    @_skip_if_no_app
    def test_sama_and_specialized_function_coexist(self):
        # Vision has SAMA compliance objective (row 1) AND a
        # cybersecurity department establishment objective (row 2);
        # both must be detected as satisfied simultaneously.
        vision = (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            'الرؤية: تعزيز الأمن السيبراني للمنظمة.\n\n'
            '### الأهداف الاستراتيجية:\n\n'
            '| # | الهدف الاستراتيجي | المؤشر | المبرر | الإطار |\n'
            '|---|------------------|-------|--------|--------|\n'
            '| 1 | الالتزام بضوابط ساما '
            '| 100% | تحقيق متطلبات SAMA Cybersecurity Framework '
            '| 12 شهراً |\n'
            '| 2 | إنشاء إدارة الأمن السيبراني وتعيين CISO '
            '| 100% | تأسيس الإدارة المتخصصة | 12 شهراً |\n'
            '| 3 | بناء SOC | 100% | المراقبة | 12 شهراً |\n'
            '| 4 | تطبيق MFA | 100% | الحماية | 12 شهراً |\n'
            '| 5 | تدريب الموظفين | 100% | الوعي | 12 شهراً |\n'
            '| 6 | إدارة الحوادث | 100% | الاستجابة | 12 شهراً |\n'
        )
        sections = {'vision': vision}
        # SAMA compliance is satisfied.
        missing_fw = _APP._compute_missing_compliance_objective(
            sections, ['SAMA'], domain='Cyber Security', lang='ar',
        )
        self.assertNotIn('SAMA', missing_fw)
        # Specialized function objective is satisfied.
        missing_sf = (
            _APP._compute_missing_specialized_function_objective(
                sections, 'Cyber Security', lang='ar',
                org_structure_is_none=True,
            )
        )
        self.assertFalse(missing_sf)
        # Row count preserved (>=6).
        self.assertGreaterEqual(
            _APP.count_valid_objective_rows(vision), 6,
        )


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
