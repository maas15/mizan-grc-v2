"""PR-5B.8Q — Selected-framework coverage enforcement.

Covers the registry, the resolver, the missing-coverage helper, and the
``_final_strategy_audit`` integration that emits
``selected_framework_coverage_missing:<FW>:<family>`` defects.

These tests exercise pure helpers — no AI calls, no DB writes.

Run:
    python -m pytest tests/test_selected_framework_coverage.py -q
"""
import importlib.util
import os
import sys
import tempfile
import unittest

# ── Boot env required by ``app`` ─────────────────────────────────────────
_TMP_DB_DIR = tempfile.mkdtemp(prefix='test_fw_coverage_')
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


# ── Minimal section fixtures ──────────────────────────────────────────────
# These fixtures are intentionally short — only the substring vocabulary
# matters for coverage detection. Other audit thresholds (min rows etc.)
# are not asserted here; the test exercises ONLY the new
# selected-framework coverage path.
_BASE_ECC_SECTIONS_AR = {
    'vision': '## 1. الرؤية والأهداف الاستراتيجية\n\nالرؤية: تعزيز '
              'الحوكمة والامتثال.\n',
    'pillars': '## 2. الركائز الاستراتيجية\n\n### الركيزة 1: الحوكمة\n'
               'إطار حوكمة الأمن السيبراني وسياسات معتمدة، مع إدارة '
               'الهوية والوصول المميز (PAM).\n',
    'environment': '## 3. البيئة التنظيمية والتهديدات\n\n'
                   'يفرض الإطار التنظيمي NCA ECC على جميع الجهات الحكومية '
                   'متطلبات صارمة. مشهد التهديدات يشمل هجمات الفدية. '
                   'السياق التشغيلي يعتمد على البنية التحتية الرقمية.\n',
    'gaps': '## 4. تحليل الفجوات\n\n| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | غياب SIEM | لا يوجد مراقبة مركزية | عالية | مفتوحة |\n'
            '| 2 | ضعف الاستجابة للحوادث | لا يوجد CSIRT | عالية | مفتوحة |\n',
    'roadmap': '## 5. خارطة الطريق التنفيذية\n\n'
               '| # | النشاط | المسؤول | الإطار الزمني | المخرج |\n'
               '|---|---|---|---|---|\n'
               '| 1 | تأسيس مركز العمليات الأمنية SOC | CISO | 6 أشهر | '
               'SIEM | \n',
    'kpis': '## 6. مؤشرات الأداء الرئيسية\n\n'
            '| # | المؤشر | النوع | المستهدف | الصيغة | المصدر | المالك | '
            'التكرار | الإطار |\n'
            '|---|---|---|---|---|---|---|---|---|\n'
            '| 1 | تغطية المراقبة (SIEM) | KPI | 95% | × | SIEM | CISO | '
            'شهري | 12 |\n',
    'confidence': '## 7. تقييم الثقة والمخاطر\n\n**درجة الثقة:** 70%\n'
                   '\n### مبررات التقييم\nالاستراتيجية مبنية على إطار '
                   'NCA ECC مع حوكمة معتمدة.\n\n'
                   '### المخاطر الرئيسية\n'
                   '| # | الخطر | الاحتمالية | التأثير | المعالجة | المالك |\n'
                   '|---|---|---|---|---|---|\n'
                   '| 1 | حادث أمني | عالية | عالٍ | تعزيز الاستجابة للحوادث '
                   '| CISO |\n',
}


def _add_tcc_coverage(sections):
    """Inject TCC vocabulary into a copy of the ECC fixture."""
    s = dict(sections)
    s['pillars'] = s['pillars'] + (
        '\n### الركيزة 2: العمل عن بُعد\n'
        'تأمين الوصول عن بُعد عبر VPN و ZTNA مع المصادقة متعددة العوامل '
        '(MFA) وإدارة الأجهزة المحمولة (MDM) ومنع تسرب البيانات (DLP) '
        'والتشفير.\n'
    )
    s['environment'] = s['environment'] + (
        '\n**سياق العمل عن بُعد:** تتزايد المخاطر على جلسات الوصول عن بُعد '
        'وتشمل سرقة بيانات الاعتماد.\n'
    )
    s['gaps'] = s['gaps'] + (
        '| 3 | غياب MFA للوصول عن بعد | لا توجد ضوابط مصادقة | عالية | '
        'مفتوحة |\n'
    )
    s['roadmap'] = s['roadmap'] + (
        '| 2 | نشر VPN/ZTNA و MFA لجميع جلسات العمل عن بُعد | CISO | 9 '
        'أشهر | بنية وصول آمن |\n'
        '| 3 | نشر EDR و MDM على الأجهزة الطرفية والأجهزة الشخصية BYOD | '
        'CISO | 12 شهراً | حماية الأجهزة الطرفية |\n'
    )
    s['kpis'] = s['kpis'] + (
        '| 2 | تغطية MFA للوصول عن بُعد | KPI | 100% | × | IAM | CISO | '
        'شهري | 6 |\n'
    )
    s['confidence'] = s['confidence'] + (
        '| 2 | تسرب بيانات عبر العمل عن بُعد | متوسطة | عالٍ | DLP + '
        'تشفير | CISO |\n'
    )
    return s


# ── Tests ─────────────────────────────────────────────────────────────────
class FrameworkRegistryTest(unittest.TestCase):

    @_skip_if_no_app
    def test_registry_contains_required_frameworks(self):
        reg = _APP._FRAMEWORK_COVERAGE_REQUIREMENTS
        for fw in ['ECC', 'TCC', 'CCC', 'DCC', 'CSCC', 'ISO27001',
                   'NIST_CSF', 'SAMA', 'NDMO', 'DGA', 'ISO22301',
                   'NIST_AI_RMF']:
            self.assertIn(fw, reg, f'Framework {fw} missing from registry')
            spec = reg[fw]
            self.assertIn('aliases', spec)
            self.assertIn('capabilities', spec)
            self.assertTrue(spec['capabilities'],
                            f'{fw} has no capability families')
            self.assertIn('applicable_domains', spec)
            self.assertIn('required_sections', spec)
            self.assertIn('repair_targets', spec)
            for fam in spec['capabilities']:
                self.assertEqual(len(fam), 3,
                                 f'{fw} family malformed: {fam!r}')


class ResolveSelectedFrameworksTest(unittest.TestCase):

    @_skip_if_no_app
    def test_resolve_empty_or_none(self):
        f = _APP._resolve_selected_frameworks
        self.assertEqual(f(None), [])
        self.assertEqual(f([]), [])
        self.assertEqual(f(''), [])

    @_skip_if_no_app
    def test_resolve_string_alias_match(self):
        f = _APP._resolve_selected_frameworks
        self.assertIn('ECC', f('NCA ECC'))
        self.assertIn('TCC', f('nca tcc'))
        self.assertIn('NDMO', f('NDMO'))

    @_skip_if_no_app
    def test_resolve_list_multi(self):
        f = _APP._resolve_selected_frameworks
        out = f(['NCA ECC', 'NCA TCC'])
        self.assertIn('ECC', out)
        self.assertIn('TCC', out)

    @_skip_if_no_app
    def test_resolve_domain_filter_excludes_non_applicable(self):
        f = _APP._resolve_selected_frameworks
        # NDMO is Data Management only — must NOT resolve under
        # Cyber Security domain even when present in input.
        out = f(['NDMO'], domain='Cyber Security')
        self.assertNotIn('NDMO', out)

    @_skip_if_no_app
    def test_resolve_domain_filter_keeps_applicable(self):
        f = _APP._resolve_selected_frameworks
        out = f(['NCA ECC', 'NCA TCC'], domain='Cyber Security')
        self.assertEqual(set(out), {'ECC', 'TCC'})


class ComputeMissingCoverageTest(unittest.TestCase):

    @_skip_if_no_app
    def test_no_frameworks_means_no_missing(self):
        f = _APP._compute_missing_selected_framework_coverage
        self.assertEqual(
            f(_BASE_ECC_SECTIONS_AR, [], domain='Cyber Security',
              lang='ar'),
            [],
        )

    @_skip_if_no_app
    def test_ecc_only_strategy_satisfies_ecc(self):
        f = _APP._compute_missing_selected_framework_coverage
        missing = f(_BASE_ECC_SECTIONS_AR, ['NCA ECC'],
                    domain='Cyber Security', lang='ar')
        # Each missing entry's framework must NOT be ECC (the fixture
        # explicitly satisfies ECC's families).
        offending = [m for m in missing if m[0] == 'ECC']
        self.assertEqual(
            offending, [],
            f'ECC fixture should satisfy ECC; got {offending!r}',
        )

    @_skip_if_no_app
    def test_ecc_plus_tcc_misses_tcc_when_no_remote_work_terms(self):
        f = _APP._compute_missing_selected_framework_coverage
        missing = f(_BASE_ECC_SECTIONS_AR, ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        tcc_missing = [m for m in missing if m[0] == 'TCC']
        self.assertGreater(
            len(tcc_missing), 0,
            'Selecting TCC against an ECC-only fixture must report '
            'TCC families as missing.'
        )
        # And every reported TCC entry must point at a registry
        # repair_target section.
        repair_targets = set(
            _APP._FRAMEWORK_COVERAGE_REQUIREMENTS['TCC']['repair_targets'])
        for fw_key, fam_id, sk in tcc_missing:
            self.assertIn(sk, repair_targets,
                          f'TCC missing reported on non-target section {sk!r}')

    @_skip_if_no_app
    def test_tcc_satisfied_when_remote_work_terms_present(self):
        f = _APP._compute_missing_selected_framework_coverage
        sections = _add_tcc_coverage(_BASE_ECC_SECTIONS_AR)
        missing = f(sections, ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        tcc_missing = [m for m in missing if m[0] == 'TCC']
        self.assertEqual(
            tcc_missing, [],
            f'TCC fixture should satisfy TCC; got {tcc_missing!r}'
        )

    @_skip_if_no_app
    def test_helper_accepts_string_text(self):
        f = _APP._compute_missing_selected_framework_coverage
        # When passed a flat string the helper must still detect missing
        # families (with section_key='*').
        flat = ' '.join(_BASE_ECC_SECTIONS_AR.values())
        missing = f(flat, ['NCA ECC', 'NCA TCC'],
                    domain='Cyber Security', lang='ar')
        tcc_missing = [m for m in missing if m[0] == 'TCC']
        self.assertGreater(len(tcc_missing), 0)
        for fw_key, fam_id, sk in tcc_missing:
            self.assertEqual(sk, '*')

    @_skip_if_no_app
    def test_non_cyber_domain_does_not_force_cyber_frameworks(self):
        f = _APP._compute_missing_selected_framework_coverage
        # User accidentally includes "NCA ECC" while generating a Data
        # Management strategy. The domain filter must drop ECC so the
        # data strategy is not penalised for missing cyber vocabulary.
        sections = {'pillars': 'حوكمة البيانات وجودة البيانات وكتالوج '
                               'البيانات.', 'environment': 'NDMO data '
                                                            'governance.'}
        missing = f(sections, ['NCA ECC'], domain='Data Management',
                    lang='ar')
        ecc_missing = [m for m in missing if m[0] == 'ECC']
        self.assertEqual(
            ecc_missing, [],
            'ECC must not be enforced on Data Management strategies.',
        )


class FinalAuditIntegrationTest(unittest.TestCase):

    @_skip_if_no_app
    def test_audit_emits_selected_framework_coverage_missing_for_tcc(self):
        defects = _APP._final_strategy_audit(
            _BASE_ECC_SECTIONS_AR, lang='ar', doc_subtype='technical',
            selected_frameworks=['NCA ECC', 'NCA TCC'],
            domain='Cyber Security',
        )
        tags = [d[1] for d in defects]
        self.assertTrue(
            any(t.startswith('selected_framework_coverage_missing:TCC:')
                for t in tags),
            f'Expected selected_framework_coverage_missing:TCC:* defect; '
            f'got {tags!r}',
        )

    @_skip_if_no_app
    def test_audit_does_not_emit_tcc_defect_when_tcc_not_selected(self):
        # ECC-only — must not surface any TCC selected_framework_coverage
        # defects.
        defects = _APP._final_strategy_audit(
            _BASE_ECC_SECTIONS_AR, lang='ar', doc_subtype='technical',
            selected_frameworks=['NCA ECC'],
            domain='Cyber Security',
        )
        tcc_tags = [d[1] for d in defects
                    if 'selected_framework_coverage_missing:TCC' in d[1]]
        self.assertEqual(tcc_tags, [],
                         f'TCC must not be enforced when not selected: '
                         f'{tcc_tags!r}')

    @_skip_if_no_app
    def test_audit_no_fw_arg_is_backwards_compatible(self):
        # Calling _final_strategy_audit without the new kwargs must not
        # emit any selected_framework_coverage defects.
        defects = _APP._final_strategy_audit(
            _BASE_ECC_SECTIONS_AR, lang='ar', doc_subtype='technical',
        )
        for sec, tag, cnt, fl in defects:
            self.assertFalse(
                tag.startswith('selected_framework_coverage_missing:'),
                f'Backwards-compat path leaked FW defect: {tag!r}'
            )

    @_skip_if_no_app
    def test_audit_satisfied_emits_no_fw_defect_for_tcc(self):
        sections = _add_tcc_coverage(_BASE_ECC_SECTIONS_AR)
        defects = _APP._final_strategy_audit(
            sections, lang='ar', doc_subtype='technical',
            selected_frameworks=['NCA ECC', 'NCA TCC'],
            domain='Cyber Security',
        )
        tcc_tags = [d[1] for d in defects
                    if 'selected_framework_coverage_missing:TCC' in d[1]]
        self.assertEqual(tcc_tags, [],
                         f'Satisfied TCC fixture must not raise defects; '
                         f'got {tcc_tags!r}')


if __name__ == '__main__':
    unittest.main()
