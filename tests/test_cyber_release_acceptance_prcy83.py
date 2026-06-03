"""PR-CY83 — DCC roadmap family canonicalization + sealed artifact gate closure."""

import functools
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_release_acceptance_prcy83_')
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
    """Fail fast with blockers — release acceptance must not skip on seal."""
    if art.get('sealed') and not (art.get('blocking_errors') or []):
        return
    self_msg = (
        f'{context} not sealed: blocking_errors={art.get("blocking_errors")!r}')
    raise AssertionError(self_msg)


# Sealable vision/KPI base (matches PR-CY80 unified contract fixtures).
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

_ROADMAP_ECC_ONLY = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
    '| المرحلة 3: تحسين | 19-24 شهر | CSIRT | CISO | فريق | NCA ECC |\n'
)

_ROADMAP_TWO_PHASES = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة CISO | CISO | هيكل | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | SOC | مدير SOC | مركز | NCA ECC |\n'
)

_ROADMAP_PHASE_HEADING_NO_TIMELINE = (
    '## 5. خارطة الطريق\n\n'
    '### المرحلة 1: تأسيس\n\n'
    'نص وصفي بدون جدول زمني.\n\n'
    '### المرحلة 2: تمكين وتشغيل\n\n'
    'نص آخر بدون جدول.\n'
)

_DLP_OUTPUT_ONLY = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | تصنيف وجرد البيانات الحساسة | '
    'مدير حماية البيانات | سجل | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | تطبيق ضوابط التشفير وإدارة المفاتيح | '
    'مدير حماية البيانات | تشفير | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | معالجة البيانات الحساسة | '
    'مدير حماية البيانات | منصة DLP وقواعد مراقبة تسرب | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | معالجة البيانات الحساسة وتطبيق ضوابط الحماية | '
    'مدير حماية البيانات | إجراءات | NCA DCC |\n'
)

_OWNER_ONLY_DCC = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | مدير حماية البيانات | CISO | سجل | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | بيانات | مدير حماية البيانات | DLP | NCA DCC |\n'
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
        'roadmap': _ROADMAP_ECC_ONLY,
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


def _dcc_canonicalize(sections, roadmap_key='roadmap'):
    """Run PR-CY83 DCC canonicalization in-process (no full artifact)."""
    md = _content(sections)
    return _APP._prcy83_dcc_roadmap_family_canonicalization(
        sections, md, {'domain': 'cyber'},
        ['nca_ecc', 'nca_dcc'], 'ar', 'cyber',
        output_type='prcy83_unit', repair_actions=[])


class Prcy83DccFamilyUnitTests(unittest.TestCase):
    """Lower-level DCC family detection/repair (no live Render / no AI)."""

    @_require_app
    def test_output_only_dlp_not_sufficient(self):
        rows = _APP._prcy83_roadmap_table_data_rows(_DLP_OUTPUT_ONLY)
        fams = _APP._detect_roadmap_dcc_families_from_canonical_rows(rows)
        self.assertNotIn('dlp', fams)

    @_require_app
    def test_output_only_dlp_repaired_by_ensure(self):
        """Output-only DLP must gain a standalone initiative row via ensure."""
        secs = _sections(roadmap=_DLP_OUTPUT_ONLY)
        self.assertFalse(
            _APP._prcy83_dlp_standalone_initiative_present(secs['roadmap']))
        secs2, inserted, _ = _APP._ensure_required_dcc_roadmap_families(
            secs, 'ar', ['nca_ecc', 'nca_dcc'])
        rm = secs2.get('roadmap', '')
        self.assertTrue(_APP._prcy83_dlp_standalone_initiative_present(rm))
        if not _APP._prcy83_initiative_matches_dcc_family(
                'منصة DLP وقواعد مراقبة تسرب', 'dlp'):
            self.assertIn('dlp', inserted)

    @_require_app
    def test_owner_only_not_dcc_family(self):
        rows = _APP._prcy83_roadmap_table_data_rows(_OWNER_ONLY_DCC)
        fams = _APP._detect_roadmap_dcc_families_from_canonical_rows(rows)
        for fam in _APP._PRCY83_REQUIRED_DCC_FAMILIES:
            self.assertNotIn(fam, fams)

    @_require_app
    def test_generic_data_not_family(self):
        for fam in _APP._PRCY83_REQUIRED_DCC_FAMILIES:
            self.assertFalse(
                _APP._prcy83_initiative_matches_dcc_family('بيانات', fam))
            self.assertFalse(
                _APP._prcy83_initiative_matches_dcc_family('data', fam))

    @_require_app
    def test_missing_dlp_initiative_inserts_canonical_row(self):
        secs = _sections(roadmap=_ROADMAP_ECC_ONLY)
        rows_before = _APP._prcy83_roadmap_table_data_rows(secs['roadmap'])
        self.assertIn(
            'dlp',
            _APP._validate_required_dcc_roadmap_families(
                rows_before, ['nca_ecc', 'nca_dcc']))
        secs2, inserted, _ = _APP._ensure_required_dcc_roadmap_families(
            secs, 'ar', ['nca_ecc', 'nca_dcc'])
        self.assertIn('dlp', inserted)
        rm = secs2.get('roadmap', '')
        self.assertTrue(_APP._prcy83_dlp_standalone_initiative_present(rm))
        self.assertIn('تفعيل DLP', rm)

    @_require_app
    def test_existing_dlp_not_duplicated(self):
        rm = (
            '## 5.\n\n| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1: تأسيس | 1-6 أشهر | تصنيف وجرد البيانات الحساسة | '
            'مدير حماية البيانات | سجل | NCA DCC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | تطبيق ضوابط التشفير وإدارة المفاتيح | '
            'مدير حماية البيانات | تشفير | NCA DCC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | تفعيل DLP ومراقبة تسرب البيانات | '
            'مدير حماية البيانات | منصة | NCA DCC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | معالجة البيانات الحساسة وتطبيق ضوابط الحماية | '
            'مدير حماية البيانات | إجراءات | NCA DCC |\n')
        secs2, _, diag, _, _ = _dcc_canonicalize(_sections(roadmap=rm))
        self.assertNotIn('dlp', diag.get('inserted_families') or [])
        self.assertEqual(
            (secs2.get('roadmap') or '').count('تفعيل DLP'), 1)

    @_require_app
    def test_all_four_dcc_families_after_canonicalization(self):
        secs2, _, diag, _, be = _dcc_canonicalize(
            _sections(roadmap=_ROADMAP_ECC_ONLY))
        self.assertIsNone(be)
        for fam in _APP._PRCY83_REQUIRED_DCC_FAMILIES:
            self.assertIn(fam, diag.get('detected_families_after') or [])

    @_require_app
    def test_stale_dcc_family_blockers_filtered_post_sealed(self):
        """PR-CY82 — stale DCC family tokens must not re-block after seal."""
        stale = [
            'final_quality_gate_failed:prcy74_missing_required_dcc_family:dlp',
            'final_quality_gate_failed:'
            'prcy71_final_artifact_missing_required_dcc_roadmap_rows:2',
            'final_quality_gate_failed:'
            'prcy73_missing_standalone_dlp_roadmap_row',
            'cyber_roadmap_balance_missing:sensitive_data_handling',
        ]
        filtered = _APP._prcy82_filter_stale_quality_issues(stale)
        self.assertEqual(filtered, [])
        for code in stale:
            self.assertTrue(_APP._prcy82_is_stale_artifact_content_blocker(code))


class Prcy83ReleaseAcceptanceTests(unittest.TestCase):

    def setUp(self):
        if _APP is not None:
            _APP._PRCY82_CONTRACT_BYPASS_EVENTS.clear()

    @_require_app
    def test_prcy83_flag_and_registry(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy83'))
        fp = _APP._prcy37_runtime_build_fingerprint_payload(
            route_name='generation', output_type='generation')
        self.assertTrue(fp.get('prcy82'))
        self.assertTrue(fp.get('prcy83'))
        _APP._prcy83_assert_blocker_registry_complete()
        self.assertIn(
            'prcy74_missing_required_dcc_family',
            _APP._FINAL_ARTIFACT_BLOCKER_REGISTRY)

    @_require_app
    def test_missing_dlp_initiative_inserted_full_artifact(self):
        art, log = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'missing_dlp')
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('[DCC-ROADMAP-FAMILY-CANONICALIZATION]', log)
        self.assertTrue(_APP._prcy83_dlp_standalone_initiative_present(rm))

    @_require_app
    def test_all_dcc_families_before_seal(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'all_families')
        rows = _APP._prcy83_roadmap_table_data_rows(
            (art.get('sections') or {}).get('roadmap', ''))
        fams = _APP._detect_roadmap_dcc_families_from_canonical_rows(rows)
        for fam in _APP._PRCY83_REQUIRED_DCC_FAMILIES:
            self.assertIn(fam, fams)

    @_require_app
    def test_prcy74_dlp_not_after_sealed(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'prcy74')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('prcy74_missing_required_dcc_family:dlp', joined)

    @_require_app
    def test_prcy71_rows_not_after_sealed(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'prcy71')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn(
            'prcy71_final_artifact_missing_required_dcc_roadmap_rows', joined)

    @_require_app
    def test_prcy73_dlp_not_after_sealed(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'prcy73')
        joined = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('prcy73_missing_standalone_dlp_roadmap_row', joined)

    @_require_app
    def test_preview_docx_pdf_sealed_hash_no_dcc_mutation(self):
        art, _ = _artifact(_sections(roadmap=_ROADMAP_ECC_ONLY))
        _require_sealed(art, 'export_parity')
        fh = art['final_hash']
        meta = {'domain': 'cyber', 'sealed': True, 'final_hash': fh}
        for ot in ('preview', 'docx', 'pdf'):
            c = _APP._prcy80_invoke_final_strategy_artifact(
                art['final_markdown'],
                metadata=meta,
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar', domain='cyber', output_type=ot, read_only=True)
            self.assertEqual(c.get('content_hash'), fh, msg=ot)
        self.assertEqual(_APP._PRCY82_CONTRACT_BYPASS_EVENTS, [])

    @_require_app
    def test_pdf_dense_table_fallbacks_zero_actionable_warnings(self):
        """Dense PDF table card fallbacks — local docmodel only (no Render)."""
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [['1', 'x' * 120, '≥ 95%', 'f' * 40, 'src', 'شهري']],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_require_app
    def test_noisy_release_fixture(self):
        """Combined: missing DLP, phase headings, KPI # = —, non-canonical ECC roadmap."""
        noisy_kpi = _KPI_SEALABLE.replace('| 1 |', '| — |', 1)
        art, log = _artifact(_sections(
            roadmap=_ROADMAP_PHASE_HEADING_NO_TIMELINE,
            kpis=noisy_kpi,
        ))
        _require_sealed(art, 'noisy_release')
        self.assertIn('[CYBER-FINAL-ARTIFACT-CONTRACT-V2]', log)
        self.assertIn('[DCC-ROADMAP-FAMILY-CANONICALIZATION]', log)
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertTrue(_APP._prcy83_dlp_standalone_initiative_present(rm))
        for tok in ('المرحلة 3', '19-24', '1-6', '7-18'):
            self.assertIn(tok, rm)
        kpi_body = (art.get('sections') or {}).get('kpis', '')
        data_rows = [
            ln for ln in kpi_body.split('\n')
            if ln.strip().startswith('|') and '---' not in ln
            and 'وصف' not in ln]
        self.assertTrue(data_rows)
        self.assertNotEqual(
            [c.strip() for c in data_rows[0].split('|') if c.strip()][0],
            '—')
        self.assertEqual(_APP._PRCY82_CONTRACT_BYPASS_EVENTS, [])

    @_require_app
    def test_two_phase_roadmap_gets_phase_three(self):
        art, log = _artifact(_sections(roadmap=_ROADMAP_TWO_PHASES))
        _require_sealed(art, 'two_phases')
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('19-24', rm)
        self.assertIn('[ROADMAP-FINAL-PHASE-TIMELINE-CANONICALIZATION]', log)

    @_require_app
    def test_owner_only_roadmap_repaired_in_artifact(self):
        art, _ = _artifact(_sections(roadmap=_OWNER_ONLY_DCC))
        _require_sealed(art, 'owner_only_roadmap')
        rows = _APP._prcy83_roadmap_table_data_rows(
            (art.get('sections') or {}).get('roadmap', ''))
        fams = _APP._detect_roadmap_dcc_families_from_canonical_rows(rows)
        for fam in _APP._PRCY83_REQUIRED_DCC_FAMILIES:
            self.assertIn(fam, fams)
        for r in rows:
            init = _APP._prcy73_roadmap_initiative_text(r)
            self.assertNotEqual(init.strip(), 'مدير حماية البيانات')
            self.assertNotIn(init.strip(), ('بيانات', 'data'))


if __name__ == '__main__':
    unittest.main()
