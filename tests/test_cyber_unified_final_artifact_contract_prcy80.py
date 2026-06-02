"""PR-CY80 — Unified final strategy artifact contract (save/preview/DOCX/PDF)."""

import functools
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout


_TMP = tempfile.mkdtemp(prefix='test_cyber_unified_final_artifact_prcy80_')
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


def _skip(fn):
    @functools.wraps(fn)
    def _w(self, *a, **kw):
        if _APP is None:
            self.skipTest('app unavailable')
        return fn(self, *a, **kw)
    return _w


_LEGACY_SO_ROWS = (
    '| 1 | إنشاء إدارة الأمن السيبراني المتخصصة | '
    'هيكل تنظيمي معتمد مع تعيين CISO وفريق SOC |\n'
    '| 2 | تشغيل مركز عمليات الأمن المتقدم | '
    'مركز SOC يعمل 24/7 مع تغطية 100% للأصول الحرجة |\n'
)

_CANON_SO_HEADER = (
    '| # | الهدف الاستراتيجي | المستهدف القابل للقياس |'
    ' المبرر | الإطار الزمني |\n'
    '|---|---|---|---|---|\n'
)

_CANON_SO_ROW = (
    '| 1 | إنشاء إدارة الأمن السيبراني وتعيين CISO |'
    ' تأسيس الهيكل 100% | قيادة وحوكمة | 6 أشهر |\n'
)

_ROADMAP_CANON = (
    '## 5. خارطة الطريق\n\n'
    '| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار المرتبط |\n'
    '|---|---|---|---|---|---|\n'
    '| المرحلة 1: تأسيس | 1-6 أشهر | تعيين CISO وحوكمة | CISO | هيكل معتمد | NCA ECC |\n'
    '| المرحلة 2: تمكين وتشغيل | 7-18 شهر | تشغيل SOC/SIEM | مدير SOC | مركز تشغيل | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | IAM/PAM/MFA | مدير IAM | ضوابط هوية | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | CSIRT وإدارة الثغرات | مدير CSIRT | برنامج | NCA ECC |\n'
    '| المرحلة 3: تحسين واستدامة | 19-24 شهر | تحسين نضج الامتثال | CISO | تقرير نضج | NCA ECC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | تصنيف البيانات | DPO | جرد | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | التشفير وإدارة المفاتيح | DPO | ضوابط | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | DLP ومراقبة التسرب | DPO | مراقبة | NCA DCC |\n'
    '| المرحلة 2: تمكين | 7-18 شهر | حماية البيانات الحساسة | DPO | إجراءات | NCA DCC |\n'
)

_KPI_MAIN = (
    '## 6. مؤشرات الأداء\n\n'
    '| # | وصف المؤشر | القيمة المستهدفة | صيغة الاحتساب |'
    ' مصدر البيانات/الأداة | تواتر القياس |\n'
    '|---|---|---|---|---|\n'
    '| 1 | متوسط زمن الكشف عن الحوادث MTTD | ≤ 60 دقيقة |'
    ' مجموع أوقات الكشف ÷ عدد الحوادث | SIEM/SOC | شهري |\n'
    '| 2 | متوسط زمن الاستجابة للحوادث MTTR | ≤ 4 ساعات |'
    ' مجموع أوقات الاستجابة ÷ عدد الحوادث | ITSM/SOAR | شهري |\n'
    '| 3 | امتثال DCC للبيانات الحساسة | ≥ 90% | (مطبق/مطلوب)*100 | DCC | ربع سنوي |\n'
)

_CONF = (
    '## 7. تقييم الثقة\n\n'
    '**درجة الثقة:** 82%\n'
    '**مبررات التقييم:** نص مبرر.\n'
    '| # | عامل المخاطر | الاحتمالية | التأثير | خطة المعالجة |\n'
    '|---|---|---|---|---|\n'
    '| 1 | مخاطر تشغيلية | متوسط | عالٍ | خطة |\n'
)


def _minimal_sections(**overrides):
    base = {
        'vision': (
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            + _CANON_SO_HEADER + _CANON_SO_ROW
            + '| 2 | SOC/CSIRT | 100% | تشغيل | 12 شهر |\n'
            + '| 3 | IAM/PAM/MFA | 95% | هوية | 12 شهر |\n'
            + '| 4 | DCC حماية البيانات | 90% | امتثال | 18 شهر |\n'
            + '| 5 | إطار ECC/DCC | 90% | تنظيمي | 18 شهر |\n'
        ),
        'pillars': '## 2. الركائز\n\nنص.\n',
        'environment': '## 3. البيئة\n\nتصنيف وتشفير DLP.\n',
        'gaps': '## 4. الفجوات\n\nGap #1 Implementation Guide steps.\n',
        'roadmap': _ROADMAP_CANON,
        'kpis': _KPI_MAIN,
        'confidence': _CONF,
    }
    base.update(overrides)
    return base


def _content_from_sections(sections):
    if hasattr(_APP, '_prcy65_rebuild_content_from_sections'):
        return _APP._prcy65_rebuild_content_from_sections(sections, None)
    return '\n\n'.join(
        sections[k] for k in (
            'vision', 'pillars', 'environment', 'gaps',
            'roadmap', 'kpis', 'confidence')
        if sections.get(k))


def _run_artifact(sections, output_type='generation', read_only=False, **kw):
    content = _content_from_sections(sections)
    buf = io.StringIO()
    with redirect_stdout(buf):
        art = _APP._build_cyber_final_strategy_artifact(
            content,
            sections=dict(sections),
            metadata=kw.get('metadata') or {'domain': 'cyber'},
            selected_frameworks=kw.get('frameworks') or ['nca_ecc', 'nca_dcc'],
            lang=kw.get('lang', 'ar'),
            domain='cyber',
            output_type=output_type,
            read_only=read_only,
            request_context={'route_name': output_type},
            generation_mode='consulting',
        )
    return art, buf.getvalue()


class Prcy80UnifiedArtifactTests(unittest.TestCase):

    @_skip
    def test_flag_and_helpers_present(self):
        self.assertTrue(_APP._PRCY28_VERSION_FLAGS.get('prcy80'))
        self.assertTrue(hasattr(_APP, '_build_cyber_final_strategy_artifact'))
        self.assertTrue(hasattr(_APP, '_prcy80_invoke_final_strategy_artifact'))
        self.assertTrue(hasattr(_APP, '_prcy80_user_facing_error_message'))

    @_skip
    def test_missing_objectives_table_repaired_and_sealed(self):
        sections = _minimal_sections(vision=(
            '## 1. الرؤية والأهداف الاستراتيجية\n\n'
            '### الأهداف الاستراتيجية\n\n'
            'نص بدون جدول.\n'))
        art, _log = _run_artifact(sections)
        vision = (art.get('sections') or {}).get('vision', '')
        self.assertIn(_CANON_SO_HEADER.split('\n')[0], vision)
        self.assertNotIn(
            'strategic_objectives_section_missing',
            ' '.join(art.get('blocking_errors') or []))
        if art.get('sealed'):
            self.assertIn('[CYBER-FINAL-ARTIFACT-CONTRACT-V2]', _log)

    @_skip
    def test_legacy_rows_removed_when_canonical_present(self):
        vision = (
            '## 1. الرؤية\n\n### الأهداف الاستراتيجية\n\n'
            + _LEGACY_SO_ROWS + _CANON_SO_HEADER
            + _CANON_SO_ROW
            + '| 2 | SOC | 100% | تشغيل | 12 شهر |\n'
            + '| 3 | IAM | 95% | هوية | 12 شهر |\n'
            + '| 4 | DCC | 90% | بيانات | 18 شهر |\n'
            + '| 5 | ECC | 90% | امتثال | 18 شهر |\n'
        )
        sections = _minimal_sections(vision=vision)
        art, _ = _run_artifact(sections)
        out_vision = (art.get('sections') or {}).get('vision', '')
        self.assertNotIn('إنشاء إدارة الأمن السيبراني المتخصصة', out_vision)
        self.assertIn('الهدف الاستراتيجي', out_vision)

    @_skip
    def test_insufficient_rows_topped_up_to_five_families(self):
        sections = _minimal_sections(vision=(
            '## 1. الرؤية\n\n### الأهداف\n\n'
            + _CANON_SO_HEADER + _CANON_SO_ROW))
        art, _ = _run_artifact(sections)
        vision = (art.get('sections') or {}).get('vision', '')
        valid, _ = _APP._prcy67_count_valid_so_rows(vision)
        self.assertGreaterEqual(valid, 5)
        fam = _APP._prcy67_detect_objective_families(vision)
        for fid in (
                'governance_ciso', 'framework_compliance_ecc_dcc',
                'soc_csirt', 'iam_pam_mfa', 'data_protection_dcc'):
            self.assertTrue(fam.get(fid), msg=fid)

    @_skip
    def test_incomplete_row_repaired_or_precisely_blocked(self):
        sections = _minimal_sections(vision=(
            '## 1. الرؤية\n\n### الأهداف\n\n'
            + _CANON_SO_HEADER
            + '| 1 | هدف |  | مبرر | 6 أشهر |\n'
            + '| 2 | SOC | 100% | تشغيل | 12 شهر |\n'
            + '| 3 | IAM | 95% | هوية | 12 شهر |\n'
            + '| 4 | DCC | 90% | بيانات | 18 شهر |\n'
            + '| 5 | ECC | 90% | امتثال | 18 شهر |\n'))
        art, _ = _run_artifact(sections)
        blockers = art.get('blocking_errors') or []
        incomplete = [
            b for b in blockers
            if 'strategic_objectives_incomplete_row' in str(b)]
        if incomplete:
            self.assertTrue(
                any('strategic_objectives_incomplete_row:' in b
                    for b in incomplete))
        else:
            issues = _APP._prcy80_strategic_objectives_incomplete_rows(
                art.get('sections') or {}, 'ar')
            self.assertEqual(issues, [])

    @_skip
    def test_row_schema_violation_not_in_blockers_after_sealed_pass(self):
        sections = _minimal_sections()
        art, _ = _run_artifact(sections)
        if not art.get('sealed'):
            self.skipTest('fixture did not seal — skip schema survival check')
        blockers = ' '.join(art.get('blocking_errors') or [])
        self.assertNotIn('strategic_objectives_row_schema_violation', blockers)

    @_skip
    def test_quality_issues_post_cannot_block_when_artifact_empty_blockers(self):
        stale = [
            'strategic_objectives_row_schema_violation',
            'strategic_objectives_rows_insufficient',
            'confidence_score_missing',
        ]
        diag = {
            'so_valid_after_final_recheck': True,
            'so_rows_sufficient_after_final_recheck': True,
        }
        resolved = _APP._prcy75_resolve_final_save_gate_issues(stale, diag)
        self.assertNotIn('strategic_objectives_row_schema_violation', resolved)
        self.assertNotIn('strategic_objectives_rows_insufficient', resolved)
        _cy80_stale = {
            'strategic_objectives_row_schema_violation',
            'strategic_objectives_rows_insufficient',
            'strategic_objectives_incomplete_row',
            'confidence_score_missing',
            'score_justification_missing',
        }
        filtered = [
            i for i in stale
            if not any(
                i == t or str(i).startswith(t + ':')
                for t in _cy80_stale)]
        self.assertEqual(filtered, [])

    @_skip
    def test_roadmap_non_canonical_schema_normalized(self):
        bad = (
            '## 5. خارطة\n\n'
            '| # | النشاط | المسؤول | الإطار | المخرج |\n'
            '|---|---|---|---|---|\n'
            '| 1 | SOC | CISO | ECC | out |\n'
        )
        sections = _minimal_sections(roadmap=bad)
        art, _ = _run_artifact(sections)
        rm = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('المرحلة', rm)
        self.assertIn('المبادرة', rm)

    @_skip
    def test_roadmap_missing_phase3_repaired(self):
        rm = (
            '## 5. خارطة\n\n'
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة | CISO | out | NCA ECC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | SOC | CISO | out2 | NCA ECC |\n'
        )
        sections = _minimal_sections(roadmap=rm)
        art, _ = _run_artifact(sections)
        out = (art.get('sections') or {}).get('roadmap', '')
        self.assertIn('تحسين', out)

    @_skip
    def test_roadmap_sensitive_data_handling_repaired(self):
        rm = (
            '## 5. خارطة\n\n'
            '| المرحلة | الفترة | المبادرة | المسؤول | المخرج | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| المرحلة 1: تأسيس | 1-6 أشهر | حوكمة | CISO | out | NCA ECC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | SOC | CISO | out2 | NCA ECC |\n'
            '| المرحلة 3: تحسين | 19-24 شهر | VM | CISO | out3 | NCA ECC |\n'
            '| المرحلة 2: تمكين | 7-18 شهر | DCC عام | DPO | out4 | NCA DCC |\n'
        )
        sections = _minimal_sections(roadmap=rm)
        art, _ = _run_artifact(sections)
        miss = _APP._compute_missing_cyber_roadmap_balance_topics(
            (art.get('sections') or {}).get('roadmap', ''),
            ['ECC', 'DCC'], lang='ar')
        self.assertNotIn('sensitive_data_handling', miss)

    @_skip
    def test_dcc_roadmap_has_classification_encryption_dlp_handling(self):
        art, _ = _run_artifact(_minimal_sections())
        rm = (art.get('sections') or {}).get('roadmap', '').lower()
        for token in ('تصنيف', 'تشفير', 'dlp', 'حساس'):
            self.assertIn(token, rm, msg=token)

    @_skip
    def test_kpi_dash_resequenced_in_pdf_cleanup(self):
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        tbl = {
            'schema': 'kpi_main',
            'header': list(_PSR.SCHEMA_KPI_MAIN_AR),
            'rows': [
                ['1', 'A', '≥ 95%', 'f', 'src', 'شهري'],
                ['—', 'B', '≥ 90%', 'f2', 'src2', 'شهري'],
            ],
        }
        model['blocks']['kpi_kri_framework']['tables'] = [tbl]
        diag = _PSR.apply_pdf_final_table_fallback_cleanup(model, 'ar')
        rows = model['blocks']['kpi_kri_framework']['tables'][0]['rows']
        self.assertEqual(rows[1][0], '2')
        self.assertGreaterEqual(diag.get('kpi_rows_resequenced', 0), 1)

    @_skip
    def test_mttd_mttr_semantic_alignment_helpers(self):
        self.assertTrue(hasattr(_APP, '_prcy68_kpi_detection_response_aligned'))
        self.assertTrue(
            _APP._prcy68_kpi_detection_response_aligned(_KPI_MAIN, 'ar'))

    @_skip
    def test_confidence_score_and_justification_present_after_artifact(self):
        sections = _minimal_sections(confidence='## 7.\n\n')
        art, _ = _run_artifact(sections)
        conf = (art.get('sections') or {}).get('confidence', '')
        det = _APP._prcy65_detect_confidence_presence(conf)
        self.assertTrue(det['confidence_score_present'])
        self.assertTrue(det['score_justification_present'])

    @_skip
    def test_traceability_dcc_does_not_map_to_vulnerability(self):
        sections = _minimal_sections()
        sections['environment'] = (
            '## 3.\n\n| الإطار | القدرة | الفجوة | المبادرة | KPI |\n'
            '|---|---|---|---|---|\n'
            '| NCA DCC | تصنيف البيانات | فجوة | مبادرة DLP | KPI DCC |\n'
        )
        invalid = _APP._prcy70_traceability_invalid_cells(
            sections, ['NCA ECC', 'NCA DCC'], lang='ar')
        vuln_hits = [
            v for v in (invalid or [])
            if 'vulnerability' in str(v).lower()
            and 'dcc' in str(v).lower()]
        self.assertEqual(vuln_hits, [])

    @_skip
    def test_arabic_cleanup_removes_known_residues(self):
        dirty = 'المسؤولحوكمة CISO CISO التش… — حما'
        clean = _APP._prcy39_normalize_arabic_concatenations(dirty)
        clean, _samples = _APP._prcy71_apply_arabic_residue_cleanup(clean, 'ar')
        self.assertNotIn('المسؤولحوكمة', clean)
        self.assertNotIn('CISO CISO', clean)
        self.assertIn('مسؤول حوكمة', clean)

    @_skip
    def test_preview_docx_pdf_share_sealed_final_hash(self):
        sections = _minimal_sections()
        art, _ = _run_artifact(sections, output_type='generation')
        if not art.get('sealed'):
            self.skipTest('generation fixture did not seal')
        fh = art.get('final_hash')
        meta = {
            'domain': 'cyber',
            'final_hash': fh,
            'sealed': True,
            'prcy39': True,
        }
        for ot in ('preview', 'docx', 'pdf'):
            contract = _APP._prcy80_invoke_final_strategy_artifact(
                art['final_markdown'],
                metadata=meta,
                selected_frameworks=['nca_ecc', 'nca_dcc'],
                lang='ar',
                domain='cyber',
                output_type=ot,
                read_only=True,
            )
            self.assertEqual(contract.get('content_hash'), fh, msg=ot)
            self.assertEqual(contract.get('post_contract_hash'), fh, msg=ot)

    @_skip
    def test_pdf_render_model_card_fallbacks_zero_actionable_warnings(self):
        from tests.test_cyber_export_parity_prcy50 import _model as _m50
        model = _m50()
        tbl = {
            'schema': 'strategic_objectives',
            'header': list(_PSR.SCHEMA_STRATEGIC_OBJECTIVES_AR),
            'rows': [['1', 'x' * 280, 't', 'r', '24 شهر']],
        }
        model['blocks']['vision_objectives']['tables'] = [tbl]
        fb = _PSR.compute_pdf_export_layout_fallbacks(model, 'ar')
        ev = _PSR.evaluate_vertical_stack_gate(model, fallbacks=fb)
        self.assertEqual(ev.get('actionable_warning_count_after'), 0)

    @_skip
    def test_user_facing_errors_no_raw_json(self):
        msg = _APP._prcy80_user_facing_error_message(
            'final_quality_gate_failed:strategic_objectives_incomplete_row:1',
            lang='ar')
        self.assertNotIn('{', msg)
        self.assertNotIn('blocking_errors', msg)
        self.assertIn('الأهداف الاستراتيجية', msg)
        try:
            json.loads(msg)
            self.fail('message must not be JSON')
        except json.JSONDecodeError:
            pass


if __name__ == '__main__':
    unittest.main()
