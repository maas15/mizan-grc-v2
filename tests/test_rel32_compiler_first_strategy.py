"""PR-REL3.2 — compiler-first canonical strategy architecture tests."""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix='test_rel32_')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', 'sqlite:///' + os.path.join(_TMP, 'test.db'))
os.environ.setdefault('OPENAI_API_KEY', '')
os.environ.setdefault('REL2_SKIP_EXPORT_EVIDENCE', '1')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_APP = None
try:
    _spec = importlib.util.spec_from_file_location('app', ROOT / 'app.py')
    _APP = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_APP)
    sys.modules['app'] = _APP
except Exception as _e:
    raise SystemExit(f'Cannot load app: {_e!r}')

from release_engine.kpi_model import (
    _parse_kpi_rows,
    resolve_kpi_canonical_family,
)
from release_engine.traceability_substance_model import (
    TRACE_CANONICAL_REGISTRY,
    build_canonical_traceability_from_registry,
)
from release_engine_v3.canonical_document import (
    build_final_document_artifact,
    clear_artifact_registry,
)
from release_engine_v3.document_quality_spec import evaluate_document_quality
from release_engine_v3.rel32_compiler import (
    compile_canonical_strategy_document,
    is_rel32_compiler_first,
)
from release_engine_v3.rel32_registries import REL32_CANONICAL_HEADINGS
from release_engine_v3.orchestrator import rel3_build_render_tree


def _ctx():
    return {
        'lang': 'ar',
        'domain': 'cyber',
        'backend': {
            'flags': {'rel3': True, 'rel31': True, 'rel32': True},
            'lang': 'ar',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        },
    }


def _compile(sections):
    return compile_canonical_strategy_document(sections, request_context=_ctx())


def _dup_mttd_kpis() -> str:
    return (
        '## 6. مؤشرات الأداء\n\n'
        '| # | وصف المؤشر | المستهدف | صيغة الاحتساب | المصدر | التكرار |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | متوسط زمن اكتشاف الحوادث الأمنية | < 4 ساعات | f | SIEM | شهري |\n'
        '| 2 | متوسط زمن كشف الحوادث الأمنية | ≤ 15 دقيقة | f | SOC | شهري |\n'
        '| 3 | MTTD | ≤ 15 دقيقة | f | SIEM | شهري |\n'
        '| 4 | متوسط زمن الاستجابة للحوادث الأمنية | < 4 ساعات | f | ITSM | شهري |\n'
        '| 5 | MTTR | ≤ 4 ساعات | f | SOAR | شهري |\n'
    )


class Rel32CompilerFirstTests(unittest.TestCase):

    def setUp(self):
        clear_artifact_registry()

    def test_01_malformed_headings_compile_to_canonical(self):
        ai = {
            'vision': '## 1. أهداف خاطئة\n\nنص',
            'pillars': '## ركائز خاطئة\n\nنص فقط',
            'environment': '## بيئة\n\nسياق',
            'gaps': '## فجوات\n\n',
            'roadmap': '## خارطة خاطئة\n\n| p | t | i | o | d | f |\n',
            'kpis': '## KPIs wrong\n\n',
            'confidence': '## ثقة\n\n',
            'governance': '## gov\n\n',
            'traceability': '## trace wrong\n\n',
        }
        r = _compile(ai)
        self.assertTrue(r.passed, r.blocking_errors)
        for key, title in REL32_CANONICAL_HEADINGS.items():
            body = r.legacy_sections.get(key, '')
            self.assertIn(title, body, msg=f'missing canonical heading for {key}')

    def test_02_gap_table_under_environment_relocated(self):
        gap_in_env = (
            '| # | الفجوة | الوصف | الأولوية | الحالة |\n'
            '|---|---|---|---|---|\n'
            '| 1 | فجوة | وصف | عالية | مفتوحة |\n'
        )
        ai = {
            'environment': f'## بيئة\n\n{gap_in_env}',
            'gaps': '',
        }
        r = _compile(ai)
        env = r.legacy_sections.get('environment', '')
        self.assertNotIn('الأولوية', env)
        gaps = r.legacy_sections.get('gaps', '')
        self.assertIn(REL32_CANONICAL_HEADINGS['gaps'], gaps)
        self.assertGreaterEqual(
            len([ln for ln in gaps.splitlines()
                 if ln.strip().startswith('|') and '---' not in ln]),
            6)

    def test_03_omitted_gaps_built_from_registry(self):
        r = _compile({'gaps': ''})
        self.assertTrue(r.passed, r.blocking_errors)
        gaps = r.legacy_sections.get('gaps', '')
        self.assertIn('ضعف تصنيف وجرد البيانات الحساسة', gaps)
        self.assertGreaterEqual(len(r.document.gaps), 5)

    def test_04_omitted_kpi_table_built_from_registry(self):
        r = _compile({'kpis': ''})
        self.assertTrue(r.passed, r.blocking_errors)
        kpis = r.legacy_sections.get('kpis', '')
        self.assertIn(REL32_CANONICAL_HEADINGS['kpis'], kpis)
        _, rows = _parse_kpi_rows(kpis.split('###')[0])
        self.assertGreaterEqual(len(rows), 5)

    def test_05_owner_columns_inserted(self):
        r = _compile({
            'roadmap': (
                '| المرحلة | الإطار | المبادرة | المخرج | الإطار |\n'
                '|---|---|---|---|---|\n'
                '| 1 | 1-6 | مبادرة | مخرج | ECC |\n'
            ),
            'kpis': '| # | وصف | قيمة | صيغة | مصدر | تواتر |\n|---|---|---|---|---|---|\n',
            'governance': '',
        })
        self.assertTrue(r.passed, r.blocking_errors)
        road = r.legacy_sections.get('roadmap', '')
        self.assertIn('مدير SOC', road)
        self.assertIn('CISO', road)
        kpis = r.legacy_sections.get('kpis', '')
        self.assertIn('المالك', kpis)
        gov = r.legacy_sections.get('governance', '')
        self.assertIn('نطاق المسؤولية', gov)

    def test_06_duplicate_mttd_deduped_to_one_mttd_one_mttr(self):
        r = _compile({'kpis': _dup_mttd_kpis()})
        self.assertTrue(r.passed, r.blocking_errors)
        _, rows = _parse_kpi_rows(
            (r.legacy_sections.get('kpis') or '').split('###')[0])
        mttd = sum(
            1 for row in rows
            if resolve_kpi_canonical_family(row[1] if len(row) > 1 else '')
            == 'soc_mttd')
        mttr = sum(
            1 for row in rows
            if resolve_kpi_canonical_family(row[1] if len(row) > 1 else '')
            == 'incident_response_mttr')
        self.assertEqual(mttd, 1)
        self.assertEqual(mttr, 1)

    def test_07_wrong_dcc_traceability_rebuilt(self):
        bad_trace = (
            '## trace\n| fw | cap | gap | init | met | risk |\n'
            '|---|---|---|---|---|---|\n'
            '| NCA DCC | تصنيف | حوكمة عامة | خطأ | — | — |\n'
        )
        r = _compile({'traceability': bad_trace})
        self.assertTrue(r.passed, r.blocking_errors)
        trace = r.legacy_sections.get('traceability', '')
        canon = build_canonical_traceability_from_registry(lang='ar')
        for fam in ('data_classification', 'dlp', 'encryption'):
            self.assertIn(
                TRACE_CANONICAL_REGISTRY[fam]['expected_gap'], trace)
        self.assertNotIn('حوكمة عامة', trace)

    def test_08_arabic_residues_repaired_before_freeze(self):
        ai = {
            'vision': 'ال معلومات والمنظمة تتطلب حوكمة',
            'environment': 'فريقمن متخصص',
        }
        r = _compile(ai)
        self.assertTrue(r.passed, r.blocking_errors)
        blob = '\n'.join(r.legacy_sections.values())
        self.assertNotRegex(blob, r'(?<![\u0600-\u06FF])ال معلومات')
        self.assertNotIn('فريقمن', blob)

    def test_09_pillar_narratives_only_builds_initiatives(self):
        r = _compile({'pillars': '## ركائز\n\nنص سردي فقط بدون جداول'})
        self.assertTrue(r.passed, r.blocking_errors)
        self.assertGreaterEqual(len(r.document.pillar_initiatives), 8)
        pillars = r.legacy_sections.get('pillars', '')
        self.assertIn('المبادرة', pillars)
        self.assertIn('المسؤول', pillars)

    def test_10_short_roadmap_expanded_to_full(self):
        short = (
            '| المرحلة | الإطار | المبادرة | المالك | المخرج | الإطار |\n'
            '|---|---|---|---|---|---|\n'
            '| 1 | 1-6 | واحد | CISO | مخرج | ECC |\n'
            '| 2 | 7-18 | اثنان | SOC | مخرج | ECC |\n'
        )
        r = _compile({'roadmap': short})
        self.assertTrue(r.passed, r.blocking_errors)
        self.assertGreaterEqual(len(r.document.roadmap), 10)

    def test_11_omitted_confidence_score_and_rationale_built(self):
        r = _compile({'confidence': '## مخاطر فقط\n\n| r | p |\n|---|---|\n'})
        self.assertTrue(r.passed, r.blocking_errors)
        conf = r.legacy_sections.get('confidence', '')
        self.assertIn('درجة الثقة', conf)
        self.assertRegex(conf, r'\d+\s*%')
        self.assertIn('مبررات التقييم', conf)
        self.assertTrue(r.document.confidence_score)
        self.assertTrue(r.document.confidence_rationale)

    def test_11b_kpi_assessment_guides_built_from_registry(self):
        r = _compile({'kpis': ''})
        self.assertTrue(r.passed, r.blocking_errors)
        kpis = r.legacy_sections.get('kpis', '')
        self.assertIn('أدلة تقييم مؤشرات الأداء', kpis)
        self.assertIn('طريقة التقييم', kpis)
        self.assertIn('دليل تقييم المؤشر رقم', kpis)
        comp = (r.diagnostics or {}).get('final_strategy_completeness') or {}
        self.assertEqual(comp.get('missing_sections_after'), [])

    def test_12_canonical_document_passes_dqs_before_render_tree(self):
        r = _compile({})
        self.assertTrue(r.passed, r.blocking_errors)
        dqs = evaluate_document_quality(legacy_sections=r.legacy_sections)
        self.assertTrue(dqs.get('passed'), dqs.get('blocking_errors'))
        art = build_final_document_artifact(
            {'sections': r.legacy_sections, 'domain': 'cyber',
             'contract_meta': {'lang': 'ar'}},
            freeze=False)
        tree = rel3_build_render_tree(art)
        self.assertTrue(tree.render_tree_hash)

    def test_13_preview_docx_pdf_same_canonical_and_render_hashes(self):
        if _APP is None:
            self.skipTest('app not loaded')
        r = _compile({})
        self.assertTrue(r.passed, r.blocking_errors)
        from release_engine_v3.orchestrator import clear_rel3_caches
        from release_engine_v3.rel31_authority import (
            clear_rel3_route_artifact_hashes,
            record_rel3_route_artifact_hashes,
            rel3_export_authoritative,
        )
        clear_rel3_caches()
        clear_rel3_route_artifact_hashes()
        backend = _APP._rel31_backend_callables()
        sections = dict(r.legacy_sections)
        md = _APP._prcy65_rebuild_content_from_sections(sections, None)
        art = {
            'sections': sections,
            'final_markdown': md,
            'domain': 'cyber',
            'sealed': True,
            'strategy_id': 'rel32-hash-test',
            'contract_meta': {'lang': 'ar'},
        }
        backend['split_sections'] = lambda _c: dict(sections)
        kwargs = {
            'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
            'selected_frameworks': ['NCA ECC', 'NCA DCC'],
        }
        flags = {'rel3': True, 'rel31': True, 'rel32': True}
        preview = rel3_export_authoritative(
            'preview', art, backend=backend, flags=flags, export_kwargs=kwargs)
        docx = rel3_export_authoritative(
            'docx', art, backend=backend, flags=flags, export_kwargs=kwargs)
        pdf = rel3_export_authoritative(
            'pdf', art, backend=backend, flags=flags, export_kwargs=kwargs)
        record_rel3_route_artifact_hashes(
            'rel32-hash-test', 'generation',
            canonical_hash=preview[0].canonical_hash,
            render_tree_hash=preview[0].render_tree_hash,
        )
        self.assertTrue(preview[0].canonical_hash)
        self.assertEqual(preview[0].canonical_hash, docx[0].canonical_hash)
        self.assertEqual(preview[0].canonical_hash, pdf[0].canonical_hash)
        self.assertEqual(preview[0].render_tree_hash, docx[0].render_tree_hash)
        self.assertEqual(preview[0].render_tree_hash, pdf[0].render_tree_hash)

    def test_14_no_route_uses_raw_ai_markdown_as_final_source(self):
        r = _compile({
            'vision': '## WRONG HEADING\n\n| AI | TABLE |\n|---|---|\n| x | y |',
        })
        self.assertTrue(r.passed, r.blocking_errors)
        self.assertEqual(r.document.source_authority, 'canonical_compiler')
        self.assertFalse(r.diagnostics.get('ai_markdown_authority'))
        self.assertNotIn('## WRONG HEADING', r.legacy_sections.get('vision', ''))
        art = build_final_document_artifact(
            {'sections': r.legacy_sections, 'domain': 'cyber',
             'contract_meta': {'lang': 'ar'}},
            freeze=False)
        self.assertNotIn('## WRONG HEADING', art.final_markdown_view or '')

    @pytest.mark.slow
    def test_15_release_readiness_report_exits_zero(self):
        if os.environ.get('REL31_READINESS_REPORT', '').strip() == '1':
            self.skipTest('nested readiness report — run as top-level gate only')
        proc = subprocess.run(
            [sys.executable, str(ROOT / 'scripts' / 'release_readiness_report.py')],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=7200,
            env={**os.environ, 'REL2_SKIP_EXPORT_EVIDENCE': '1'},
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=(proc.stdout or '')[-4000:] + (proc.stderr or '')[-2000:])

    @pytest.mark.slow
    def test_16_pytest_not_slow_zero_failures(self):
        proc = subprocess.run(
            [sys.executable, '-m', 'pytest', '-m', 'not slow', '-q',
             '--tb=no', '--no-header'],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=7200,
            env={**os.environ, 'REL2_SKIP_EXPORT_EVIDENCE': '1'},
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout[-3000:])

    @pytest.mark.slow
    def test_17_broad_suite_zero_failures(self):
        proc = subprocess.run(
            [sys.executable, '-m', 'pytest', '-m', 'not slow', '-q',
             '--tb=no', '--no-header',
             '-k', (
                 '(release or cyber or data or ai or digital or erm or global '
                 'or policy or procedure or risk or audit or prcy) and not '
                 'test_13_release_readiness_and_compiler_authority')],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=10800,
            env={**os.environ, 'REL2_SKIP_EXPORT_EVIDENCE': '1'},
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout[-3000:])


class Rel32AuthorityFlagsTests(unittest.TestCase):

    def test_compiler_first_flag_for_cyber_ar(self):
        flags = {'rel3': True, 'rel31': True}
        self.assertTrue(is_rel32_compiler_first(
            domain='cyber', lang='ar', flags=flags))
        self.assertTrue(is_rel32_compiler_first(
            domain='data', lang='ar', flags=flags))
        self.assertFalse(is_rel32_compiler_first(
            domain='cyber', lang='en', flags=flags))
        self.assertFalse(is_rel32_compiler_first(
            domain='cyber', lang='ar', flags=flags,
            document_type='policy'))


if __name__ == '__main__':
    unittest.main()
