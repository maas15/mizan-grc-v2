"""PR-REL3.1 — KPI canonical family dedup before REL3 freeze."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='test_rel31_kpi_dedup_')
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
    KPI_CANONICAL_REGISTRY,
    _duplicate_kpi_families_from_rows,
    _parse_kpi_rows,
    repair_kpi_canonical_families,
    resolve_kpi_canonical_family,
)
from release_engine.rel31_acceptance_checks import repair_rel31_canonical_sections
from release_engine_v3.document_quality_spec import (
    check_duplicate_metric_labels,
    evaluate_document_quality,
)
from release_engine_v3.evidence.docx_text_extractor import extract_docx_visible_text
from release_engine_v3.orchestrator import clear_rel3_caches, rel3_export_with_evidence
from release_engine_v3.rel31_authority import rel3_export_authoritative
from tests.fixtures.rel31_content_quality.latest_live_fixtures import (
    DOCX_LATEST,
    ensure_latest_live_fixtures,
    sections_from_latest_docx_text,
)


def _dup_mttd_kpis() -> str:
    return (
        '## 6. مؤشرات الأداء\n\n'
        '| # | وصف المؤشر | المستهدف | صيغة الاحتساب | المصدر | التكرار |\n'
        '|---|---|---|---|---|---|\n'
        '| 1 | متوسط زمن اكتشاف الحوادث الأمنية | < 4 ساعات | '
        'مجموع أزمنة اكتشاف ÷ عدد الحوادث | SIEM | شهري |\n'
        '| 2 | متوسط زمن كشف الحوادث الأمنية | ≤ 15 دقيقة | '
        'زمن الكشف ÷ عدد | SOC | شهري |\n'
        '| 3 | MTTD | ≤ 15 دقيقة | MTTD formula | SIEM | شهري |\n'
        '| 4 | متوسط زمن الاستجابة للحوادث الأمنية | < 4 ساعات | '
        'مجموع الاستجابة ÷ عدد | ITSM | شهري |\n'
        '| 5 | MTTR | ≤ 4 ساعات | MTTR formula | SOAR | شهري |\n'
        '\n### صيغة الاحتساب\n\n'
        '| # | صيغة الاحتساب | مصدر البيانات/الأداة |\n'
        '|---|---|---|\n'
        '| 1 | f1 | s1 |\n| 2 | f2 | s2 |\n| 3 | f3 | s3 |\n'
        '| 4 | f4 | s4 |\n| 5 | f5 | s5 |\n'
    )


class KpiCanonicalDetectTests(unittest.TestCase):

    def test_01_duplicate_arabic_mttd_labels_detected_before_repair(self):
        _, rows = _parse_kpi_rows(_dup_mttd_kpis())
        dup_fams, labels = _duplicate_kpi_families_from_rows(rows)
        self.assertIn('soc_mttd', dup_fams)
        self.assertGreaterEqual(len(labels), 2)
        blockers = check_duplicate_metric_labels(_dup_mttd_kpis())
        self.assertIn('duplicate_mttd', blockers)

    def test_02_mttd_hour_and_minute_targets_merge_to_one_row(self):
        repaired, diag = repair_kpi_canonical_families(
            {'kpis': _dup_mttd_kpis()}, lang='ar')
        self.assertIn('soc_mttd', diag.get('duplicate_families_before') or [])
        self.assertIn('soc_mttd', diag.get('merged_families') or [])
        text = repaired.get('kpis') or ''
        _, rows = _parse_kpi_rows(text.split('###')[0])
        mttd_rows = [
            r for r in rows
            if resolve_kpi_canonical_family(r[1] if len(r) > 1 else '') == 'soc_mttd']
        self.assertEqual(len(mttd_rows), 1)
        tgt = mttd_rows[0][2] if len(mttd_rows[0]) > 2 else ''
        self.assertIn('4', tgt)

    def test_03_mttd_and_mttr_remain_distinct(self):
        repaired, diag = repair_kpi_canonical_families(
            {'kpis': _dup_mttd_kpis()}, lang='ar')
        fams = diag.get('canonical_metric_families_after') or []
        self.assertEqual(fams.count('soc_mttd'), 1)
        self.assertEqual(fams.count('incident_response_mttr'), 1)

    def test_04_duplicate_mttd_removed_from_main_table(self):
        repaired, _ = repair_kpi_canonical_families(
            {'kpis': _dup_mttd_kpis()}, lang='ar')
        main = repaired['kpis'].split('###')[0]
        _, rows = _parse_kpi_rows(main)
        mttd = sum(
            1 for r in rows
            if resolve_kpi_canonical_family(r[1] if len(r) > 1 else '') == 'soc_mttd')
        self.assertEqual(mttd, 1)

    def test_05_duplicate_mttd_removed_from_formula_table(self):
        repaired, diag = repair_kpi_canonical_families(
            {'kpis': _dup_mttd_kpis()}, lang='ar')
        self.assertTrue(diag.get('main_formula_row_count_match'))
        self.assertEqual(diag.get('duplicate_metric_labels_after'), [])

    def test_06_formula_table_one_to_one_with_main(self):
        repaired, diag = repair_kpi_canonical_families(
            {'kpis': _dup_mttd_kpis()}, lang='ar')
        self.assertTrue(diag.get('main_formula_row_count_match'))
        self.assertTrue(diag.get('kpi_canonical_repair_passed'))

    def test_07_emits_rel3_kpi_canonical_repair_diagnostic(self):
        buf = StringIO()
        with redirect_stdout(buf):
            repair_kpi_canonical_families({'kpis': _dup_mttd_kpis()}, lang='ar')
        self.assertIn('[REL3-KPI-CANONICAL-REPAIR]', buf.getvalue())
        m = re.search(r'\[REL3-KPI-CANONICAL-REPAIR\] (\{.*\})', buf.getvalue())
        self.assertIsNotNone(m)
        payload = json.loads(m.group(1))
        self.assertEqual(payload.get('duplicate_metric_labels_after'), [])
        self.assertTrue(payload.get('kpi_canonical_repair_passed'))


class KpiCanonicalLiveFixtureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ensure_latest_live_fixtures()
        cls.docx_text = extract_docx_visible_text(DOCX_LATEST.read_bytes())
        cls.sections = sections_from_latest_docx_text(cls.docx_text)

    def test_08_live_37_fails_duplicate_mttd_before_repair(self):
        kpis = self.sections.get('kpis') or self.docx_text
        blockers = check_duplicate_metric_labels(kpis)
        self.assertIn('duplicate_mttd', blockers)

    def test_09_live_37_passes_after_canonical_repair(self):
        backend = _APP._rel31_backend_callables()
        repaired, repairs = repair_rel31_canonical_sections(
            self.sections, lang='ar', domain='cyber', backend=backend)
        self.assertTrue(repairs)
        kpis = repaired.get('kpis') or ''
        blockers = check_duplicate_metric_labels(kpis)
        self.assertNotIn('duplicate_mttd', blockers)
        dq = evaluate_document_quality(
            canonical_artifact={'sections': repaired, 'domain': 'cyber'},
            legacy_sections=repaired,
            extracted_docx_text=self.docx_text,
            extracted_preview_text='',
            extracted_pdf_text='',
            pdf_bytes=b'',
        )
        self.assertFalse(
            any('duplicate_mttd' in b for b in (dq.get('blocking_errors') or [])),
            dq.get('blocking_errors'))

    def test_10_rel3_returned_file_evidence_after_repair(self):
        clear_rel3_caches()
        backend = _APP._rel31_backend_callables()
        repaired, _ = repair_rel31_canonical_sections(
            self.sections, lang='ar', domain='cyber', backend=backend)
        md = _APP._prcy65_rebuild_content_from_sections(repaired, None)
        backend['split_sections'] = lambda _c: dict(repaired)
        export, evidence = rel3_export_authoritative(
            'docx',
            {
                'sections': repaired,
                'final_markdown': md,
                'domain': 'cyber',
                'sealed': True,
                'contract_meta': {'lang': 'ar'},
            },
            backend=backend,
            flags={'rel3': True, 'rel31': True},
            export_kwargs={
                'filename': 't.docx', 'lang': 'ar', 'domain': 'cyber',
                'selected_frameworks': ['NCA ECC', 'NCA DCC'],
            },
        )
        self.assertTrue(evidence.export_return_allowed, evidence.blocking_errors)
        self.assertNotIn(
            'duplicate_mttd',
            ' '.join(export.blocking_errors or evidence.blocking_errors or []))


class KpiCanonicalRegistryTests(unittest.TestCase):

    def test_canonical_registry_mttd_mttr_labels(self):
        self.assertIn('soc_mttd', KPI_CANONICAL_REGISTRY)
        self.assertIn('incident_response_mttr', KPI_CANONICAL_REGISTRY)
        self.assertIn('اكتشاف', KPI_CANONICAL_REGISTRY['soc_mttd']['label_ar'])
        self.assertIn('استجابة', KPI_CANONICAL_REGISTRY['incident_response_mttr']['label_ar'])


if __name__ == '__main__':
    unittest.main()
