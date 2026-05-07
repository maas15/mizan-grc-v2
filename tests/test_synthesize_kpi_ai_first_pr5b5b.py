"""PR-5B.5B — AI-first contract for synthesize_kpi_depth.

Asserts that synthesize_kpi_depth no longer relies on deterministic
cyber-default priority banks, KPI-guide rows, or header skeletons:
it either leaves a sufficient KPI section unchanged (returning 0) or
delegates to ai_repair_strategy_section(section_key='kpis', ...).
On AI failure or invalid AI output the function raises RepairError.
The final audit gate still blocks malformed KPI sections.

Run:  python -m pytest tests/test_synthesize_kpi_ai_first_pr5b5b.py -v
"""
import os
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password')
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL',
                      'sqlite:///tmp/test_synth_kpi_pr5b5b.db')
# No AI provider configured — unmocked AI calls raise.
os.environ['OPENAI_API_KEY']    = ''
os.environ['ANTHROPIC_API_KEY'] = ''
os.environ['GOOGLE_API_KEY']    = ''
os.environ['GROQ_API_KEY']      = ''
os.environ['DEEPSEEK_API_KEY']  = ''

_APP = None
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'app', os.path.join(os.path.dirname(__file__), '..', 'app.py')
    )
    _APP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_APP)
except Exception:
    _APP = None


def _skip_if_no_app(fn):
    import functools

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if _APP is None:
            self.skipTest('app.py could not be imported')
        return fn(self, *args, **kwargs)
    return wrapper


# Canonical valid English KPI section: 9-column schema, 6 substantive
# rows, includes the Frequency column.
_VALID_KPIS_EN = (
    "## 6. Key Performance Indicators\n\n"
    "| # | Metric | Type KPI/KRI | Target Value | Calculation Formula "
    "| Data Source | Owner | Frequency | Timeframe |\n"
    "|---|--------|--------------|--------------|---------------------"
    "|-------------|-------|-----------|-----------|\n"
    "| 1 | Control implementation rate | KPI | >= 95% | "
    "(Implemented / Total) * 100 | GRC platform | CISO | Quarterly | "
    "12 months |\n"
    "| 2 | Awareness pass rate | KPI | >= 90% | (Passed / Enrolled) "
    "* 100 | LMS | CHRO | Quarterly | 9 months |\n"
    "| 3 | Mean time to detect | KPI | <= 4 hours | Sum / # incidents "
    "| SIEM | SOC Mgr | Monthly | 6 months |\n"
    "| 4 | Mean time to respond | KPI | <= 6 hours | Sum / # incidents "
    "| SIEM | SOC Mgr | Monthly | 6 months |\n"
    "| 5 | Third-party assessment coverage | KPI | 100% critical | "
    "(Assessed / Total) * 100 | TPRM | Procurement | Quarterly | "
    "12 months |\n"
    "| 6 | Patch SLA compliance | KPI | >= 95% | (On-time / Total) * 100 "
    "| ITSM | IT Ops | Monthly | 6 months |\n"
)

def _kpi_guides_en(names):
    """Build a canonical English KPI Assessment Guidelines block with one
    per-KPI guide table per name (matches the post-PR-5B.6F contract
    enforced by ``synthesize_kpi_depth`` and the final integrity gate)."""
    lines = ["", "### KPI Assessment Guidelines", ""]
    for i, n in enumerate(names, start=1):
        lines.extend([
            f"#### KPI #{i} Assessment Guide: {n}",
            "",
            "| Step | Action | Tool / System | Owner | Output |",
            "|------|--------|---------------|-------|--------|",
            "| 1 | Collect data | GRC platform | Owner | Log |",
            "| 2 | Apply formula | Spreadsheet | Owner | Value |",
            "| 3 | Validate | Review | Owner | Report |",
            "| 4 | Report | Dashboard | Owner | Statement |",
            "**Formula:** (Numerator / Denominator) * 100",
            "",
        ])
    return "\n".join(lines)


_VALID_KPIS_EN = _VALID_KPIS_EN + _kpi_guides_en([
    "Control implementation rate",
    "Awareness pass rate",
    "Mean time to detect",
    "Mean time to respond",
    "Third-party assessment coverage",
    "Patch SLA compliance",
])

_REPAIRED_KPIS_EN = (
    "## 6. Key Performance Indicators\n\n"
    "| # | Metric | Type KPI/KRI | Target Value | Calculation Formula "
    "| Data Source | Owner | Frequency | Timeframe |\n"
    "|---|--------|--------------|--------------|---------------------"
    "|-------------|-------|-----------|-----------|\n"
    "| 1 | AI metric one | KPI | >= 90% | (a / b) * 100 | source-1 "
    "| owner-1 | Quarterly | 12 months |\n"
    "| 2 | AI metric two | KPI | >= 80% | (c / d) * 100 | source-2 "
    "| owner-2 | Quarterly | 9 months |\n"
    "| 3 | AI metric three | KPI | <= 5h | sum/n | source-3 | owner-3 "
    "| Monthly | 6 months |\n"
    "| 4 | AI metric four | KPI | <= 6h | sum/n | source-4 | owner-4 "
    "| Monthly | 6 months |\n"
    "| 5 | AI metric five | KPI | 100% | (e / f) * 100 | source-5 "
    "| owner-5 | Quarterly | 12 months |\n"
    "| 6 | AI metric six | KPI | >= 95% | (g / h) * 100 | source-6 "
    "| owner-6 | Monthly | 6 months |\n"
) + _kpi_guides_en([
    "AI metric one",
    "AI metric two",
    "AI metric three",
    "AI metric four",
    "AI metric five",
    "AI metric six",
])

_KPIS_MISSING_FREQ = (
    "## 6. Key Performance Indicators\n\n"
    "| # | KPI Description | Target Value | Calculation Formula "
    "| Justification | Timeframe |\n"
    "|---|-----------------|--------------|---------------------"
    "|---------------|-----------|\n"
    "| 1 | Implementation rate | >= 95% | (i / t) * 100 | gap closure "
    "| 12 months |\n"
    "| 2 | Awareness | >= 90% | (p / e) * 100 | gap closure | 9 months |\n"
    "| 3 | MTTD | <= 4h | sum / n | SOC capability | 6 months |\n"
    "| 4 | MTTR | <= 6h | sum / n | SOC capability | 6 months |\n"
    "| 5 | TPRM coverage | 100% | (a / t) * 100 | supply gap "
    "| 12 months |\n"
    "| 6 | Patch SLA | >= 95% | (o / t) * 100 | hygiene | 6 months |\n"
)


class TestSynthesizeKPIAIFirstPR5B5B(unittest.TestCase):
    @_skip_if_no_app
    def test_valid_kpis_unchanged_returns_zero_no_ai_call(self):
        sections = {'kpis': _VALID_KPIS_EN}
        before = sections['kpis']
        with patch.object(_APP, 'ai_repair_strategy_section') as mock_ai:
            n = _APP.synthesize_kpi_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(n, 0)
        self.assertEqual(sections['kpis'], before)
        mock_ai.assert_not_called()

    @_skip_if_no_app
    def test_missing_frequency_column_triggers_ai_with_section_key_kpis(self):
        sections = {'kpis': _KPIS_MISSING_FREQ}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_KPIS_EN) as mock_ai:
            n = _APP.synthesize_kpi_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertTrue(mock_ai.called)
        kwargs = mock_ai.call_args.kwargs
        self.assertEqual(kwargs.get('section_key'), 'kpis',
                         'must use section_key="kpis"')
        self.assertNotEqual(kwargs.get('section_key'), 'kpi')
        # n == number of valid repaired rows
        self.assertGreaterEqual(n, _APP._RICHNESS_MIN_KPI_ROWS)

    @_skip_if_no_app
    def test_repaired_kpis_replace_sections_kpis(self):
        sections = {'kpis': _KPIS_MISSING_FREQ}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=_REPAIRED_KPIS_EN):
            _APP.synthesize_kpi_depth(
                sections, lang='en',
                domain='Cyber Security', fw_short='NCA ECC',
                generation_mode='drafting',
            )
        self.assertEqual(sections['kpis'], _REPAIRED_KPIS_EN)
        # Old malformed rows must not survive (no Frequency col there).
        self.assertNotIn('Implementation rate', sections['kpis'])

    @_skip_if_no_app
    def test_domain_kpi_banks_are_not_called(self):
        # PR-5B.5H: legacy _build_domain_kpi_bank_ar/_en helpers are
        # deleted.  Replace the runtime patch with an AST scan + symbol
        # absence assertion (no production call site, no module attr).
        import ast
        import os
        path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(path, 'r', encoding='utf-8') as fh:
            tree = ast.parse(fh.read(), filename=path)
        targets = {'_build_domain_kpi_bank_ar', '_build_domain_kpi_bank_en'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else None)
                self.assertNotIn(
                    name, targets,
                    f'PR-5B.5H: legacy KPI bank helper {name!r} called at '
                    f'app.py:{node.lineno}')
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_ar'))
        self.assertFalse(hasattr(_APP, '_build_domain_kpi_bank_en'))

    @_skip_if_no_app
    def test_no_kpi_guide_rows_or_skeleton_inserted(self):
        """Even when AI fails, no KPI guide blocks or deterministic
        skeleton headers are appended to sections['kpis']."""
        sections = {'kpis': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('no ai')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # No deterministic header / guide injection.
        self.assertEqual(sections['kpis'], '')

    @_skip_if_no_app
    def test_ai_failure_raises_repair_error(self):
        sections = {'kpis': _KPIS_MISSING_FREQ}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError('ai down')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        # Original (malformed) section is untouched.
        self.assertEqual(sections['kpis'], _KPIS_MISSING_FREQ)

    @_skip_if_no_app
    def test_invalid_ai_repaired_kpis_are_rejected(self):
        """If the AI returns too few valid rows, raise RepairError
        and do not overwrite sections['kpis']."""
        too_thin = (
            "## 6. Key Performance Indicators\n\n"
            "| # | Metric | Type KPI/KRI | Target Value | "
            "Calculation Formula | Data Source | Owner | Frequency "
            "| Timeframe |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
            "| 1 | only metric | KPI | 100% | a/b | src | own "
            "| Quarterly | 12 months |\n"
        )
        sections = {'kpis': _KPIS_MISSING_FREQ}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=too_thin):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )
        self.assertEqual(sections['kpis'], _KPIS_MISSING_FREQ)

    @_skip_if_no_app
    def test_ai_repaired_kpis_missing_frequency_rejected(self):
        """Even with enough rows, missing Frequency/التكرار column
        causes rejection."""
        no_freq = _KPIS_MISSING_FREQ  # 6 rows, but no Frequency col
        sections = {'kpis': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          return_value=no_freq):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, lang='en',
                    domain='Cyber Security', fw_short='NCA ECC',
                )

    @_skip_if_no_app
    def test_domain_contaminated_ai_output_is_rejected(self):
        """ai_repair_strategy_section is the gate that rejects
        domain-contaminated output. From the synth function's
        perspective: if the AI helper raises RepairError because of
        forbidden cross-domain terms, the synth must propagate.
        """
        sections = {'kpis': ''}
        with patch.object(_APP, 'ai_repair_strategy_section',
                          side_effect=_APP.RepairError(
                              'forbidden cross-domain terms in AI output')):
            with self.assertRaises(_APP.RepairError):
                _APP.synthesize_kpi_depth(
                    sections, lang='en',
                    domain='Data Management', fw_short='DAMA-DMBOK',
                )
        self.assertEqual(sections['kpis'], '')

    @_skip_if_no_app
    def test_final_audit_still_blocks_malformed_kpi_sections(self):
        """The post-normalisation audit (count_substantive_kpis +
        _RICHNESS_MIN_KPI_ROWS) must still flag KPI sections that
        fall short of the floor — regardless of whether the synth
        function was invoked."""
        bad = ("## 6. Key Performance Indicators\n\n"
               "| # | Metric | Target | Formula |\n"
               "|---|---|---|---|\n"
               "| 1 | only one | 100% | a/b |\n")
        n = _APP.count_substantive_kpis(bad)
        self.assertLess(n, _APP._RICHNESS_MIN_KPI_ROWS,
                        'audit floor must still reject thin KPIs')


if __name__ == '__main__':
    unittest.main()
