"""PR-REL3.3 — tests for the deterministic strategy completeness top-up.

Covers the 17 required scenarios:

 1. data strategy with 0 pillars gets a deterministic data-specific pillar.
 2. dt strategy with 5 confidence/risk rows is topped up to >= 6.
 3. cyber strategy with valid pillars is unchanged.
 4. ai strategy with valid confidence/risk rows is unchanged.
 5. top-up preserves existing valid content.
 6. top-up does not duplicate existing rows.
 7. top-up does not add Cyber terms into data/dt/ai.
 8. top-up does not run for erm:risk.
 9. top-up does not run for global:gap_assessment.
10. post-repair quality gate still fails if top-up cannot safely repair.
11. diagnostics emitted with before/after counts.
12. topped-up output passes the real app.py strategy gate counters
    (proxy for "data/dt/ai/cyber strategy routes pass").
13. ERM risk sections are never mutated by the top-up.
14. global gap sections are never mutated by the top-up.
15. topped-up confidence rows are non-placeholder (no DOCX/PDF empty-cell
    bypass path).
16. topped-up risk table is well-formed (6 columns, digit index).
17. running twice is idempotent (no double top-up once minimums are met).
"""

import re

import pytest

from release_engine_v3.rel33_strategy_completeness_topup import (
    STRATEGY_TOPUP_MIN_PILLARS,
    STRATEGY_TOPUP_MIN_RISK_ROWS,
    apply_strategy_completeness_topup,
    is_strategy_completeness_topup_applicable,
    _count_risk_rows_with_mitigation,
    _count_substantive_pillars,
)


# ── Fixtures / builders ──────────────────────────────────────────────────────

_CSF_BLOCK = (
    '### عوامل النجاح الحرجة\n\n'
    '| # | العامل | الوصف | الأهمية |\n'
    '|---|---|---|---|\n'
    '| 1 | التزام القيادة | دعم الإدارة العليا الموثق | عالٍ |\n'
    '| 2 | الموارد | تمويل وكوادر كافية | عالٍ |\n'
    '| 3 | الحوكمة | إطار حوكمة واضح ومعتمد | عالٍ |\n'
    '| 4 | القياس | مؤشرات أداء دورية | متوسط |\n'
)


def _confidence_with_n_risks(n, *, domain_label='dt'):
    rows = []
    for i in range(1, n + 1):
        rows.append(
            f'| {i} | مخاطرة {domain_label} رقم {i} | متوسط | عالٍ | '
            f'خطة معالجة موثقة رقم {i} | مالك المخاطرة {i} |')
    table = (
        '### المخاطر الرئيسية\n\n'
        '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك |\n'
        '|---|---|---|---|---|---|\n'
        + '\n'.join(rows) + '\n')
    return _CSF_BLOCK + '\n' + table + '\nدرجة الثقة: 85%\n'


def _valid_pillars_block():
    parts = []
    for i in range(1, 4):
        parts.append(
            f'### الركيزة الاستراتيجية {i}: ركيزة رقم {i}\n'
            'وصف موضوعي كافٍ لهذه الركيزة الاستراتيجية.\n\n'
            '| # | المبادرة | الوصف | المخرج | المالك |\n'
            '|---|---|---|---|---|\n'
            f'| 1 | مبادرة {i} | وصف المبادرة الموثق | مخرج معتمد | مالك {i} |\n')
    return '\n\n'.join(parts)


# ── 1. data: 0 pillars -> deterministic data pillar ──────────────────────────

def test_data_zero_pillars_gets_data_pillar():
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(6)}
    diag = apply_strategy_completeness_topup(
        sections, domain='Data Management', document_type='strategy',
        lang='ar', route='data:strategy:ar', emit=False)
    assert diag['pillars_before'] == 0
    assert diag['pillars_after'] >= STRATEGY_TOPUP_MIN_PILLARS
    assert diag['pillars_added'] >= 1
    assert diag['passed'] is True
    # data-specific substance present (NDMO/data governance)
    assert 'حوكمة البيانات' in sections['pillars']


# ── 2. dt: 5 risk rows -> topped up to >= 6 ──────────────────────────────────

def test_dt_five_risk_rows_topped_up():
    sections = {'pillars': _valid_pillars_block(),
                'confidence': _confidence_with_n_risks(5)}
    diag = apply_strategy_completeness_topup(
        sections, domain='Digital Transformation', document_type='strategy',
        lang='ar', route='dt:strategy:ar', emit=False)
    assert diag['confidence_risk_rows_before'] == 5
    assert diag['confidence_risk_rows_after'] >= STRATEGY_TOPUP_MIN_RISK_ROWS
    assert diag['confidence_risk_rows_added'] >= 1
    assert diag['passed'] is True


# ── 3. cyber with valid pillars is unchanged ─────────────────────────────────

def test_cyber_valid_pillars_unchanged():
    pillars = _valid_pillars_block()
    sections = {'pillars': pillars,
                'confidence': _confidence_with_n_risks(6)}
    before = sections['pillars']
    diag = apply_strategy_completeness_topup(
        sections, domain='Cyber Security', document_type='strategy',
        lang='ar', route='cyber:strategy:ar', emit=False)
    assert diag['pillars_before'] >= STRATEGY_TOPUP_MIN_PILLARS
    assert diag['pillars_added'] == 0
    assert sections['pillars'] == before
    assert 'pillars' not in diag['sections_touched']


# ── 4. ai with valid confidence rows is unchanged ────────────────────────────

def test_ai_valid_confidence_unchanged():
    conf = _confidence_with_n_risks(6)
    sections = {'pillars': _valid_pillars_block(), 'confidence': conf}
    diag = apply_strategy_completeness_topup(
        sections, domain='Artificial Intelligence', document_type='strategy',
        lang='ar', route='ai:strategy:ar', emit=False)
    assert diag['confidence_risk_rows_before'] >= STRATEGY_TOPUP_MIN_RISK_ROWS
    assert diag['confidence_risk_rows_added'] == 0
    assert sections['confidence'] == conf
    assert 'confidence' not in diag['sections_touched']


# ── 5. preserves existing valid content ──────────────────────────────────────

def test_topup_preserves_existing_content():
    conf = _confidence_with_n_risks(5, domain_label='data')
    sections = {'pillars': '', 'confidence': conf}
    apply_strategy_completeness_topup(
        sections, domain='Data Management', document_type='strategy',
        lang='ar', emit=False)
    # every original risk row survives verbatim
    for i in range(1, 6):
        assert f'مخاطرة data رقم {i}' in sections['confidence']
    # CSF block preserved
    assert 'درجة الثقة: 85%' in sections['confidence']
    assert 'التزام القيادة' in sections['confidence']


# ── 6. does not duplicate existing rows ──────────────────────────────────────

def test_topup_no_duplicate_risk_rows():
    from release_engine_v3.rel33_domain_substance import (
        DOMAIN_CONFIDENCE_RISK_ROWS)
    first = DOMAIN_CONFIDENCE_RISK_ROWS['dt'][0][0]  # a real registry risk name
    # Seed confidence with 5 rows, one of which duplicates a registry row.
    rows = [
        f'| 1 | {first} | متوسط | عالٍ | خطة موثقة | مالك 1 |',
        '| 2 | مخاطرة فريدة 2 | متوسط | عالٍ | خطة 2 | مالك 2 |',
        '| 3 | مخاطرة فريدة 3 | منخفض | متوسط | خطة 3 | مالك 3 |',
        '| 4 | مخاطرة فريدة 4 | متوسط | عالٍ | خطة 4 | مالك 4 |',
        '| 5 | مخاطرة فريدة 5 | متوسط | متوسط | خطة 5 | مالك 5 |',
    ]
    conf = (_CSF_BLOCK + '\n### المخاطر الرئيسية\n\n'
            '| # | المخاطر | الاحتمالية | التأثير | خطة المعالجة | المالك |\n'
            '|---|---|---|---|---|---|\n' + '\n'.join(rows) + '\n')
    sections = {'pillars': _valid_pillars_block(), 'confidence': conf}
    apply_strategy_completeness_topup(
        sections, domain='Digital Transformation', document_type='strategy',
        lang='ar', emit=False)
    # The duplicated registry risk name must appear exactly once.
    assert sections['confidence'].count(first) == 1
    assert _count_risk_rows_with_mitigation(sections['confidence']) >= 6


# ── 7. no Cyber terms into data/dt/ai ────────────────────────────────────────

@pytest.mark.parametrize('domain', [
    'Data Management', 'Digital Transformation', 'Artificial Intelligence'])
def test_no_cyber_terms_in_non_cyber(domain):
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(3)}
    diag = apply_strategy_completeness_topup(
        sections, domain=domain, document_type='strategy', lang='ar',
        emit=False)
    assert diag['contamination_check_passed'] is True
    blob = (sections['pillars'] + '\n' + sections['confidence'])
    low = blob.lower()
    for term in ('ciso', 'soc', 'siem', 'csirt', ' iam', ' pam', ' mfa'):
        assert term.strip() not in low.split()  # no standalone cyber acronym
    assert 'الأمن السيبراني' not in blob
    assert 'العمليات الأمنية' not in blob


# ── 8. does not run for erm:risk ─────────────────────────────────────────────

def test_not_applicable_for_risk():
    assert is_strategy_completeness_topup_applicable('risk') is False
    conf = _confidence_with_n_risks(2)
    sections = {'pillars': '', 'confidence': conf}
    diag = apply_strategy_completeness_topup(
        sections, domain='Enterprise Risk Management', document_type='risk',
        lang='ar', route='erm:risk:ar', emit=False)
    assert diag['topup_applied'] is False
    assert sections['pillars'] == ''
    assert sections['confidence'] == conf


# ── 9. does not run for global:gap_assessment ────────────────────────────────

def test_not_applicable_for_gap_assessment():
    assert is_strategy_completeness_topup_applicable('gap_assessment') is False
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(1)}
    snapshot = dict(sections)
    diag = apply_strategy_completeness_topup(
        sections, domain='Global Standards',
        document_type='gap_assessment', lang='ar',
        route='global:gap_assessment:ar', emit=False)
    assert diag['topup_applied'] is False
    assert sections == snapshot


# ── 10. gate still fails if top-up cannot safely repair ──────────────────────

def test_failclosed_when_no_risk_table():
    # Confidence has a CSF block but NO risk table -> cannot safely append.
    sections = {'pillars': _valid_pillars_block(),
                'confidence': _CSF_BLOCK}
    diag = apply_strategy_completeness_topup(
        sections, domain='Digital Transformation', document_type='strategy',
        lang='ar', emit=False)
    assert diag['passed'] is False
    assert any('rel33_strategy_completeness_topup_failed' in e
               for e in diag['blocking_errors'])
    # Section left untouched so the strict downstream gate still fails closed.
    assert _count_risk_rows_with_mitigation(sections['confidence']) < 6


def test_failclosed_unsupported_domain():
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(2)}
    diag = apply_strategy_completeness_topup(
        sections, domain='Totally Unknown Domain', document_type='strategy',
        lang='ar', emit=False)
    assert diag['passed'] is False
    assert any('rel33_strategy_completeness_topup_failed' in e
               for e in diag['blocking_errors'])


# ── 11. diagnostics emitted with before/after counts ─────────────────────────

def test_diagnostic_fields_present():
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(4)}
    diag = apply_strategy_completeness_topup(
        sections, domain='Data Management', document_type='strategy',
        lang='ar', route='data:strategy:ar', emit=False)
    for field in (
            'route', 'domain', 'document_type', 'artifact_type', 'language',
            'generation_stage', 'pillars_before', 'pillars_after',
            'pillars_added', 'confidence_risk_rows_before',
            'confidence_risk_rows_after', 'confidence_risk_rows_added',
            'sections_touched', 'domain_profile',
            'contamination_check_passed', 'quality_gate_minimums_met',
            'topup_applied', 'blocking_errors', 'passed'):
        assert field in diag
    assert diag['domain'] == 'data'
    assert diag['pillars_before'] == 0
    assert diag['pillars_after'] >= STRATEGY_TOPUP_MIN_PILLARS


# ── 12. topped-up output passes the REAL app.py gate counters ────────────────

@pytest.mark.parametrize('domain,label', [
    ('Data Management', 'data'),
    ('Digital Transformation', 'dt'),
    ('Artificial Intelligence', 'ai'),
    ('Cyber Security', 'cyber'),
])
def test_output_passes_real_app_counters(domain, label):
    import app  # heavy import; validates alignment with runtime gates
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(5)}
    diag = apply_strategy_completeness_topup(
        sections, domain=domain, document_type='strategy', lang='ar',
        route=f'{label}:strategy:ar', emit=False)
    assert diag['passed'] is True
    # Real confidence/risk counter (post-repair assertion floor is 6).
    assert app._count_risk_rows_with_mitigation(sections['confidence']) >= 6
    # Real CSF floor.
    assert app._count_csf_rows(sections['confidence']) >= 4
    # Real pillar substantive count via the audit's discovery logic.
    pt = sections['pillars']
    matches = list(app._PILLAR_HEADING_RE_GLOBAL.finditer(pt))
    all_h3 = list(re.finditer(r'^###[^#\n][^\n]*$', pt, re.M))
    if len(all_h3) > len(matches):
        matches = all_h3
    n_pill = 0
    for i, m in enumerate(matches):
        bs = m.end()
        be = matches[i + 1].start() if i + 1 < len(matches) else len(pt)
        if app._pillar_has_substantive_initiative(pt[bs:be]):
            n_pill += 1
    assert n_pill >= STRATEGY_TOPUP_MIN_PILLARS


# ── 13. ERM risk sections never mutated ──────────────────────────────────────

def test_erm_risk_sections_never_mutated():
    sections = {
        'register': '| # | المخاطرة | الاحتمال | الأثر |\n| 1 | مخاطرة | عالٍ | عالٍ |',
        'treatments': 'خطط المعالجة',
        'pillars': '',
        'confidence': '',
    }
    snapshot = dict(sections)
    apply_strategy_completeness_topup(
        sections, domain='Enterprise Risk Management', document_type='risk',
        lang='ar', emit=False)
    assert sections == snapshot


# ── 14. global gap sections never mutated ────────────────────────────────────

def test_global_gap_sections_never_mutated():
    sections = {'gaps': 'قائمة الفجوات', 'pillars': '', 'confidence': ''}
    snapshot = dict(sections)
    apply_strategy_completeness_topup(
        sections, domain='Global Standards', document_type='gap_assessment',
        lang='ar', emit=False)
    assert sections == snapshot


# ── 15. topped-up confidence rows are non-placeholder ────────────────────────

def test_added_confidence_rows_non_placeholder():
    sections = {'pillars': _valid_pillars_block(),
                'confidence': _confidence_with_n_risks(3)}
    apply_strategy_completeness_topup(
        sections, domain='Artificial Intelligence', document_type='strategy',
        lang='ar', emit=False)
    # The real counter rejects placeholder cells; passing >=6 proves the
    # added rows are non-placeholder in Risk/Likelihood/Impact/Mitigation.
    assert _count_risk_rows_with_mitigation(sections['confidence']) >= 6


# ── 16. topped-up risk table is well-formed ──────────────────────────────────

def test_added_risk_rows_well_formed():
    sections = {'pillars': _valid_pillars_block(),
                'confidence': _confidence_with_n_risks(3)}
    apply_strategy_completeness_topup(
        sections, domain='Digital Transformation', document_type='strategy',
        lang='ar', emit=False)
    # Every risk-table data row has exactly 6 columns and a digit index.
    in_tbl = False
    seen_rows = 0
    for ln in sections['confidence'].split('\n'):
        s = ln.strip()
        if re.match(r'^\|\s*#\s*\|\s*المخاطر\s*\|', s):
            in_tbl = True
            continue
        if in_tbl:
            if not (s.startswith('|') and s.endswith('|')):
                if not s:
                    continue
                break
            if re.match(r'^\|[\s\-:|]+\|$', s):
                continue
            cells = [c.strip() for c in s.split('|')[1:-1]]
            if cells and cells[0].replace('.', '').isdigit():
                seen_rows += 1
                assert len(cells) == 6, f'bad row: {s}'
    assert seen_rows >= 6


# ── 17. idempotent second run ────────────────────────────────────────────────

def test_topup_idempotent():
    sections = {'pillars': '', 'confidence': _confidence_with_n_risks(4)}
    apply_strategy_completeness_topup(
        sections, domain='Data Management', document_type='strategy',
        lang='ar', emit=False)
    after_first = dict(sections)
    diag2 = apply_strategy_completeness_topup(
        sections, domain='Data Management', document_type='strategy',
        lang='ar', emit=False)
    assert diag2['topup_applied'] is False
    assert sections == after_first
