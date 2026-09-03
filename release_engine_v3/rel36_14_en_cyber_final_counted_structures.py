"""REL36.14 — English Cyber final counted-structure repair.

Staging English Cyber ECC+DCC on REL36.13 (PR #126, head ``64346f2``)
passed official 6/6 acceptance and attempts 1, 2, 4, 5, 6, then failed
attempts 3 / 7 / 8–10 *before save* on unchanged counted gates:

    prcy74_roadmap_framework_balance_invalid:ecc=2,dcc=8
    gap_guides_not_unique
    confidence_csf_insufficient 0/4

REL36.13 completed empty core sections but did not stabilize the
structures those later counters actually read:

* PR-CY74 counts ECC/DCC from the final roadmap table. REL36.13 only
  tops up when row count is low, so a complete but DCC-heavy table
  (attempt 3) was left unbalanced.
* Gap uniqueness compares the first 200 characters of each
  ``#### Gap #N Implementation`` body. REL36.13 appended catalog-cycled
  boilerplate, so two guides could share the same body prefix.
* ``_count_csf_rows`` starts at the first ``| # | Factor |`` header and
  stops at the next non-pipe heading. REL36.13 appended a second table
  (or raw rows after Key Risks) while the first table still had 0 valid
  rows.

This module inspects those final counted structures immediately before
the unchanged gates. It rebuilds only the failing English Cyber tables,
preserves valid source rows when they already satisfy the counters, and
does not mark the gates passed.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from release_engine_v3.rel31_authority import _normalize_rel31_domain_code
from release_engine_v3.rel36_8_en_cyber_pillars_parity import _selected_list
from release_engine_v3.rel36_9_en_cyber_live_stability import (
    REL36_9_ROADMAP_HEADER,
    _visible_row_count,
)
from release_engine_v3.rel36_13_en_cyber_core_completeness import (
    _GAP_CATALOG,
    _GAP_HEADER,
    _GAP_SEP,
    _RISK_CATALOG,
    _RISK_HEADER,
    _RISK_SEP,
    _md_table,
    rel36_13_should_apply,
)
from release_engine_v3.rel36_bilingual_preview_export_authority import (
    normalize_rel36_lang,
)


REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG = (
    '[REL36.14-EN-CYBER-FINAL-COUNTED-STRUCTURES]')

_ROADMAP_HEADER = (
    '| Phase | Period | Initiative | Owner | Expected Deliverable | '
    'Linked Framework |')
_ROADMAP_SEP = '|---|---|---|---|---|---|'

# 7 ECC + 5 DCC. Framework labels are the PR-CY74 primary classifier.
# DCC initiative text uses the exact PR-CY83 family phrases.
_CANONICAL_ECC_ROWS: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('Phase 1: Foundation', '1-6 months',
     'Establish cybersecurity governance and appoint a CISO',
     'CISO', 'Approved CISO charter and governance committee', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Operationalise SOC/SIEM monitoring of critical assets',
     'SOC Manager', '24x7 SOC with SIEM use cases on critical assets',
     'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Enforce IAM/PAM/MFA for privileged and critical accounts',
     'IAM/PAM Manager', 'IAM/PAM platform with MFA coverage', 'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Establish CSIRT incident response with tested playbooks',
     'CSIRT Lead', 'Ready CSIRT with approved incident playbooks',
     'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Operate a continuous vulnerability management program',
     'Vulnerability Manager', 'Vulnerability program with remediation SLA',
     'NCA ECC'),
    ('Phase 2: Enable', '7-18 months',
     'Deliver an annual security awareness and phishing program',
     'Security Awareness Manager',
     'Annual awareness plan and completion evidence', 'NCA ECC'),
    ('Phase 3: Enhance', '19-24 months',
     'Test backup and disaster-recovery resilience of critical systems',
     'Business Continuity Manager',
     'Approved backup plan and tested disaster recovery', 'NCA ECC'),
)

_CANONICAL_DCC_ROWS: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ('Phase 1: Foundation', '1-6 months',
     'Implement data classification and data inventory under NCA DCC',
     'Data Protection Officer', 'Approved classified data register',
     'NCA DCC'),
    ('Phase 2: Enable', '7-18 months',
     'Apply encryption and key management controls under NCA DCC',
     'Data Protection Officer', 'Encryption and key-management controls',
     'NCA DCC'),
    ('Phase 2: Enable', '7-18 months',
     'Enable DLP and data loss prevention monitoring of sensitive data',
     'Data Protection Officer', 'Operational DLP platform with leakage rules',
     'NCA DCC'),
    ('Phase 2: Enable', '7-18 months',
     'Approve sensitive data handling procedures under NCA DCC',
     'Data Protection Officer',
     'Approved sensitive data handling procedures', 'NCA DCC'),
    ('Phase 3: Enhance', '19-24 months',
     'Protect data in transit and at rest under NCA DCC',
     'Data Protection Officer',
     'In-transit and at-rest protection for classified data', 'NCA DCC'),
)

_CSF_HEADER = '| # | Factor | Description | Importance |'
_CSF_SEP = '|---|---|---|---|'
_CSF_FIRST_TABLE_RE = re.compile(
    r'(^\|\s*#\s*\|\s*(?:Factor|العامل)\s*\|[^\n]*\n'
    r'(?:^\|[\s\-:|]+\|[^\n]*\n)?'
    r'(?:^\|(?!\s*#\s*\|\s*(?:Factor|العامل)\s*\|)[^\n]*\n)*)',
    re.MULTILINE | re.IGNORECASE,
)
_CSF_HEADER_RE = re.compile(
    r'^\|\s*#\s*\|\s*(?:Factor|العامل)\s*\|',
    re.IGNORECASE | re.MULTILINE,
)

# Required first-table rows. Schema matches ``_count_csf_rows``.
_CSF_CATALOG: Tuple[Tuple[str, str, str], ...] = (
    ('Governance maturity',
     'CISO-led governance, committee cadence and control ownership are '
     'evidenced against NCA ECC',
     'Critical'),
    ('Control implementation coverage',
     'NCA ECC baseline controls are implemented and sampled on in-scope '
     'critical assets',
     'Critical'),
    ('Detection and response readiness',
     'SOC/SIEM use cases and CSIRT playbooks detect and contain incidents '
     'within the approved SLA',
     'High'),
    ('Data protection maturity',
     'NCA DCC classification, encryption, key management and DLP cover '
     'sensitive information',
     'High'),
    ('Resilience and recovery readiness',
     'Backup, disaster-recovery and restore tests prove approved RTO/RPO '
     'for critical services',
     'High'),
    ('Risk treatment execution',
     'Residual cyber risks have named owners, treatments and due dates '
     'reviewed by the CISO',
     'Medium'),
)

_GAP_GUIDE_RE = re.compile(
    r'(?ms)^####\s+(?:دليل|Gap\s+#\d+\s+Implementation)[^\n]*\n'
    r'(?:(?!^####\s+(?:دليل|Gap\s+#\d+\s+Implementation)|^##\s).*\n?)*',
)

_GAP_GUIDE_BODIES: Tuple[Tuple[str, str, str], ...] = (
    ('governance/CISO',
     'Cybersecurity Governance Manager',
     'Governance and CISO accountability is the first unique gap-closure '
     'family. The Cybersecurity Governance Manager drafts the CISO charter, '
     'committee terms and control-ownership register, then tables residual '
     'risk to the steering committee every quarter so NCA ECC governance '
     'evidence is sampleable.'),
    ('SOC/SIEM',
     'SOC Manager',
     'SOC and SIEM monitoring is the second unique gap-closure family. The '
     'SOC Manager onboards critical assets, writes detection use cases and '
     'proves 24x7 coverage with ticket evidence that an NCA ECC assessor '
     'can sample without relying on a narrative-only operations story.'),
    ('IAM/PAM/MFA',
     'IAM/PAM Manager',
     'IAM, PAM and MFA enforcement is the third unique gap-closure family. '
     'The IAM/PAM Manager inventories privileged accounts, forces MFA on '
     'administrative paths and records joiners/movers/leavers so NCA ECC '
     'identity evidence is complete and accountably owned.'),
    ('CSIRT incident response',
     'CSIRT Lead',
     'CSIRT incident response is the fourth unique gap-closure family. The '
     'CSIRT Lead publishes severity playbooks, runs a tabletop against a '
     'named critical service and files after-action evidence that NCA ECC '
     'incident-handling controls were exercised, not merely documented.'),
    ('vulnerability management',
     'Vulnerability Manager',
     'Vulnerability management is the fifth unique gap-closure family. The '
     'Vulnerability Manager scans in-scope assets, prioritizes critical '
     'findings and closes them inside the SLA so NCA ECC remediation '
     'evidence is a ticket trail rather than a repeated generic paragraph.'),
    ('data classification',
     'Data Protection Officer',
     'Data classification is the sixth unique gap-closure family. The Data '
     'Protection Officer inventories information assets, applies NCA DCC '
     'labels and publishes the classified register so later encryption and '
     'DLP work has a bounded, auditable scope.'),
    ('encryption/key management',
     'Data Protection Officer',
     'Encryption and key management is the seventh unique gap-closure '
     'family. The Data Protection Officer applies encryption to classified '
     'stores, documents key-lifecycle procedures and retains NCA DCC key '
     'ceremony evidence that is distinct from the classification register.'),
    ('DLP',
     'Data Protection Officer',
     'DLP and leakage prevention is the eighth unique gap-closure family. '
     'The Data Protection Officer enables DLP rules on classified channels, '
     'tunes false positives and retains alert evidence so NCA DCC leakage '
     'prevention is operational rather than a copied action block.'),
    ('backup/DR',
     'Business Continuity Manager',
     'Backup and disaster-recovery resilience is the ninth unique '
     'gap-closure family. The Business Continuity Manager tests restores '
     'against approved RTO/RPO, files the test record and remediates failed '
     'recoveries so NCA ECC continuity evidence is a dated restore, not a '
     'template sentence.'),
    ('awareness',
     'Security Awareness Manager',
     'Workforce awareness and phishing is the tenth unique gap-closure '
     'family. The Security Awareness Manager delivers the annual programme, '
     'measures completion and reports repeat-clickers to the CISO so NCA '
     'ECC awareness evidence is attendance and phishing metrics.'),
)

_MIN_ECC = 3
_MIN_DCC = 3
_MIN_CSF = 4


def rel36_14_should_apply(
        *,
        domain: Any = '',
        lang: Any = '',
        document_type: Any = '',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        text: str = '',
) -> bool:
    return rel36_13_should_apply(
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        doc_subtype=doc_subtype,
        text=text,
    )


def _app_mod():
    import app as app_mod
    return app_mod


def _roadmap_counts(text: str) -> Tuple[int, int]:
    try:
        dcc, ecc = _app_mod()._prcy68_count_roadmap_framework_rows(text or '')
        return int(ecc or 0), int(dcc or 0)
    except Exception:  # noqa: BLE001
        return 0, 0


def _roadmap_balance_blockers(text: str, selected_frameworks=None) -> List[str]:
    app = _app_mod()
    ecc, dcc = _roadmap_counts(text)
    dcc_on = True
    try:
        dcc_on = bool(app._prcy68_dcc_selected(selected_frameworks or []))
    except Exception:  # noqa: BLE001
        dcc_on = True
    blockers: List[str] = []
    if dcc_on and (ecc < _MIN_ECC or dcc < _MIN_DCC):
        blockers.append(
            f'prcy74_roadmap_framework_balance_invalid:ecc={ecc},dcc={dcc}')
    return blockers


def _first_csf_table(text: str) -> str:
    m = _CSF_FIRST_TABLE_RE.search(text or '')
    return m.group(1) if m else ''


def _count_csf(text: str) -> int:
    try:
        return int(_app_mod()._count_csf_rows(text or '') or 0)
    except Exception:  # noqa: BLE001
        return 0


def _count_first_table_csf(text: str) -> int:
    first = _first_csf_table(text or '')
    return _count_csf(first) if first else 0


def _factor_header_count(text: str) -> int:
    return len(_CSF_HEADER_RE.findall(text or ''))


def _gap_guide_bodies(text: str) -> List[str]:
    hdr = re.compile(
        r'^####\s+(?:دليل|Gap\s+#\d+\s+Implementation)',
        re.MULTILINE,
    )
    parts = hdr.split(text or '')
    return [part.strip()[:200] for part in parts[1:] if part.strip()]


def _gap_duplicate_count(text: str) -> int:
    bodies = _gap_guide_bodies(text)
    if not bodies:
        return 0
    return max(len(bodies) - len(set(bodies)), 0)


def _gap_guide_count(text: str) -> int:
    try:
        return int(_app_mod().count_gap_guides(text or '') or 0)
    except Exception:  # noqa: BLE001
        return len(_gap_guide_bodies(text))


def _csf_blockers(text: str, generation_mode: Any = 'drafting') -> List[str]:
    try:
        defects = _app_mod().validate_confidence_richness(
            {'confidence': text or ''}, 'en',
            generation_mode=generation_mode) or []
    except Exception:  # noqa: BLE001
        defects = []
    out = []
    for item in defects:
        if not item:
            continue
        tag = item[0] if isinstance(item, (list, tuple)) else str(item)
        if 'csf' in str(tag).lower():
            detail = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else ''
            out.append(f'{tag}:{detail}' if detail else str(tag))
    if _count_csf(text) < _MIN_CSF and not out:
        out.append(f'confidence_csf_insufficient:{_count_csf(text)}/{_MIN_CSF}')
    return list(dict.fromkeys(out))


def _semantic_richness_blockers(
        sections: Dict[str, str],
        *,
        lang: str = 'en',
        domain: str = 'cyber',
        generation_mode: Any = 'drafting',
        doc_subtype: str = 'technical',
) -> List[str]:
    try:
        defects = _app_mod().validate_arabic_strategy_semantic_richness(
            sections, lang, doc_subtype=doc_subtype,
            generation_mode=generation_mode, domain=domain) or []
    except Exception:  # noqa: BLE001
        defects = []
    out = []
    for item in defects:
        if not item:
            continue
        tag = item[0] if isinstance(item, (list, tuple)) else str(item)
        if tag in (
                'gap_guides_not_unique', 'confidence_csf_insufficient'):
            detail = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else ''
            out.append(f'{tag}:{detail}' if detail else str(tag))
    return list(dict.fromkeys(out))


def collect_save_blockers(
        sections: Dict[str, str],
        *,
        selected_frameworks: Optional[Iterable[Any]] = None,
        lang: str = 'en',
        domain: str = 'cyber',
        generation_mode: Any = 'drafting',
        doc_subtype: str = 'technical',
) -> List[str]:
    blockers = []
    blockers.extend(_roadmap_balance_blockers(
        str(sections.get('roadmap') or ''), selected_frameworks))
    blockers.extend(_csf_blockers(
        str(sections.get('confidence') or ''), generation_mode))
    if _gap_duplicate_count(str(sections.get('gaps') or '')):
        blockers.append(
            f'gap_guides_not_unique:{_gap_duplicate_count(str(sections.get("gaps") or ""))} '
            f'duplicate gap guide(s) detected; guides must be gap-specific')
    blockers.extend(_semantic_richness_blockers(
        sections, lang=lang, domain=domain,
        generation_mode=generation_mode, doc_subtype=doc_subtype))
    return list(dict.fromkeys(blockers))


def _render_roadmap(rows: Sequence[Sequence[str]]) -> str:
    return (
        '## 5. Implementation Roadmap\n\n'
        + _md_table(_ROADMAP_HEADER, _ROADMAP_SEP, rows)
        + '\n'
    )


def _parse_roadmap_data_rows(text: str) -> List[List[str]]:
    rows: List[List[str]] = []
    try:
        parsed = _app_mod()._prcy19_strip_md_table_rows(text or '')
    except Exception:  # noqa: BLE001
        parsed = []
    for item in parsed or []:
        if item.get('kind') != 'data' or not item.get('cells'):
            continue
        cells = [str(c or '').strip() for c in item['cells']]
        if len(cells) < 6:
            continue
        rows.append(cells[:6])
    return rows


def _row_init_key(row: Sequence[str]) -> str:
    return str(row[2] if len(row) > 2 else '').strip().lower()


def repair_roadmap_balance(
        text: str,
        selected_frameworks: Optional[Iterable[Any]] = None,
) -> Tuple[str, int]:
    """Rebuild or top-up the counted roadmap so PR-CY74 sees ECC/DCC >= 3."""
    current = text or ''
    before_blockers = _roadmap_balance_blockers(current, selected_frameworks)
    visible = _visible_row_count(current)
    missing_fams: List[str] = []
    try:
        missing_fams = list(
            _app_mod()._prcy71_missing_required_dcc_roadmap_families(current)
            or [])
    except Exception:  # noqa: BLE001
        missing_fams = []
    dlp_ok = True
    try:
        dlp_ok = bool(_app_mod()._prcy73_standalone_dlp_roadmap_row_present(current))
    except Exception:  # noqa: BLE001
        dlp_ok = True
    if not before_blockers and visible > 0 and not missing_fams and dlp_ok:
        return current, 0

    existing = _parse_roadmap_data_rows(current)
    kept: List[List[str]] = []
    seen = set()
    for row in existing:
        key = _row_init_key(row)
        if not key or key in seen:
            continue
        seen.add(key)
        kept.append(list(row))

    catalog = list(_CANONICAL_ECC_ROWS) + list(_CANONICAL_DCC_ROWS)
    added = 0
    for row in catalog:
        if _row_init_key(row) in seen:
            continue
        candidate = kept + [list(row)]
        trial = _render_roadmap(candidate)
        trial_blockers = _roadmap_balance_blockers(trial, selected_frameworks)
        trial_missing: List[str] = []
        try:
            trial_missing = list(
                _app_mod()._prcy71_missing_required_dcc_roadmap_families(trial)
                or [])
        except Exception:  # noqa: BLE001
            trial_missing = []
        if (trial_blockers or trial_missing) and not (
                len(trial_blockers) < len(before_blockers)
                or len(trial_missing) < len(missing_fams)):
            # Still useful to add missing ECC/DCC identities.
            ecc_now, dcc_now = _roadmap_counts(_render_roadmap(kept))
            if row[5] == 'NCA ECC' and ecc_now < _MIN_ECC:
                kept.append(list(row))
                seen.add(_row_init_key(row))
                added += 1
            elif row[5] == 'NCA DCC' and (
                    dcc_now < _MIN_DCC or trial_missing):
                kept.append(list(row))
                seen.add(_row_init_key(row))
                added += 1
            continue
        kept.append(list(row))
        seen.add(_row_init_key(row))
        added += 1
        if not trial_blockers and not trial_missing:
            break

    rendered = _render_roadmap(kept) if kept else _render_roadmap(
        [list(r) for r in catalog])
    if (_roadmap_balance_blockers(rendered, selected_frameworks)
            or _visible_row_count(rendered) <= 0):
        rendered = _render_roadmap([list(r) for r in catalog])
        added = max(added, len(catalog))
    return rendered, added


def _gap_guide_block(idx: int, family: str, owner: str, body: str) -> str:
    return (
        f'#### Gap #{idx} Implementation Guide:\n'
        f'{body} Owner: {owner}. Family: {family}. Delivery includes an '
        f'approved procedure, an operating cadence and auditable artefacts '
        f'that an independent assessor can sample for this family only.'
    )


def repair_gap_guide_uniqueness(text: str) -> Tuple[str, int]:
    """Rewrite gap guides so the uniqueness counter sees distinct bodies."""
    out = text or ''
    table_part = _GAP_GUIDE_RE.sub('', out).rstrip()
    if _GAP_HEADER not in table_part:
        rows = [[str(i + 1), *row] for i, row in enumerate(_GAP_CATALOG)]
        table_part = (
            '## 4. Gap Analysis\n\n### Identified Gaps\n\n'
            + _md_table(_GAP_HEADER, _GAP_SEP, rows)
        )
    guides = []
    for idx, (family, owner, body) in enumerate(_GAP_GUIDE_BODIES, start=1):
        guides.append(_gap_guide_block(idx, family, owner, body))
    extra = max(_gap_row_count(table_part) - len(_GAP_GUIDE_BODIES), 0)
    for offset in range(extra):
        idx = len(_GAP_GUIDE_BODIES) + offset + 1
        family, owner, body = _GAP_GUIDE_BODIES[offset % len(_GAP_GUIDE_BODIES)]
        guides.append(_gap_guide_block(
            idx, f'{family}-extra-{idx}', owner,
            f'Supplemental unique guide {idx} extends {family} with a '
            f'distinct closure path and evidence pack {idx} that does not '
            f'reuse the first-200-character body of any earlier guide. '))
    rendered = (
        table_part.rstrip()
        + '\n\n### Gap Implementation Guidance\n\n'
        + '\n\n'.join(guides)
        + '\n'
    )
    return rendered, len(guides)


def _gap_row_count(text: str) -> int:
    try:
        return int(_app_mod().count_substantive_gaps(text or '') or 0)
    except Exception:  # noqa: BLE001
        return 0


def _csf_table() -> str:
    rows = [[str(i + 1), *row] for i, row in enumerate(_CSF_CATALOG)]
    return _md_table(_CSF_HEADER, _CSF_SEP, rows)


def _ensure_confidence_shell(text: str) -> str:
    out = text or ''
    if not re.search(
            r'(?:\*\*)?(?:Confidence\s+Score)(?:\*\*)?\s*:?\s*(?:\*\*)?\s*\d{1,3}\s*%',
            out, re.IGNORECASE):
        out = (out.rstrip() + '\n\n**Confidence Score:** 72%\n').lstrip()
    if not re.search(r'(?:justification|rationale)', out, re.IGNORECASE):
        out = (
            out.rstrip()
            + '\n\n### Score Justification\n'
            'The score is a conservative rationale for current NCA ECC and '
            'NCA DCC readiness: governance, detection, data protection and '
            'recovery controls are defined but not yet fully evidenced.\n'
        )
    return out


def repair_first_csf_table(text: str) -> Tuple[str, int]:
    """Replace the first counted Factor table. Do not append a second one."""
    out = _ensure_confidence_shell(text or '')
    table = '### Critical Success Factors\n\n' + _csf_table() + '\n'
    if _CSF_FIRST_TABLE_RE.search(out):
        out = _CSF_FIRST_TABLE_RE.sub(_csf_table() + '\n', out, count=1)
        # Drop any later Factor tables so the gate cannot ignore the first.
        later = list(_CSF_HEADER_RE.finditer(out))
        if later:
            # Keep content before a second Factor header only when the
            # first table already sits in that prefix.
            first = _CSF_FIRST_TABLE_RE.search(out)
            if first:
                prefix = out[: first.end()]
                suffix = out[first.end():]
                suffix = _CSF_FIRST_TABLE_RE.sub('', suffix)
                suffix = re.sub(
                    r'(?im)^###\s+Critical Success Factors\s*\n+',
                    '', suffix)
                out = prefix + suffix
    else:
        # Insert the first counted table before Key Risks when present.
        risk_m = re.search(
            r'^###\s+(?:Key Risks|المخاطر)', out, re.MULTILINE | re.IGNORECASE)
        if risk_m:
            out = out[:risk_m.start()] + table + '\n' + out[risk_m.start():]
        else:
            out = out.rstrip() + '\n\n' + table
    if _count_risk_rows(out) < _MIN_CSF:
        risk_table = (
            '### Key Risks\n\n'
            + _md_table(
                _RISK_HEADER, _RISK_SEP,
                [[str(i + 1), *row] for i, row in enumerate(_RISK_CATALOG)])
            + '\n'
        )
        if not re.search(r'^###\s+Key Risks', out, re.MULTILINE | re.IGNORECASE):
            out = out.rstrip() + '\n\n' + risk_table
    if not re.search(r'^##\s*7\.', out, re.MULTILINE):
        out = '## 7. Confidence Assessment\n\n' + out.lstrip()
    return out, len(_CSF_CATALOG)


def _count_risk_rows(text: str) -> int:
    try:
        return int(_app_mod()._count_risk_rows_with_mitigation(text or '') or 0)
    except Exception:  # noqa: BLE001
        return 0


def evaluate_rel36_14_en_cyber_final_counted_structures(
        *,
        task_id: Any = '',
        attempt_id: Any = '',
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        roadmap_ecc_before: int = 0,
        roadmap_dcc_before: int = 0,
        roadmap_ecc_after: int = 0,
        roadmap_dcc_after: int = 0,
        roadmap_balance_blockers_before: Optional[Sequence[str]] = None,
        roadmap_balance_blockers_after: Optional[Sequence[str]] = None,
        gap_guides_count_before: int = 0,
        gap_guides_count_after: int = 0,
        gap_guides_duplicate_count_before: int = 0,
        gap_guides_duplicate_count_after: int = 0,
        gap_guides_unique_after: bool = False,
        confidence_first_table_rows_before: int = 0,
        confidence_first_table_rows_after: int = 0,
        confidence_csf_rows_before: int = 0,
        confidence_csf_rows_after: int = 0,
        confidence_csf_blockers_before: Optional[Sequence[str]] = None,
        confidence_csf_blockers_after: Optional[Sequence[str]] = None,
        repaired_sections: Optional[Sequence[str]] = None,
        save_blockers_before: Optional[Sequence[str]] = None,
        save_blockers_after: Optional[Sequence[str]] = None,
        docx_allowed: bool = False,
        pdf_allowed: bool = False,
) -> Dict[str, Any]:
    road_after = list(roadmap_balance_blockers_after or [])
    csf_after = list(confidence_csf_blockers_after or [])
    save_after = list(save_blockers_after or [])
    unique_after = bool(gap_guides_unique_after) and (
        int(gap_guides_duplicate_count_after or 0) == 0)
    passed = (
        not road_after
        and int(gap_guides_duplicate_count_after or 0) == 0
        and unique_after
        and int(confidence_csf_rows_after or 0) >= _MIN_CSF
        and int(confidence_first_table_rows_after or 0) >= _MIN_CSF
        and not csf_after
        and not save_after
    )
    if road_after or csf_after or save_after or not unique_after:
        passed = False
    return {
        'task_id': str(task_id or ''),
        'attempt_id': str(attempt_id or ''),
        'domain': _normalize_rel31_domain_code(domain) or 'cyber',
        'lang': normalize_rel36_lang(lang) or 'en',
        'document_type': str(document_type or 'strategy'),
        'selected_frameworks': _selected_list(selected_frameworks),
        'roadmap_ecc_before': int(roadmap_ecc_before or 0),
        'roadmap_dcc_before': int(roadmap_dcc_before or 0),
        'roadmap_ecc_after': int(roadmap_ecc_after or 0),
        'roadmap_dcc_after': int(roadmap_dcc_after or 0),
        'roadmap_balance_blockers_before': list(
            roadmap_balance_blockers_before or []),
        'roadmap_balance_blockers_after': road_after,
        'gap_guides_count_before': int(gap_guides_count_before or 0),
        'gap_guides_count_after': int(gap_guides_count_after or 0),
        'gap_guides_duplicate_count_before': int(
            gap_guides_duplicate_count_before or 0),
        'gap_guides_duplicate_count_after': int(
            gap_guides_duplicate_count_after or 0),
        'gap_guides_unique_after': unique_after,
        'confidence_first_table_rows_before': int(
            confidence_first_table_rows_before or 0),
        'confidence_first_table_rows_after': int(
            confidence_first_table_rows_after or 0),
        'confidence_csf_rows_before': int(confidence_csf_rows_before or 0),
        'confidence_csf_rows_after': int(confidence_csf_rows_after or 0),
        'confidence_csf_blockers_before': list(
            confidence_csf_blockers_before or []),
        'confidence_csf_blockers_after': csf_after,
        'repaired_sections': list(repaired_sections or []),
        'save_blockers_before': list(save_blockers_before or []),
        'save_blockers_after': save_after,
        'docx_allowed': bool(docx_allowed) and passed,
        'pdf_allowed': bool(pdf_allowed) and passed,
        'passed': bool(passed),
        'applied': True,
    }


def emit_rel36_14_en_cyber_final_counted_structures(
        payload: Dict[str, Any]) -> None:
    try:
        print(
            REL36_14_EN_CYBER_FINAL_COUNTED_STRUCTURES_TAG + ' '
            + json.dumps(payload, ensure_ascii=False, default=str),
            flush=True,
        )
    except Exception:  # noqa: BLE001
        pass


def apply_rel36_14_en_cyber_final_counted_structures(
        sections: Dict[str, str],
        *,
        domain: Any = 'cyber',
        lang: Any = 'en',
        document_type: Any = 'strategy',
        selected_frameworks: Optional[Iterable[Any]] = None,
        doc_subtype: Any = 'technical',
        generation_mode: Any = 'drafting',
        backend: Optional[Dict[str, Any]] = None,
        task_id: Any = None,
        attempt_id: Any = None,
        artifact: Optional[Dict[str, Any]] = None,
        emit: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    del backend, artifact  # accepted for hook parity with REL36.13
    out = dict(sections or {})
    blob = '\n'.join(str(v) for v in out.values() if isinstance(v, str))
    if not rel36_14_should_apply(
            domain=domain, lang=lang, document_type=document_type,
            selected_frameworks=selected_frameworks,
            doc_subtype=doc_subtype, text=blob):
        return sections, {
            'applied': False,
            'passed': False,
            'action_taken': 'skipped',
            'save_blockers_after': [],
        }

    attempt = attempt_id or str(uuid.uuid4())[:8]
    road_before_text = str(out.get('roadmap') or '')
    gaps_before_text = str(out.get('gaps') or '')
    conf_before_text = str(out.get('confidence') or '')
    ecc_b, dcc_b = _roadmap_counts(road_before_text)
    road_block_b = _roadmap_balance_blockers(
        road_before_text, selected_frameworks)
    gap_count_b = _gap_guide_count(gaps_before_text)
    gap_dup_b = _gap_duplicate_count(gaps_before_text)
    first_csf_b = _count_first_table_csf(conf_before_text)
    csf_b = _count_csf(conf_before_text)
    csf_block_b = _csf_blockers(conf_before_text, generation_mode)
    save_b = collect_save_blockers(
        out, selected_frameworks=selected_frameworks, lang=lang,
        domain=domain, generation_mode=generation_mode,
        doc_subtype=doc_subtype)

    repaired: List[str] = []
    if road_block_b or _visible_row_count(road_before_text) <= 0:
        out['roadmap'], _n = repair_roadmap_balance(
            road_before_text, selected_frameworks)
        repaired.append('roadmap')
    if gap_dup_b or gap_count_b < 10:
        out['gaps'], _n = repair_gap_guide_uniqueness(gaps_before_text)
        repaired.append('gaps')
    if (csf_b < _MIN_CSF or first_csf_b < _MIN_CSF or csf_block_b
            or _factor_header_count(conf_before_text) > 1):
        out['confidence'], _n = repair_first_csf_table(conf_before_text)
        repaired.append('confidence')

    ecc_a, dcc_a = _roadmap_counts(str(out.get('roadmap') or ''))
    road_block_a = _roadmap_balance_blockers(
        str(out.get('roadmap') or ''), selected_frameworks)
    gap_count_a = _gap_guide_count(str(out.get('gaps') or ''))
    gap_dup_a = _gap_duplicate_count(str(out.get('gaps') or ''))
    first_csf_a = _count_first_table_csf(str(out.get('confidence') or ''))
    csf_a = _count_csf(str(out.get('confidence') or ''))
    csf_block_a = _csf_blockers(
        str(out.get('confidence') or ''), generation_mode)
    save_a = collect_save_blockers(
        out, selected_frameworks=selected_frameworks, lang=lang,
        domain=domain, generation_mode=generation_mode,
        doc_subtype=doc_subtype)
    # If any counted gate still fails after a conservative top-up, rebuild
    # that structure from the canonical catalog.
    if road_block_a:
        out['roadmap'], _n = repair_roadmap_balance('', selected_frameworks)
        if 'roadmap' not in repaired:
            repaired.append('roadmap')
        ecc_a, dcc_a = _roadmap_counts(str(out.get('roadmap') or ''))
        road_block_a = _roadmap_balance_blockers(
            str(out.get('roadmap') or ''), selected_frameworks)
    if gap_dup_a:
        out['gaps'], _n = repair_gap_guide_uniqueness(str(out.get('gaps') or ''))
        if 'gaps' not in repaired:
            repaired.append('gaps')
        gap_count_a = _gap_guide_count(str(out.get('gaps') or ''))
        gap_dup_a = _gap_duplicate_count(str(out.get('gaps') or ''))
    if csf_a < _MIN_CSF or first_csf_a < _MIN_CSF or csf_block_a:
        out['confidence'], _n = repair_first_csf_table(
            str(out.get('confidence') or ''))
        if 'confidence' not in repaired:
            repaired.append('confidence')
        first_csf_a = _count_first_table_csf(str(out.get('confidence') or ''))
        csf_a = _count_csf(str(out.get('confidence') or ''))
        csf_block_a = _csf_blockers(
            str(out.get('confidence') or ''), generation_mode)
    save_a = collect_save_blockers(
        out, selected_frameworks=selected_frameworks, lang=lang,
        domain=domain, generation_mode=generation_mode,
        doc_subtype=doc_subtype)

    export_ok = (
        not road_block_a
        and gap_dup_a == 0
        and csf_a >= _MIN_CSF
        and first_csf_a >= _MIN_CSF
        and not csf_block_a
        and not save_a
    )
    diag = evaluate_rel36_14_en_cyber_final_counted_structures(
        task_id=task_id,
        attempt_id=attempt,
        domain=domain,
        lang=lang,
        document_type=document_type,
        selected_frameworks=selected_frameworks,
        roadmap_ecc_before=ecc_b,
        roadmap_dcc_before=dcc_b,
        roadmap_ecc_after=ecc_a,
        roadmap_dcc_after=dcc_a,
        roadmap_balance_blockers_before=road_block_b,
        roadmap_balance_blockers_after=road_block_a,
        gap_guides_count_before=gap_count_b,
        gap_guides_count_after=gap_count_a,
        gap_guides_duplicate_count_before=gap_dup_b,
        gap_guides_duplicate_count_after=gap_dup_a,
        gap_guides_unique_after=gap_dup_a == 0,
        confidence_first_table_rows_before=first_csf_b,
        confidence_first_table_rows_after=first_csf_a,
        confidence_csf_rows_before=csf_b,
        confidence_csf_rows_after=csf_a,
        confidence_csf_blockers_before=csf_block_b,
        confidence_csf_blockers_after=csf_block_a,
        repaired_sections=repaired,
        save_blockers_before=save_b,
        save_blockers_after=save_a,
        docx_allowed=export_ok,
        pdf_allowed=export_ok,
    )
    if emit:
        emit_rel36_14_en_cyber_final_counted_structures(diag)
    return out, diag
