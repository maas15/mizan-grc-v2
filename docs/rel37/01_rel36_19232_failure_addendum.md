# REL36.19–36.23.2 Failure Closeout Addendum

**Date:** 2026-09-13  
**Decision:** Stop PR #128 hotfix work. Do not implement REL36.24.  
**PR #128:** remains OPEN / unmerged as forensic evidence and requirement catalog.

This addendum freezes the failure record. It does not add code to PR #128.

## Freeze snapshot

| Surface | Value |
|---|---|
| Production service | `mizan-grc-v2` `srv-d5vgjnsoud1c738gtpgg` |
| Production deploy | `dep-dabg86710e5c73fu2uig` |
| Production commit | `ec779cc1a91f5d3dd4bef0fac45c30d20bf28410` (PR #125 / REL36.11) |
| Production `autoDeploy` | `no` |
| Production hook | not called |
| `origin/main` | `fb6173642f37fc02210da360770ad3614162e362` (PR #127 / REL36.18.1) |
| PR #128 head | `f04f60b7922308a48b0f832acc146ada02ed9c7e` |
| PR #128 on `main`? | No |
| Staging (last validation) | `mizan-grc-rel21-staging` `dep-daj36noae00c738epk1g` @ `f04f60b` |
| QA Harness | not started |

## Final official staging on `f04f60b`

`REL33_STAGING_ACCEPTANCE_PASS=0`. Accepted **1/6**. `script_blockers=[]`. Real save-gate failures, not transport.

| Route | Result | App blocker |
|---|---|---|
| `cyber:strategy:ar:technical` | fail | `kpi_main_header_count_invalid (kpis) 0/1` |
| `data:strategy:ar` | fail | `kpi_main_header_count_invalid (kpis) 0/1` |
| `ai:strategy:ar` | fail | `kpi_main_header_count_invalid (kpis) 0/1` |
| `dt:strategy:ar` | fail | `kpis_per_guide_count_mismatch=8` guides vs `11` rows |
| `erm:risk:ar` | **accepted** | none |
| `global:gap_assessment:ar` | fail | `kpis_main_table_header_count_invalid=0` |

CI on `f04f60b` passed. CI is not staging.

## Why the chain is not a safe hotfix

REL36.23.2 tried to stop a formula/source appendix from counting as a second KPI main table. It did that by installing a **global** 8-role header counter on save/audit. Arabic headers that use `المصدر` (definite article) fail that counter (`مصدر` / `مصدر البيانات` only), so Cyber/Data/AI/Global became `0/1`. DT merged extra DGA rows without typed guides and hit `8` vs `11`.

That is a cross-domain schema/counting regression, not a one-route flake. Another REL36.x regex would continue the tower.

## Requirement catalog (reuse rules, not modules)

Allowed as **requirements** for REL37. Do not cherry-pick PR #128 commits or port these as live markdown mutators:

| Source | Requirement to keep |
|---|---|
| REL36.19.1 | Language parity; exact Arabic `org_name` in English docs; do not strip legitimate Arabic; repair before canonical hash (as a model rule) |
| REL36.20 | Data/AI gap and KPI guides complete before save |
| REL36.20.2 | Arabic Data roadmap rows remain countable; no insufficient-row collapse |
| REL36.21 | Selected-framework SO coverage: NDMO, PDPL, SDAIA from **request metadata** |
| REL36.22 | DGA `citizen_experience` (and interoperability / digital_services) present in DT counted sections |
| REL36.23 | Unique gap guides; English SO header exactly `Strategic Objective \| Measurable Target \| Rationale \| Timeframe` |
| REL36.23.2 | Formula/source table is **not** a KPI main table |

Do **not** port:

- REL36.23.2 global KPI header counter
- Post-hoc DGA row insertion / table collapse as a markdown rewriter
- Stacked `_apply_rel36_*` hooks

## Artifacts to preserve (do not commit)

Existing untracked / workspace evidence stays untracked:

- `qa_outputs/rel36_23_2_staging_samples/`
- `qa_outputs/rel36_23_1_staging_samples/`
- `qa_outputs/rel36_23_staging_samples/`
- `/opt/cursor/artifacts/rel36_23_2_staging_samples/`
- `/opt/cursor/artifacts/rel36_closeout/`
- `static/fonts/Amiri-Regular.ttf` (do not stage)

PR #128 itself is the code-history evidence (+14957 lines of repair on 35 files vs `main`).

## REL37 start line

New work starts from `origin/main` on `feature/rel37-deterministic-data-ai-dt-compilers`.  
PR #128 is not an ancestor of that branch. Compilers are not implemented until this plan is approved.
