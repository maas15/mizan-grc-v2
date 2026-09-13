# REL36 Forensic Closeout

**Status:** Hotfix escalation stopped. REL36.24 will not be implemented.  
**Date:** 2026-09-13  
**Scope:** Evidence only. No code fix. PR #128 left open and unmerged.

## 1. Production

| Field | Value |
|---|---|
| Service | `mizan-grc-v2` |
| Service ID | `srv-d5vgjnsoud1c738gtpgg` |
| Live deploy | `dep-dabg86710e5c73fu2uig` |
| Commit | `ec779cc1a91f5d3dd4bef0fac45c30d20bf28410` |
| Message | Merge pull request #125 from `feature/rel36-11-english-cyber-export-stability-hotfix` |
| `autoDeploy` | `no` |
| Hook | Not called during REL36.19–23.2 validation |

Production is **REL36.11**, not main and not PR #128. It has been unchanged since 2026-09-01.

## 2. Current `main`

| Field | Value |
|---|---|
| Commit | `fb6173642f37fc02210da360770ad3614162e362` |
| Message | Merge pull request #127 from `feature/rel36-18-ai-sdaia-kpi-synth-hotfix` |
| Tip content | REL36.18 + REL36.18.1 (AI SDAIA KPI synth) |
| PR #128 merged? | No. `f04f60b` is not an ancestor of `origin/main`. |

`main` is ahead of production (REL36.12–18.1 merged, not deployed to production).

## 3. PR #128 identity and commit chain

| Field | Value |
|---|---|
| PR | [#128](https://github.com/maas15/mizan-grc-v2/pull/128) |
| Branch | `feature/rel36-19-bilingual-language-parity-hotfix` |
| State | OPEN, not draft, `mergedAt=null`, base `main` |
| Head | `f04f60b7922308a48b0f832acc146ada02ed9c7e` |
| Title | REL36.23.2: fix DT Arabic live KPI classifier and token persistence |

### Chain requested (`931900f` → `f04f60b`)

| SHA | Date (UTC) | Tag | Subject |
|---|---|---|---|
| `931900f` | 2026-09-07 18:44 | REL36.19 | keep section H2 and isolate English Cyber catalog |
| `94936cc` | 2026-09-08 05:02 | REL36.19.1 | fix bilingual parity Codex P1 guards |
| `d537066` | 2026-09-08 10:59 | REL36.20 | stabilize Data and AI guide save-gates |
| `62acc73` | 2026-09-09 04:49 | REL36.20.1 | fix Data roadmap family integrity regression |
| `0178261` | 2026-09-09 07:08 | REL36.20.2 | preserve Arabic Data countable roadmap rows |
| `8d4a954` | 2026-09-10 05:11 | REL36.21 | stabilize English Data and AI framework objectives |
| `6b702c4` | 2026-09-10 08:20 | REL36.22 | stabilize DT DGA citizen experience coverage |
| `64df263` | 2026-09-12 13:22 | REL36.23 | stabilize Data AI guides and English visible headers |
| `a75df55` | 2026-09-12 16:52 | REL36.23.1 | enforce DT DGA single KPI table |
| `f04f60b` | 2026-09-13 05:11 | REL36.23.2 | fix DT Arabic live KPI classifier and token persistence |

PR #128 vs `main` also includes `58ebe9e` (REL36.19: enforce bilingual visible language parity) immediately before `931900f`. Codex leftover P1/P2 comments on #128 still point at `931900f`.

Diff vs `main`: 35 files, **+14957 / −127**. Sixteen `_apply_rel36_*` wrappers exist in `app.py`. Twenty-nine `rel36_*.py` modules exist in `release_engine_v3/` (including pre-#128 REL36.1–18 modules already on `main`).

## 4. Local-only vs staging outcomes

Legend:

- **Local** = pytest / smoke / diagnostic on the agent workspace.
- **PR staging** = `mizan-grc-rel21-staging` deploy of that SHA.
- **Official 6/6** = `scripts/_rel33_all_domain_staging_acceptance.py` with `REL33_STAGING_ACCEPTANCE_PASS=1` and no critical live-content fail.
- **Critical live** = saved/latest artifact inspection, not helper-on-copy.

| Commit | Local gates | PR staging deployed | Official 6/6 | Critical live / later matrix |
|---|---|---|---|---|
| `58ebe9e` / `931900f` REL36.19 | Claimed pass | Not retained as a distinct official report in this workspace | No retained 6/6 pass | Codex P1/P2 opened; 19.1 followed |
| `94936cc` REL36.19.1 | Claimed pass | Not retained | No retained 6/6 pass | Intended to close 931900f P1/P2; comments remain mapped |
| `d537066` REL36.20 | Local samples exist | `dep-dafuqrht0dsc73fsa660` | No retained 6/6 pass | Guide-save local samples only |
| `62acc73` REL36.20.1 | Local samples exist | `dep-dagefrqd0e5s73c5ebh0` | No retained 6/6 pass | Roadmap family local samples |
| `0178261` REL36.20.2 | Local samples exist | `dep-dagght2d0e5s73cdq35g` | No retained 6/6 pass | Arabic Data countable-roadmap local samples |
| `8d4a954` REL36.21 | Local samples exist | `dep-dah47im1egvs73ch305g` | No retained 6/6 pass | EN Data/AI objective local samples |
| `6b702c4` REL36.22 | Local samples exist | `dep-dah6ph142hec73f1sn50` | No retained 6/6 pass | DT DGA citizen local samples |
| `64df263` REL36.23 | Local smoke claimed | `dep-dails8h5efls73e2g9a0` | **Fail 5/6** | DT `kpi_main_header_count_invalid 2/1`. Matrix not started |
| `a75df55` REL36.23.1 | Local 31 tests + smoke claimed | `dep-daiois6k1f9s7391lj50` | Routes recovered **6/6 after transport** | **Critical DT live failed**: split `المست فيد` ×23, no contiguous `المستفيد`, official-regex header count 2. Helper-on-copy `passed=true` rejected. Matrix not started |
| `f04f60b` REL36.23.2 | Local 38 tests + smoke claimed | `dep-daj36noae00c738epk1g` (still live) | **Fail 1/6** | See §5. Matrix not started |

**None of REL36.19–23.2 has a clean official staging acceptance plus critical live pass.**  
CI on `f04f60b` passed (`REL32 PR gate`, run `34739691472`). CI is not staging.

Merged-to-main REL36.1–18.1 are a separate history. Production only has through REL36.11. Those earlier hotfixes also chased Cyber export/pillar/roadmap and Data/AI leakage, which is the same class of problem (repair-after-markdown) even when a given SHA was mergeable.

## 5. REL36.23.2 official staging (stop trigger)

Deploy: `f04f60b` / `dep-daj36noae00c738epk1g`.  
Post-settle: `static_version=f04f60b79223`, `commit_match=true`, `ready=true`, `login_status=200`.  
`REL33_STAGING_ACCEPTANCE_PASS=0`. `script_blockers=[]`.

| Route | Accepted | Save | App blocker |
|---|---|---|---|
| `cyber:strategy:ar:technical` | no | no | `kpi_main_header_count_invalid (kpis) 0/1` |
| `data:strategy:ar` | no | no | `kpi_main_header_count_invalid (kpis) 0/1` |
| `ai:strategy:ar` | no | no | `kpi_main_header_count_invalid (kpis) 0/1` |
| `dt:strategy:ar` | no | no | `kpis_per_guide_count_mismatch=8` guides vs `11` rows |
| `erm:risk:ar` | **yes** | yes | none |
| `global:gap_assessment:ar` | no | no | `kpis_main_table_header_count_invalid=0` |

Classification: **REL36.23.2 introduced or exposed a cross-domain KPI schema/counting regression.**

Local reproduction of the classifier (no code change):

- Canonical 8-col header with `مصدر` → full-schema count **1**.
- Same header with `المصدر` → full-schema count **0** (source-role regex is `^مصدر$` / `مصدر البيانات` only).
- The new counter is used as the **global** save/audit gate (`_count_full_kpi_main_headers_for_gate` in `app.py`), not DT-only.

DT’s 8-vs-11 mismatch is consistent with inserting three DGA KPI rows (citizen / interop / digital) into the first main table without emitting matching per-KPI guide objects.

Helper-on-copy was **not** accepted as a pass. No new live DT latest artifact exists because save failed.

## 6. Recurring failure classes

These classes recurred across REL36.19–23.2 (and several earlier REL36.x hotfixes). Each was “fixed” by another markdown/regex repair, then reappeared on a later path (save vs preview vs DOCX vs PDF vs latest).

### 6.1 Language parity

English documents emitting Arabic table headers or prose; Arabic documents leaking English headers; Arabic `org_name` deleted by English sanitization; preview header-mismatch banners. REL36.19 / 19.1 targeted this. Codex P1 on `rel36_19_bilingual_language_parity.py` remains on the PR.

### 6.2 Selected-framework objective / coverage

`selected_framework_compliance_objective_missing:NDMO,PDPL` / `:SDAIA`.  
`selected_framework_coverage_missing:DGA:citizen_experience`.  
REL36.21 and REL36.22 inserted detector-visible rows into markdown. Coverage then drifted when a later compiler/formula-sync/persist path rewrote the section.

### 6.3 Roadmap countability

Arabic Data `roadmap_rows_insufficient`. REL36.20.2 preserved countable rows against a later family-heading cleaner. Count is a parse of markdown pipes, not a typed row list.

### 6.4 Roadmap family duplicate / restart

`roadmap_family_duplicated`, `roadmap_family_restart_detected`. REL36.20.1 normalized family headings. The same families are also inferred by REL36.7 / 36.10 balance repairs and by export extractors.

### 6.5 Gap-guide uniqueness

`gap_guides_not_unique`. REL36.23 rebuilt one guide per counted gap with unique first-200-char bodies. Uniqueness is a string-hash of markdown, not an identity on a `GapGuide` object.

### 6.6 KPI guide count mismatch

`kpis_per_guide_count_mismatch` (REL36.23.2 DT: 8 guides vs 11 rows). Guides are harvested from headings after rows are merged/inserted. They are not generated from the counted row set.

### 6.7 KPI main header count

`kpi_main_header_count_invalid n/1` and `kpis_main_table_header_count_invalid=0`.  
Loose `_KPI_MAIN_TABLE_HEADER_RE` counted formula/source tables as main (`المؤشر` alternate). REL36.23.2 switched the **gate** to an 8-role full-schema counter and over-corrected: valid Arabic headers with `المصدر` (and Global gap KPI tables) became 0/1. Two full main tables still fail, as intended, but one typed object would have made both bugs impossible.

### 6.8 Formula/source table misclassification

Allowed appendix `| # | المؤشر | صيغة الاحتساب | مصدر البيانات |` shares tokens with the main table. REL32 compiler already emits this appendix (`KpiFormulaRow`). Gates and rebuild Step 1 treat it as another markdown table.

### 6.9 Split Arabic token persistence

`المست فيد` / `المست فيدين` vs `المستفيد` / `المستفيدين`. REL36.23 / 23.1 normalized helper/copy and five sections. Live save/preview/export still persisted splits on `a75df55`. REL36.23.2 widened mutation to save/input/canonical/preview/export, then failed save on a different gate before that could be proven live.

### 6.10 Post-save / export evidence mismatch

Preview, DOCX XML, PDF extract, and `/api/strategy/latest` do not share one artifact. REL36.1–5 / 11 were English Cyber export-evidence repairs. REL36.23.1 helper-on-copy vs saved latest is the same class: the path that is gated is not the path that is stored or exported.

## 7. Root architectural reason

**LLM output + markdown repair layers + section splitters + preview render + canonical artifact + DOCX/PDF extractors do not share one deterministic document model.**

There is already a typed REL32 model (`CanonicalStrategyDocument`, `KpiRow`, `RoadmapRow`, `GapRow`, registries in `rel32_registries.py`) and a compiler (`rel32_compiler.py`). That compiler is not the live authority:

1. The LLM still emits structural markdown tables.
2. `canonical_document._legacy_to_canonical_sections` compiles, then immediately returns **legacy markdown strings**.
3. REL36.7–23.2 re-parse those strings with overlapping regexes and re-write them.
4. Save gates count headers/rows/guides from the repaired markdown.
5. Preview (`grc-markdown.js`, `rel32-preview-table-schema.js`) parses HTML tables independently.
6. DOCX/PDF writers wrap lines (Arabic tokens split visually) and extractors re-parse bytes.
7. Framework selection is recovered from body text as well as request metadata.

Each hotfix taught one detector to see one string. The next writer (compiler, formula appendix, freeze, persist, export) produced a different string. REL36.23.2 is the limit of that approach: tightening the KPI header detector globally broke Cyber/Data/AI/Global, and merging DT rows without typed guides broke DT.

## 8. Recommendation

1. **Stop the REL36 hotfix chain.** Do not implement REL36.24.
2. **Do not merge PR #128.** Keep it open as evidence.
3. **Do not deploy production.** Leave `ec779cc` / `autoDeploy=no`.
4. **Move to REL37:** deterministic compilers for Data / AI / DT strategy documents, then re-run bilingual QA.
5. Treat REL32 typed rows and registries as the seed, not another markdown repair.

## 9. What this closeout does not do

- No code change, no REL36.24, no QA Harness, no production hook, no `autoDeploy` change, no force push, no merge, no close of PR #128.
- `qa_outputs/` and `static/fonts/Amiri-Regular.ttf` remain untracked.
