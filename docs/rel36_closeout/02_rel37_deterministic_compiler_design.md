# REL37 Deterministic Document Compiler Architecture

**Status:** Design only. No implementation until approved.  
**Date:** 2026-09-13  
**Depends on:** `01_rel36_forensic_closeout.md`

## 1. Design goals

- One **canonical section model** per generated document.
- One **schema registry** keyed by `(document_type, domain, language, schema_version)`.
- Deterministic **table builders** for:
  - Strategic Objectives
  - Strategic Pillars (heading + initiatives)
  - Gap Assessment
  - Gap Implementation Guides
  - KPIs (main table)
  - KPI formula/source subtable (separate type)
  - KPI Assessment Guides
  - Roadmap
  - Confidence / CSF where the registry says the document type includes it
  - Traceability
- **LLM writes narrative prose only** (vision paragraphs, rationale sentences, guide body prose). It does not emit pipe tables or heading-numbered structural shells.
- Preview, DOCX, PDF, TXT, and Print **all render from the same model**.
- Save gates validate **the model**, not loosely parsed markdown.
- Export evidence validates rendered text/bytes **against the same model**.
- Language parity is enforced **on the model** before any render.
- Domain/framework coverage is enforced from the **registry + request metadata**, not scattered regex repairs.
- KPI main table and formula/source appendix are **distinct typed table objects**.
- Guide counts are **generated from counted rows**, never repaired later.
- Arabic and English schemas are **explicit and versioned**.
- Framework selection comes from **request metadata only**, never from body-text salvage.

## 2. What already exists (reuse, do not rewrite blindly)

REL32 already has:

- Frozen dataclasses in `release_engine_v3/canonical_strategy_document.py` (`StrategicObjectiveRow`, `PillarRow`, `PillarInitiativeRow`, `GapRow`, `RoadmapRow`, `KpiRow`, `KpiFormulaRow`, …).
- Registries in `release_engine_v3/rel32_registries.py` (SO, KPI, roadmap family, gap family, headings).
- `rel32_compiler.compile_canonical_strategy_document`.

REL33 already selects compiler-by-document-type (`rel33_domain_guard.select_rel33_compiler`) and forbids running the strategy compiler on risk.

**The defect is authority, not absence of types.** Today the compiler output is flattened back to markdown; REL36 repairs re-parse that markdown; preview/export parse it again. REL37 makes the typed document the **only** structural authority after generation.

## 3. Canonical model

```text
CanonicalDocument
  meta:
    schema_version          # e.g. rel37.strategy.v1
    document_type           # strategy | risk | gap_assessment
    domain                  # cyber | data | ai | dt | erm | global
    language                # ar | en
    selected_frameworks[]   # from request only
    org_name                # exact Unicode, never sanitized away
    task_id / strategy_id
    hashes:
      model_hash            # hash of typed JSON
      prose_hash            # hash of narrative fields only
  prose:
    vision, executive_summary, environment_narrative, ...
  tables:
    strategic_objectives: TypedTable[SORow]
    pillars: TypedTable[PillarRow]
    pillar_initiatives: TypedTable[PillarInitiativeRow]
    gaps: TypedTable[GapRow]
    gap_guides: TypedTable[GapGuide]      # 1:1 with gaps
    kpis: TypedTable[KpiRow]              # exactly one main table
    kpi_formula_source: TypedTable[KpiFormulaRow]  # 0..1 appendix
    kpi_guides: TypedTable[KpiGuide]      # 1:1 with kpis
    roadmap: TypedTable[RoadmapRow]
    confidence: TypedTable[ConfidenceRow] # if schema includes it
    traceability: TypedTable[TraceabilityRow]
  coverage:
    required_families[]     # from registry ∩ selected_frameworks
    satisfied_families[]
```

Invariants (enforced in the model, then mirrored by gates):

1. `len(kpis) >= 1` and `kpis` is a single table object (not “header count”).
2. `len(kpi_guides) == len(kpis)`.
3. `len(gap_guides) == len(gaps)`.
4. `kpi_formula_source` is never counted as `kpis`.
5. Roadmap `family` is an enum from the registry; duplicate/restart is a model check.
6. Every required coverage family has at least one row in the sections the registry names (pillars / gaps / roadmap / kpis).
7. Language of structural labels is the schema language. Prose language matches. `org_name` is exempt from script stripping.
8. `selected_frameworks` is copied from the request; scanners must not invent frameworks from body text.

## 4. Schema registry

Per `(document_type, domain, language, schema_version)`:

- Section order and required sections.
- Table column roles and display labels (Arabic and English spelled out; no “`مصدر` or `المصدر` maybe”).
- Required coverage families for each selectable framework (NDMO, PDPL, SDAIA, DGA, NCA ECC, NCA DCC, ISO 31000, …).
- Owner-role allow-lists (Data-domain owners vs Cyber-domain owners).
- Leakage deny-lists (NCA/CISO/SIEM on Data/AI Arabic, etc.).
- Guide heading templates (`#### Gap #{n} Implementation Guide` / `#### دليل تنفيذ الفجوة رقم {n}`).
- Minimum countable roadmap rows and family order.

Version the registry. A document records `schema_version`. Gates and renderers load that version. No silent header aliasing in the gate path. Aliases, if any, live only in a **legacy import adapter** for old saved artifacts.

## 5. Generation pipeline (target)

```text
Request metadata
    → framework set, domain, language, org_name, document_type
LLM prose pass
    → narrative fields only (no tables)
Deterministic compilers
    → build every TypedTable from registry + request + prose snippets
CanonicalDocument.assemble()
    → attach guides 1:1 with rows; compute coverage; model_hash
Save gate
    → validate(CanonicalDocument)   # not markdown regex
Persist
    → sections_json = model.to_json()
    → content markdown = model.render("md")   # derived, not source
Preview / DOCX / PDF / TXT / Print
    → model.render(target)
Export evidence
    → extract(target) equals model.expected_evidence()
```

LLM may propose **cell prose** (KPI name wording, gap description) through a constrained JSON schema. It must not propose column sets or extra tables. If the model rejects a cell, the compiler substitutes the registry default for that family.

## 6. Deterministic table builders (Phase 1 domains)

### Data strategy (AR/EN)

- SO table: first counted table includes NDMO and PDPL compliance/alignment objectives when those frameworks are selected.
- Pillars: substantive initiative per counted pillar; Data-domain owners only.
- Gaps + gap guides: one guide object per gap; unique bodies from template + family + framework, not hash-after-the-fact.
- KPIs + KPI guides: families `privacy_governance`, `data_catalog`, `data_lifecycle`, `personal_data_classification`, `consent_management`, `data_subject_rights`, `breach_notification` as required by NDMO/PDPL selection.
- Roadmap: countable rows from the family list; no duplicate/restart by construction.

### AI strategy (AR/EN)

- SO table: SDAIA compliance/alignment objective when SDAIA is selected.
- Gaps/KPI guides complete before save because they are compiled, not “filled if missing”.
- Leakage deny-list from registry (no NCA/CISO/SIEM/SOC/IAM/PAM/MFA/CSIRT/NIST in Arabic AI structural cells).

### DT strategy (AR/EN)

- DGA families `citizen_experience`, `interoperability`, `digital_services` are compiler rows, not post-hoc inserts.
- One `kpis` table. Formula/source appendix is a second object.
- Citizen token is the contiguous registry string `المستفيد` / `المستفيدين`. Split forms are not representable in the model.
- `len(kpi_guides) == len(kpis)` because guides are emitted in the same loop as rows.

### Cyber (Phase 1)

Leave the current REL36.11/main Cyber path in place if needed. Add **regression fixtures** so Data/AI/DT compilers cannot change Cyber output. Phase 2 can move Cyber onto the same compiler once Data/AI/DT are green.

## 7. Render and evidence

One renderer interface:

```text
render(model, target in {md, html, docx, pdf, txt, print})
```

Rules:

- Structural labels come from the schema, never from LLM markdown.
- Arabic shaping/wrapping happens **after** tokens are complete. DOCX/PDF extractors normalize wrap-induced visual splits before evidence compare, but the model never stores `المست فيد`.
- Preview JS does not invent schemas. It receives a JSON table payload (or renders server HTML already built from the model). Cache-bust `?v=<commit>` stays.
- Evidence check: extracted SO header, KPI header, row counts, required family presence, leakage, `org_name` exact match.

Save gates (examples, all model-level):

- `kpis.count == 1` table object
- `kpis.rows >= 1`
- `kpi_guides.rows == kpis.rows`
- `gap_guides.rows == gaps.rows`
- `coverage.missing == []`
- `language.structural == document.language`
- `frameworks == request.frameworks`

Markdown regex gates remain only as a **legacy adapter** for old artifacts until Phase 3 old-saved-export tests pass.

## 8. Phased implementation

### Phase 1 — compilers, production frozen

- Production stays `ec779cc` / `autoDeploy=no`.
- PR #128 stays open and unmerged.
- No REL36.24.
- Implement REL37 compilers + registries for:
  - Data strategy Arabic and English
  - AI strategy Arabic and English
  - DT strategy Arabic and English
- Cyber stays on the current stable path; keep existing Cyber regression tests.
- Unit tests against golden **model JSON**, not markdown snapshots only.

### Phase 2 — cut over repair chain

- For Data/AI/DT strategy, stop calling REL36.19–23.2 markdown mutators on the live save path.
- Persist `sections_json` as the model (or a lossless projection).
- Markdown `content` is a render.
- Golden fixtures: Cyber/Data/AI/DT × Arabic/English (preview HTML + DOCX + PDF extracted text + model JSON).
- Browser preview checks: no Arabic headers on English preview; Arabic headers remain on Arabic preview; no red KPI header-mismatch banner.
- DOCX/PDF extracted-text checks against the model.

### Phase 3 — QA Harness (only after Phase 2 is green)

- 10-attempt cap-neutral generation per critical route (fresh staging QA users).
- Bilingual matrix (Cyber/Data/AI AR+EN, plus English with Arabic `org_name`).
- Old saved-artifact export tests (legacy adapter).
- Browser cache-bust tests (`rel32-preview-table-schema.js?v=…`, `grc-markdown.js?v=…`).
- Concurrency tests.
- Stale CSRF / cross-user export auth tests.
- Production smoke **contract** (read-only assertions). Do not enable production `autoDeploy` as part of REL37.

Do **not** start QA Harness in this closeout.

## 9. Non-goals

- Another REL36.x detector/repair module.
- Weakening `kpi_main_header_count_invalid`, coverage, uniqueness, or leakage gates.
- Merging PR #128 to get “partial credit”.
- Using production as an experiment surface.
