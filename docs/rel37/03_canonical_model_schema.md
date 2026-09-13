# REL37 CanonicalDocument model schema

`schema_version`: `rel37.strategy.v1`

## 1. Root object

```text
CanonicalDocument
  meta:
    schema_version          "rel37.strategy.v1"
    document_type           "strategy"
    domain                  "data" | "ai" | "dt"     # Phase 1
    lang                    "ar" | "en"
    selected_frameworks[]   from request only
    org_name                exact Unicode
    task_id / strategy_id
    model_hash              SHA-256 of canonical JSON (stable key order)
    prose_hash              SHA-256 of narrative fields only
  prose:
    vision
    environment_narrative
    other narrative blocks allowed by schema
  tables:
    strategic_objectives    TypedTable[SORow]            # exactly one
    pillars                 TypedTable[PillarRow]
    pillar_initiatives      TypedTable[PillarInitiativeRow]
    gaps                    TypedTable[GapRow]
    gap_guides              TypedTable[GapGuide]         # 1:1 gaps
    kpis                    TypedTable[KpiRow]           # exactly one main table
    kpi_formula_source      TypedTable[KpiFormulaRow]    # zero or one
    kpi_guides              TypedTable[KpiGuide]         # 1:1 kpis
    roadmap                 TypedTable[RoadmapRow]
    confidence              TypedTable[ConfidenceRow]    # if schema includes
    traceability            TypedTable[TraceabilityRow]  # if schema includes
  coverage:
    required_families[]
    satisfied_families[]
    missing_families[]      # must be empty to save
  validation:
    passed: bool
    blockers: []
  render:
    targets: [md, html, docx, pdf, txt, print]
    last_render_hash: {target: hash}
```

`selected_frameworks` is copied from the request. Compilers and scanners must not invent frameworks from body text.

## 2. Typed tables

### 2.1 Strategic Objectives — `SORow`

| Role | English header | Arabic header |
|---|---|---|
| index | `#` | `#` |
| objective | `Strategic Objective` | `الهدف الاستراتيجي` |
| target | `Measurable Target` | `المستهدف القابل للقياس` |
| rationale | `Rationale` | `المبرر` |
| timeframe | `Timeframe` | `الإطار الزمني` |

Exactly one SO table object. First-table coverage rows for selected frameworks are compiler-inserted `SORow`s with `family` set (`ndmo_compliance`, `pdpl_compliance`, `sdaia_compliance`, …).

### 2.2 Strategic Pillars — `PillarRow` + `PillarInitiativeRow`

Pillar heading + one or more initiatives (`initiative`, `description`, `output`, `owner`, `pillar_family`). Owners come from the domain allow-list.

### 2.3 Gap Assessment — `GapRow`

`number`, `gap_label`, `description`, `priority`, `status`, `family`, `framework`.

### 2.4 Gap Implementation Guides — `GapGuide`

One object per `GapRow`. Heading template is schema-owned:

- EN: `#### Gap #{n} Implementation Guide`
- AR: `#### دليل تنفيذ الفجوة رقم {n}`

Guide **steps** use:

| Role | English | Arabic |
|---|---|---|
| step | `Step` | `الخطوة` |
| action | `Action` | `الإجراء` |
| owner | `Owner` | `المسؤول` |
| timeline | `Timeline` | `الإطار الزمني` |
| output | `Output` | `الناتج` |

`len(gap_guides) == len(gaps)` by construction.

### 2.5 KPI Main Table — `KpiRow`

Exactly **one** table object. Distinct type from formula/source.

| Role | English header | Arabic header |
|---|---|---|
| index | `#` | `#` |
| description | `KPI Description` | `وصف المؤشر` |
| type | `Type` | `النوع` |
| target | `Target Value` | `القيمة المستهدفة` |
| formula | `Calculation Formula` | `صيغة الاحتساب` |
| source | `Source` | `المصدر` |
| frequency | `Frequency` | `التكرار` |
| owner | `Owner` | `المالك` |

Arabic **source** label is `المصدر` in the schema. The model does not parse aliases. Legacy import (old saved artifacts) may map `مصدر` → source role in an adapter only.

### 2.6 KPI Formula/Source Table — `KpiFormulaRow`

Zero or one table object. **Never** counted as KPI main.

| Role | English header | Arabic header |
|---|---|---|
| index | `#` | `#` |
| kpi | `KPI` | `المؤشر` |
| formula | `Calculation Formula` | `صيغة الاحتساب` |
| data_source | `Data Source` | `مصدر البيانات` |

### 2.7 KPI Assessment Guides — `KpiGuide`

One object per `KpiRow`. Same 5-column guide schema as gap guides.  
`len(kpi_guides) == len(kpis)` by construction.

### 2.8 Roadmap — `RoadmapRow`

| Role | English header | Arabic header |
|---|---|---|
| phase | `Phase` | `المرحلة` |
| period | `Period` | `الفترة` |
| initiative | `Initiative` | `المبادرة` |
| owner | `Owner` | `المسؤول` |
| deliverable | `Expected Deliverable` | `المخرج المتوقع` |
| framework | `Linked Framework` | `الإطار المرتبط` |

`family` is a registry enum. Duplicate or restarted families are compile errors.

### 2.9 Confidence / CSF and Traceability

Included when the domain schema says so. Cyber Phase 1 uses `main`’s existing path; Data/AI/DT include traceability if the Phase 1 compiler emits it from the registry (default: include a minimal traceability table linking initiatives → gaps → KPIs).

## 3. Hard model rules (save blockers if false)

1. Exactly one KPI main table object; `kpis.rows >= 1`.
2. Zero or one KPI formula/source table object.
3. Formula/source type ≠ KPI main type; evidence counters must use type, not header regex.
4. `len(kpi_guides) == len(kpis.rows)`.
5. `len(gap_guides) == len(gaps.rows)`.
6. All `coverage.required_families` are satisfied.
7. All required roadmap families present; no duplicate; no restart.
8. Structural labels match `lang`.
9. `org_name` stored exactly; English render must contain it if the user entered Arabic.
10. No wrong-language generated prose (org_name exempt).
11. No domain leakage terms unless that framework was selected.
12. `selected_frameworks` equals the request list.
13. After validate, renderers must not rewrite table membership.

## 4. Persistence

Phase 1 tests persist model JSON in memory.  
Phase 2 persist: `sections_json` holds a lossless projection (`{"rel37_model": {...}, "legacy_markdown": <render md>}`) so old export readers still see markdown while gates use the model.

Old saved artifacts without `rel37_model` use a **legacy import adapter** (plan only in Phase 1 tests group 17).
