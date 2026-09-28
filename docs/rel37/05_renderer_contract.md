# REL37 Renderer contract

All targets consume the same `CanonicalDocument`. They do not parse LLM markdown for structure.

## 1. Interface

```text
render(model: CanonicalDocument, target: md | html | docx | pdf | txt | print) -> Rendered
  body: bytes | str
  content_hash: sha256
  evidence: EvidenceProjection
```

`EvidenceProjection` is the compare object for export evidence:

- SO header line (canonical for `lang`)
- KPI main header line
- formula/source header line if the object exists
- `kpis.row_count`, `kpi_guides.row_count`, `gaps.row_count`, `gap_guides.row_count`
- roadmap families in order
- `org_name` exact
- leakage hits (must be empty)
- `model_hash`

`render(model, t).evidence.model_hash == model.meta.model_hash` for every target.

## 2. Header emission (no aliases in the live path)

English SO: `| # | Strategic Objective | Measurable Target | Rationale | Timeframe |`  
Arabic SO: `| # | الهدف الاستراتيجي | المستهدف القابل للقياس | المبرر | الإطار الزمني |`

English KPI main: `| # | KPI Description | Type | Target Value | Calculation Formula | Source | Frequency | Owner |`  
Arabic KPI main: `| # | وصف المؤشر | النوع | القيمة المستهدفة | صيغة الاحتساب | المصدر | التكرار | المالك |`

English formula/source: `| # | KPI | Calculation Formula | Data Source |`  
Arabic formula/source: `| # | المؤشر | صيغة الاحتساب | مصدر البيانات |`

English guide: `| Step | Action | Owner | Timeline | Output |`  
Arabic guide: `| الخطوة | الإجراء | المسؤول | الإطار الزمني | الناتج |`

English roadmap: `| Phase | Period | Initiative | Owner | Expected Deliverable | Linked Framework |`  
Arabic roadmap: `| المرحلة | الفترة | المبادرة | المسؤول | المخرج المتوقع | الإطار المرتبط |`

## 3. Target-specific rules

| Target | Rule |
|---|---|
| `md` | Tables from objects; prose blocks as paragraphs. Used as `content` field only as a render. |
| `html` / preview | Server-built HTML or JSON tables for `grc-markdown.js`. Preview JS must not invent schemas. Cache-bust `?v=<commit>`. No red header-mismatch banner when model headers match. |
| `docx` | Writer receives complete Unicode cells. Wrapping must not persist split tokens. Extractor NFC-normalizes and joins wrap-only breaks before evidence compare. |
| `pdf` | Same evidence projection as DOCX. |
| `txt` / `print` | Same headers and row order as `md`. |

## 4. Language parity at render

- Structural labels = `model.meta.lang` schema.
- Generated prose language = `model.meta.lang`.
- `org_name` is copied verbatim (Arabic allowed in English documents).
- English documents: no Arabic table headers; no Arabic generated prose.
- Arabic documents: English only as approved acronyms / framework labels (`NDMO`, `PDPL`, `SDAIA`, `DGA`, `API`).

## 5. What renderers must not do

- Count formula/source as a KPI main table.
- Append a second SO or KPI main table.
- Re-run REL36 markdown mutators.
- Infer frameworks from rendered text.
- Drop `org_name` during English sanitization.

## 6. Preview / export identity

Phase 1 tests compute `model_hash` and require:

```text
hash(render(md).evidence) == hash(render(html).evidence)
    == hash(render(docx).evidence) == hash(render(pdf).evidence)
```

Bytes differ; the **evidence projection** must not.
