# Mizan GRC — AI-Powered Governance, Risk & Compliance Platform

A bilingual (English / Arabic, RTL-compliant) enterprise GRC platform that generates Big4-grade strategy documents, policies, audit reports, and risk analyses using multiple AI providers.

---

## Features

| Capability | Detail |
|---|---|
| **6 GRC Domains** | Cyber Security, Data Management, Artificial Intelligence, Digital Transformation, Global Standards, IT Governance |
| **4 Document Types** | Technical Strategy, Policy/Procedure, Audit Report, Risk Analysis |
| **Bilingual** | Full English and Arabic generation with RTL rendering |
| **Multi-AI** | Anthropic Claude (primary), OpenAI GPT-4, Google Gemini, Groq/Llama — auto-selected |
| **Async Generation** | All document types use non-blocking async generation with live progress and polling |
| **Export** | DOCX and PDF export for all document types |
| **Advisory Modes** | Drafting, Consulting, Assurance — controls review depth and traceability |
| **Quality Gates** | Document-type-aware structural validation, publishability scoring (0–100), state machine (draft → reviewed → publishable → final) |
| **Org Memory** | Per-domain organisation context (risk appetite, governance model, approved roles) reused across generation |
| **Traceability** | Per-artifact evidence chain, framework mapping, assumption logs |
| **Review Engine** | AI-powered quality review with section-level findings and recommendation |
| **Handoff Packs** | Structured consultant handoff documents including evidence gaps and assumptions |
| **Risk Register** | Persistent risk register with auto-population from risk analyses |
| **Admin Panel** | Usage analytics, user management, audit logs |

---

## Quick Start (Local)

```bash
git clone <repo>
cd mizan-grc-v2
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env — add at least one AI provider key

python app.py
```

Open `http://localhost:5000`

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | Yes | Flask session secret — auto-generated on Render |
| `ANTHROPIC_API_KEY` | Recommended | Claude API key — primary AI provider |
| `OPENAI_API_KEY` | Optional | OpenAI GPT-4 fallback |
| `GOOGLE_API_KEY` | Optional | Google Gemini fallback |
| `GROQ_API_KEY` | Optional | Groq / Llama fallback |
| `AI_PROVIDER` | Optional | Force provider: `anthropic`, `openai`, `google`, `groq`, or `auto` (default) |
| `FLASK_ENV` | Optional | `production` (default on Render) or `development` |
| `DATABASE_PATH` | Optional | SQLite path override (default: `./mizan.db`) |

At least one AI provider key must be set. The platform auto-selects the best available provider when `AI_PROVIDER=auto`.

---

## Deployment on Render

1. Fork this repository
2. Create a new **Web Service** on [Render](https://render.com) pointed at the repo
3. Render will auto-detect `render.yaml` — no manual config required
4. Set secret env vars in the Render dashboard:
   - `ANTHROPIC_API_KEY` *(recommended primary)*
   - `OPENAI_API_KEY`, `GOOGLE_API_KEY`, `GROQ_API_KEY` *(optional fallbacks)*
5. Deploy

The build command installs Arabic font packages (`fonts-noto-core`, `fonts-noto-extra`) required for bilingual PDF export.

---

## Architecture

```
app.py                    Flask application (~27k lines)
  ├── Async task layer    ThreadPoolExecutor (5 workers) + SQLite background_tasks table
  ├── Generation routes   /api/generate-*-async  →  worker thread  →  DB save  →  /api/*-status/<id>
  ├── Recovery routes     /api/*/latest?domain=  (fallback when task record is gone)
  ├── Export routes       /api/generate-docx-async, /api/generate-pdf-async
  ├── Review routes       /api/review-*, /api/validate-document
  ├── Traceability        /api/traceability/*, /api/evidence-gaps/*
  └── Admin / Analytics   /admin/*, /analytics

templates/
  ├── domain.html         Main generation UI (strategy, policy, audit, risk tabs)
  ├── history.html        Saved documents browser
  ├── dashboard.html      User dashboard
  └── base.html           Shared layout

static/js/
  ├── strategy-renderer.js   Section-aware strategy preview renderer
  ├── grc-markdown.js        GRC-specific markdown → HTML converter
  └── main.js                Shared UI helpers

static/css/main.css       Platform styles (RTL-aware, schema-scoped table widths)
```

### Async Generation Contract

All long-running document types follow the same contract:

```
POST /api/generate-{type}-async   →  { task_id }
GET  /api/{type}-status/<task_id> →  { status: pending|done|error, result: {...} }
GET  /api/{type}/latest?domain=   →  recovery: most recent saved artifact for domain
```

On completion, `result` always includes:
- `{type}_id` — the persisted DB artifact ID
- `content` / `analysis` — the generated text
- `artifact_status` — `reviewed` or `draft`
- `publishability_score` — 0–100

---

## Document State Machine

```
draft  →  reviewed  →  publishable  →  final
  ↑           ↓              ↓
rejected / requires_consultant / requires_evidence
```

- **reviewed**: structural validation passed
- **publishable**: review score ≥ 60%
- **final**: review score ≥ 70% (export-gated)

---

## System Requirements

- Python 3.11+
- SQLite (bundled)
- `reportlab`, `arabic-reshaper`, `python-bidi` — Arabic PDF
- `python-docx` — DOCX export
- `PyMuPDF` or `PyPDF2` — PDF evidence upload parsing
- Font packages: `fonts-noto-core`, `fonts-noto-extra` (Linux/Render)

---

## Created By

**Eng. Mohammad Abbas Alsaadon**  
Lead Full-Stack Engineer & GRC Architect, Mizan Platform
