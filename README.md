# Mizan GRC - Governance, Risk & Compliance Platform

A bilingual (English/Arabic) Flask web application for generating cybersecurity strategies, policies, audit reports, and risk analyses.

## Features

- 🔐 **5 GRC Domains**: Cyber Security, Data Management, IT Governance, Business Continuity, AI Governance
- 📄 **4 Document Types**: Strategy, Policy, Audit Report, Risk Analysis
- 🌐 **Bilingual Support**: English & Arabic with RTL support
- 📊 **AI-Powered**: Uses OpenAI GPT for intelligent document generation
- 📥 **Export Options**: Download as Word (.docx) or Text (.txt)
- 🏛️ **NCA Frameworks**: Supports ECC, DCC, CSCC, TCC, CCC

## Deployment on Render

1. Fork this repository
2. Connect to Render.com
3. Add environment variable: `OPENAI_API_KEY`
4. Deploy!

## Local Development

```bash
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

## Environment Variables

- `OPENAI_API_KEY` - Your OpenAI API key (required)
- `SECRET_KEY` - Flask secret key (auto-generated on Render)

## Created By

Eng. Mohammad Abbas Alsaadon
