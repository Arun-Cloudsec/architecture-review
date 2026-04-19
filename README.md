# ATLAS — Cloud Architecture Review Agent (v2.1)

An AI-powered cyber-security review platform with **four specialised agents**, an **18-baseline compliance library** covering UAE, GCC, Asia-Pacific and international frameworks, **in-product agent briefing cards**, and **data-residency controls for regulated environments** (banks, insurance, healthcare, public sector).

Describe a system — or upload designs, diagrams, IaC, or code — and ATLAS produces findings, threat models, compliance gap analysis, or a board-ready risk register, with full cross-mapping against 18 control catalogues and downloadable PDF / PPTX reports.

---

## What's new in v2.1

**Three new regulatory baselines** bring the library from 15 to 18 and introduce a new **Asia-Pacific** family:

| Baseline | Authority | Jurisdiction | Controls |
|---|---|---|---|
| **HKMA CFI** | Hong Kong Monetary Authority | Hong Kong (APAC) | 23 |
| **MAS TRM** | Monetary Authority of Singapore | Singapore (APAC) | 23 |
| **SWIFT CSP** | SWIFT | International | 32 |

- **HKMA Cybersecurity Fortification Initiative** (CFI 2.0 + TM-E-1 technology-risk + TM-G-1 IT-supervisory modules), with HKMA's mandatory 24-hour breach-notification clause wired as a first-class canonical theme.
- **MAS Technology Risk Management Guidelines** (TRM 2021 + Notice 655 cyber hygiene + Notice 644 outsourcing), including MAS's 1-hour incident-notification obligation.
- **SWIFT Customer Security Programme** (CSCF v2024) — mandatory + advisory controls for every institution on the SWIFT network.

The baseline browser now groups the library into **four families** (UAE · GCC · Asia-Pacific · International) and the cross-mapping matrix is **70 × 18**.

**In-product briefing cards on every agent.** Each of the four agents (Review · Threat · Baseline · Risk) now opens with a collapsible *"About this agent · How it works"* card explaining what the agent does, when to use it, and a numbered step-by-step walkthrough. Cards are open by default on first visit, toggle `Hide` / `Show`, and animate cleanly. This replaces the previous "empty canvas" first-run experience.

**Refreshed canonical-theme library.** New themes covering Asia-Pacific and payments-network requirements (e.g. `PRIV_BREACH_NOTIFY` for regulator-specific incident-reporting windows; `HR_SCREENING` for personnel vetting; expanded `CLOUD_*` themes for outsourcing/cloud arrangements).

Everything from v2.0 — 4 agents, theme-keyed cross-mapping, data-residency controls, PII redaction, server-side PDF/PPTX export — is unchanged and fully compatible.

---

## The four agents

| Agent | Purpose | Output |
|---|---|---|
| **Review**   | Cross-domain architecture review (infra / security / app / AI-ML) | Findings with control refs |
| **Threat**   | STRIDE threat model with MITRE ATT&CK for Cloud mapping          | Threats tied to components + techniques |
| **Baseline** | Compliance posture against a specific baseline                   | Gap findings mapped to baseline clauses |
| **Risk**     | Business risk register for the ERC                               | Risks with inherent × residual scoring |

Every finding is tagged with one or more **canonical theme keys** (e.g. `IAM_MFA`, `DATA_ENCRYPT_REST`, `PRIV_BREACH_NOTIFY`) injected into every LLM system prompt — which is what makes the gap analysis and cross-mapping real rather than keyword-matched.

---

## The 18-baseline compliance library

### UAE (4)
UAE Information Assurance Standards · NESA (ADSIC) · CBUAE Information Security · DESC ISR (Dubai)

### GCC (3)
NCA Essential Cybersecurity Controls (Saudi Arabia) · SAMA Cyber Security Framework · CBB Rulebook Volume 6 (Bahrain)

### Asia-Pacific (2)  — *new in v2.1*
HKMA Cybersecurity Fortification Initiative · MAS Technology Risk Management Guidelines

### International (9)
CIS Controls v8 · NIST CSF 2.0 · NIST SP 800-53r5 · PCI-DSS v4.0 · ISO 27001:2022 · ISO 27002:2022 · HIPAA Security Rule · SOC 2 TSC · SWIFT Customer Security Programme *(new in v2.1)*

**Totals: 18 baselines · 70 canonical themes · 401 mapped controls.**

---

## Server-side report generation

- Executive PDF (CISO-facing)
- Technical PDF (full findings + gap analysis + remediation roadmap)
- Professional PowerPoint deck (PPTX)
- Raw JSON export

AEGIS-style 4-workspace UI with control library browser, cross-mapping matrix, and live gap analysis.

---

## Data-residency controls

The v1.0 agent sent data to `api.anthropic.com`. That's a non-starter for most banks under CBUAE, SAMA, HKMA, MAS, RBI or similar regulation. ATLAS supports **three deployment modes** — pick the one that matches your risk appetite:

### 1. `anthropic_direct` (default — development only)
Calls Anthropic's public API. Simple, but traffic leaves your region. **Not suitable for production banking use.**

### 2. `aws_bedrock` (recommended for most banks)
Calls **Claude via AWS Bedrock** in your chosen region. Zero egress outside your tenant. No call ever reaches `anthropic.com`. Available in `me-central-1` (UAE), `eu-*`, `ap-south-1` (Mumbai), `ap-southeast-1` (Singapore), `ap-east-1` (Hong Kong), `us-*`.

### 3. `azure_openai` (for Azure-first banks)
Calls **GPT-4o via Azure OpenAI** in your chosen region (`uaenorth`, `westeurope`, `southeastasia`, etc.). Model hosted by Microsoft in your region; no cross-border data flow.

**Plus** a **PII redaction layer** strips Emirates ID, IBAN, credit cards, SSNs, passports, AWS keys, JWTs, PEM keys, internal IPs and more before any LLM call — 14 pattern types total.

The top-right **provider chip** and sidebar **status tile** show the current provider, region, and PII-redaction state live. The chip turns amber when your current configuration means traffic is leaving your region.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  public/index.html     ← AEGIS-style UI (1,449 lines)          │
│  ├─ Dashboard                                                  │
│  ├─ Briefing cards    · Review · Threat · Baseline · Risk      │
│  ├─ 4 agent workspaces                                         │
│  └─ Cross-map matrix (70 × 18) · Baseline browser · Gap view   │
└───────────────┬────────────────────────────────────────────────┘
                │  REST (fetch + FormData)
┌───────────────▼────────────────────────────────────────────────┐
│  server.js             ← Express app (806 lines)               │
│  ├─ /api/review               ← shared by 4 agents             │
│  ├─ /api/export/{pdf-exec,pdf-tech,pptx,json}/:id              │
│  ├─ /api/baselines · /api/baseline/:id                         │
│  ├─ /api/themes · /api/theme/:key · /api/crossmap              │
│  ├─ /api/gap-analysis                                          │
│  └─ /api/health                                                │
│                                                                │
│  PII redaction → LLM invocation → JSON parse → in-memory cache │
│  (review_id TTL 1h, max 100 cached — exports skip the LLM)     │
└───────────────┬────────────────────────────────────────────────┘
                │
        ┌───────┴─────────┬─────────────────┐
        ▼                 ▼                 ▼
  lib/controls.js    lib/reports.js    LLM provider
  18 baselines       PDF Exec          ├─ Anthropic API
  70 themes          PDF Technical     ├─ AWS Bedrock
  401 controls       PPTX deck         └─ Azure OpenAI
  cross-map (70×18)  pdfkit + pptxgenjs
  gap analysis
```

---

## Setup

```bash
# 1. Install
npm install

# 2. Configure provider
cp .env.example .env
# Edit .env — set LLM_PROVIDER and the matching credentials

# 3. Run
npm start
# ATLAS is at http://localhost:3000
```

### `.env` quick reference

```ini
# Pick ONE: anthropic_direct | aws_bedrock | azure_openai
LLM_PROVIDER=aws_bedrock

# For aws_bedrock (uses standard AWS credentials chain)
AWS_REGION=me-central-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# For anthropic_direct
# ANTHROPIC_API_KEY=sk-ant-...
# ANTHROPIC_MODEL=claude-opus-4-7

# For azure_openai
# AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
# AZURE_OPENAI_API_KEY=...
# AZURE_OPENAI_DEPLOYMENT=gpt-4o

# Data-sovereignty labels shown in the UI
DATA_REGION=UAE
DATA_SOVEREIGNTY_NOTE=Primary region me-central-1; no cross-border egress.

# PII redaction layer (strongly recommended ON)
PII_REDACTION=true
```

---

## Using the UI

### Briefing cards (new in v2.1)

The first thing you see on every agent workspace is an **About this agent · How it works** card. Each one has two columns:

- **What this agent does** — plain-language description of the agent's purpose, what outputs it produces, and the kinds of work it's best suited for (regulator submissions, CAB submissions, ERC packs, etc.).
- **Step-by-step** — a numbered walkthrough of the typical workflow, from inputs through running the agent to exporting results.

Cards are open by default. Click the header (or the `Hide` / `Show` label) to toggle. State is per-card and per-session. If you're training a new team member, leave them open; if you're demoing, collapse them for a cleaner stage.

### Review (Agent A)
Drop in a system description and any supporting artefacts (Terraform, YAML, PDF, diagrams). The agent returns findings across four domains with control references from NIST, CIS, CBUAE, OWASP LLM and others. Export as Executive PDF (for the CISO), Technical PDF (for engineering), or PPTX (for the steering committee).

### Threat (Agent B)
Describe a system's components and data flows. The agent decomposes it, applies STRIDE to each component, and maps each threat to a MITRE ATT&CK for Cloud technique ID. Good for design-phase reviews before a change hits production.

### Baseline (Agent C)
Two modes:

1. **Browse** — pick any of the 18 baselines; see the full control catalogue with the canonical themes each control addresses. The left panel now groups into four sections: *United Arab Emirates · GCC Region · Asia-Pacific · International*.
2. **Gap analysis** — after running a Review/Threat/Risk assessment, pick a baseline and hit *Gap Analysis from Last Review*. You get coverage %, covered / at-risk / not-assessed tallies, and a per-control status table tying each finding back to the baseline's own clause IDs.

A single review can be gap-analysed against multiple baselines in sequence — useful when a platform has to satisfy, say, CBUAE *and* SAMA *and* HKMA *and* SWIFT CSP all at once.

### Risk (Agent D)
Translates technical findings into business-risk language with 5×5 likelihood-impact scoring, inherent vs residual scores, and treatment recommendations (avoid / transfer / mitigate / accept). Suitable output for an Executive Risk Committee.

### Cross-map
A **70 × 18 matrix** showing which baselines address which canonical themes. Useful for showing the board that a single finding about, say, MFA impacts all 18 regulatory frameworks simultaneously — CBUAE, SAMA, HKMA, MAS, NIST 800-53, PCI-DSS, SWIFT CSP and the rest.

---

## Extending the control library

The library is intentionally curated to the most-cited controls per baseline (about 15–30 per baseline; ~22 average). To add or extend:

```javascript
// lib/controls.js
BASELINES.MY_BASELINE = {
  id: 'MY_BASELINE',
  name: 'My Custom Baseline',
  short: 'MyBL',
  jurisdiction: 'Internal',
  authority: 'Group CISO',
  family: 'international',   // 'uae' | 'gcc' | 'apac' | 'international'
  version: '1.0',
  description: '…',
  controls: [
    C('M-1', 'Some Control',
      ['IAM_MFA', 'IAM_PRIV_ACCESS']),   // use existing theme keys
    // …
  ],
};
```

As long as each control's `theme_keys` uses keys already in `THEMES`, cross-mapping and gap analysis pick them up automatically with no server changes. New themes go in `THEMES` — the UI auto-discovers both.

The Baseline browser UI (`public/index.html`) reads `family` and auto-groups new baselines into the correct section. Adding a `family: 'apac'` baseline makes it appear in the Asia-Pacific group automatically; adding a family the UI doesn't know yet (e.g. `'africa'`) requires a one-line addition to `renderBaselineList()`.

---

## API reference

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/health` | Provider, region, PII status, control counts, version |
| POST | `/api/review` | Run a workflow. `multipart/form-data` with `workflow`, `system_name`, `description`, `files[]`, optional `baseline` |
| GET  | `/api/baselines` | List all 18 baselines |
| GET  | `/api/baseline/:id` | Full baseline with controls enriched by theme metadata |
| GET  | `/api/themes` | All 70 canonical themes |
| GET  | `/api/theme/:key` | Theme + every baseline+control that addresses it |
| GET  | `/api/crossmap` | Full 70 × 18 cross-mapping matrix |
| POST | `/api/gap-analysis` | `{ review_id, baseline_id }` or `{ findings, baseline_id }` |
| GET  | `/api/export/pdf-exec/:review_id` | Executive PDF |
| GET  | `/api/export/pdf-tech/:review_id?baseline=HKMA` | Technical PDF with gap analysis |
| GET  | `/api/export/pptx/:review_id` | PowerPoint deck |
| GET  | `/api/export/json/:review_id` | Raw JSON |

Reviews are cached in memory for 1 hour (up to 100 reviews). Export endpoints pull from that cache so they don't re-invoke the LLM.

---

## Deploying to Railway

ATLAS is ready for one-click deployment to Railway (`railway.com`) — the repo ships with `railway.json` (healthcheck + restart policy) and `.nvmrc` (Node 20) so Nixpacks picks the right builder automatically.

**1. Push to GitHub.** Create a new repo, push the folder contents (top-level, not nested).

**2. Create a Railway project.** *New Project → Deploy from GitHub repo →* pick your ATLAS repo. Railway auto-detects Node.js, runs `npm install`, and starts with `npm start`.

**3. Set environment variables** in the Railway service's *Variables* tab. At minimum:

```ini
LLM_PROVIDER=anthropic_direct
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-7
PII_REDACTION=true
DATA_REGION=Railway
DATA_SOVEREIGNTY_NOTE=Hosted on Railway; provider traffic routes to Anthropic API.
```

For `aws_bedrock` or `azure_openai`, swap in the corresponding block from `.env.example`. **Do not** set `PORT` — Railway assigns it automatically and `server.js` reads `process.env.PORT`.

**4. Generate a public domain** under *Settings → Networking → Generate Domain*. Railway routes `https://<your-app>.up.railway.app` → the container's `PORT`. The `/api/health` endpoint is used as the deploy healthcheck.

**Deployment notes:**

- **Ephemeral filesystem.** Railway's default filesystem resets on every deploy. Uploaded files in `uploads/` and the in-memory review cache do not survive restarts — which is fine for this portfolio build (reviews are designed to be short-lived; exports happen immediately after the review completes). For persistence, attach a Railway Volume to `/app/uploads` and swap the in-memory cache for Postgres/Redis.
- **Secrets.** Never commit `.env` — `.gitignore` excludes it. Use Railway's Variables tab exclusively.
- **Region.** Railway lets you pick the region per-service (*Settings → Region*). Match it to your `DATA_REGION` value. Note that `anthropic_direct` still egresses to the US regardless of container region — use `aws_bedrock` for true in-region processing.
- **Build time.** First deploy takes ~2-3 minutes (full `npm install`); subsequent deploys are ~30-60 seconds thanks to cached layers.

---

## Out of scope for this portfolio build

- **Authentication & multi-tenancy** — single-user by design. For production, put it behind SSO and partition review data per tenant.
- **Audit persistence** — reviews live in memory only. Wire to Postgres/DynamoDB to retain audit trail across restarts.
- **Role-based access** — all users see all features.
- **Prompt moderation** — the agents trust the input after PII redaction; for customer-facing deployments, add content filtering.

These are all linear extensions of the existing shape, not redesigns.

---

## Credits

Design language borrows liberally from the AEGIS Platform mockup. Typography: Instrument Serif (display italics) + IBM Plex Sans (body) + IBM Plex Mono (metadata). Colour palette tuned for readable severity contrast on dark backgrounds.

Built with: Express, Anthropic SDK, AWS Bedrock SDK, OpenAI SDK (Azure), Multer, pdf-parse, Mammoth, PDFKit, PptxGenJS.
