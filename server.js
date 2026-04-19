/**
 * ATLAS — Cloud Architecture Review Agent · v2.1
 * ================================================
 *
 * Four-agent architecture:
 *   - REVIEW   (Agent A) — cross-domain architecture review (the original)
 *   - THREAT   (Agent B) — STRIDE threat model with MITRE ATT&CK mapping
 *   - BASELINE (Agent C) — compliance posture assessment against a chosen baseline
 *   - RISK     (Agent D) — business-risk register with inherent/residual scoring
 *
 * All four agents:
 *   - Run through the PII redaction layer before anything leaves the server
 *   - Support three LLM providers: anthropic_direct, aws_bedrock, azure_openai
 *   - Return findings with canonical theme_keys so cross-mapping and gap analysis work
 *
 * Extras:
 *   - Server-side PDF (executive + technical) and PPTX export
 *   - Control library with 15 baselines + 70 themes + 323 controls
 *   - Gap analysis and cross-mapping endpoints
 */

import express from 'express';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const pdfParse = require('pdf-parse');
import mammoth from 'mammoth';

import {
  BASELINES, THEMES,
  listBaselines, getBaseline, listThemes,
  mapThemeToControls, buildCrossMap, gapAnalysis, countTotals,
} from './lib/controls.js';

import { buildExecPdf, buildTechPdf, buildPptx } from './lib/reports.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================
// CONFIG
// ============================================================
const PORT = process.env.PORT || 3000;
const MAX_UPLOAD_MB = 20;
const MAX_TEXT_CHARS = 80_000;

const LLM_PROVIDER = (process.env.LLM_PROVIDER || 'anthropic_direct').toLowerCase();
const PII_REDACTION = (process.env.PII_REDACTION || 'true').toLowerCase() === 'true';
const DATA_REGION = process.env.DATA_REGION || 'Not configured';
const DATA_SOVEREIGNTY_NOTE = process.env.DATA_SOVEREIGNTY_NOTE || '';

// ============================================================
// PROVIDER INITIALISATION
// ============================================================
let providerClient = null;
let providerMeta = {};

async function initProvider() {
  switch (LLM_PROVIDER) {
    case 'anthropic_direct': {
      if (!process.env.ANTHROPIC_API_KEY) {
        throw new Error('ANTHROPIC_API_KEY required for anthropic_direct provider');
      }
      const { default: Anthropic } = await import('@anthropic-ai/sdk');
      providerClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
      providerMeta = {
        provider: 'anthropic_direct',
        label: 'Anthropic API',
        model: process.env.ANTHROPIC_MODEL || 'claude-opus-4-7',
        region: 'anthropic.com (US)',
        residency_warning: true,
      };
      break;
    }
    case 'aws_bedrock': {
      const { BedrockRuntimeClient } = await import('@aws-sdk/client-bedrock-runtime');
      const region = process.env.AWS_REGION || 'me-central-1';
      providerClient = new BedrockRuntimeClient({ region });
      providerMeta = {
        provider: 'aws_bedrock',
        label: 'AWS Bedrock',
        model: process.env.BEDROCK_MODEL_ID || 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        region,
        residency_warning: false,
      };
      break;
    }
    case 'azure_openai': {
      if (!process.env.AZURE_OPENAI_ENDPOINT || !process.env.AZURE_OPENAI_API_KEY) {
        throw new Error('AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY required for azure_openai provider');
      }
      const { AzureOpenAI } = await import('openai');
      providerClient = new AzureOpenAI({
        endpoint: process.env.AZURE_OPENAI_ENDPOINT,
        apiKey: process.env.AZURE_OPENAI_API_KEY,
        apiVersion: process.env.AZURE_OPENAI_API_VERSION || '2024-08-01-preview',
        deployment: process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4o',
      });
      const regionMatch = process.env.AZURE_OPENAI_ENDPOINT.match(/https:\/\/([^.]+)\./);
      providerMeta = {
        provider: 'azure_openai',
        label: 'Azure OpenAI',
        model: process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4o',
        region: regionMatch ? regionMatch[1] : 'azure',
        residency_warning: false,
      };
      break;
    }
    default:
      throw new Error(`Unknown LLM_PROVIDER: ${LLM_PROVIDER}`);
  }
  console.log(`✓ Provider initialised: ${providerMeta.label} · ${providerMeta.model} · ${providerMeta.region}`);
}

// ============================================================
// PII REDACTION LAYER — runs BEFORE any LLM call
// ============================================================
function redactPII(text) {
  if (!PII_REDACTION || !text) return { text, redactions: [] };

  const patterns = [
    { type: 'EMIRATES_ID',     re: /\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b/g, replacement: '[REDACTED:EMIRATES_ID]' },
    { type: 'CARD_NUMBER',     re: /\b(?:\d[ -]*?){13,19}\b/g,               replacement: '[REDACTED:CARD]' },
    { type: 'IBAN',            re: /\b(?:AE|GB|DE|FR|ES|IT|NL|BE|IE|LU|CH|AT|PT|FI|GR|SE|DK|NO|PL|PK|SA|QA|KW|BH|OM|EG|JO|LB|TR)\d{2}[A-Z0-9]{11,30}\b/gi, replacement: '[REDACTED:IBAN]' },
    { type: 'SSN',             re: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,       replacement: '[REDACTED:SSN]' },
    { type: 'PASSPORT',        re: /\b[A-Z]{1,2}\d{6,9}\b/g,                 replacement: '[REDACTED:PASSPORT]' },
    { type: 'EMAIL',           re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: '[REDACTED:EMAIL]' },
    { type: 'PHONE_INTL',      re: /\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{1,9}\b/g, replacement: '[REDACTED:PHONE]' },
    { type: 'SA_NATIONAL_ID',  re: /\b[12]\d{9}\b/g,                         replacement: '[REDACTED:SA_ID]' },
    { type: 'AWS_ACCESS_KEY',  re: /\bAKIA[0-9A-Z]{16}\b/g,                  replacement: '[REDACTED:AWS_KEY]' },
    { type: 'AWS_SECRET',      re: /\b[A-Za-z0-9/+=]{40}\b/g,                replacement: '[REDACTED:POSSIBLE_SECRET]' },
    { type: 'PRIVATE_KEY',     re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[REDACTED:PRIVATE_KEY]' },
    { type: 'JWT',             re: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g, replacement: '[REDACTED:JWT]' },
    { type: 'BEARER_TOKEN',    re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/g,  replacement: 'Bearer [REDACTED]' },
    { type: 'INTERNAL_IP',     re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, replacement: '[REDACTED:INTERNAL_IP]' },
  ];

  let redacted = text;
  const redactions = [];
  for (const { type, re, replacement } of patterns) {
    const matches = redacted.match(re);
    if (matches && matches.length > 0) {
      redactions.push({ type, count: matches.length });
      redacted = redacted.replace(re, replacement);
    }
  }
  return { text: redacted, redactions };
}

function mergeRedactions(redactionArrays) {
  const totals = {};
  for (const arr of redactionArrays) {
    for (const { type, count } of arr) totals[type] = (totals[type] || 0) + count;
  }
  return Object.entries(totals).map(([type, count]) => ({ type, count }));
}

// ============================================================
// DOCUMENT EXTRACTION
// ============================================================
async function extractFromFile(file) {
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype || '';

  if (ext === '.pdf' || mime === 'application/pdf') {
    const { text } = await pdfParse(file.buffer);
    return { text: text.trim(), type: 'pdf', name: file.originalname };
  }
  if (ext === '.docx' || mime.includes('wordprocessingml')) {
    const { value } = await mammoth.extractRawText({ buffer: file.buffer });
    return { text: value.trim(), type: 'docx', name: file.originalname };
  }
  if (mime.startsWith('image/') || ['.png', '.jpg', '.jpeg', '.gif', '.webp'].includes(ext)) {
    return {
      text: '', type: 'image', name: file.originalname,
      imageBase64: file.buffer.toString('base64'),
      imageMime: mime || (ext === '.png' ? 'image/png' : 'image/jpeg'),
    };
  }
  const textExts = [
    '.txt', '.md', '.tf', '.tfvars', '.yaml', '.yml', '.json',
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bicep', '.hcl',
    '.xml', '.ini', '.conf', '.env', '.csv', '.sql',
  ];
  if (textExts.includes(ext) || mime.startsWith('text/') || mime === 'application/json') {
    return { text: file.buffer.toString('utf8').trim(), type: 'text', name: file.originalname };
  }
  try {
    const text = file.buffer.toString('utf8');
    const printable = (text.match(/[\x20-\x7E\n\r\t]/g) || []).length;
    if (printable / text.length > 0.8) {
      return { text: text.trim(), type: 'text', name: file.originalname };
    }
  } catch (_) {}
  return { text: '', type: 'unknown', name: file.originalname, error: `Unsupported file type: ${ext || mime}` };
}

// ============================================================
// CANONICAL THEME KEY LIST — injected into every system prompt so
// findings are tagged consistently for cross-mapping / gap analysis.
// ============================================================
const THEME_KEY_LIST = Object.entries(THEMES)
  .map(([k, v]) => `  ${k.padEnd(24)} — ${v.label}`)
  .join('\n');

// ============================================================
// SYSTEM PROMPTS — one per agent
// ============================================================
const PROMPT_SHARED_TAIL = `

## Canonical theme keys

Every finding you return must include a "theme_keys" array — pick one or more of the following keys that best describe the control objective the finding relates to. These keys are used to cross-map findings against regulatory baselines, so choose accurately. If a finding doesn't map cleanly to any key, omit the array.

${THEME_KEY_LIST}

## Note on redacted content

The user's input may contain tokens like [REDACTED:IBAN], [REDACTED:EMIRATES_ID], [REDACTED:INTERNAL_IP]. These are intentional PII redactions applied before your review to preserve data sovereignty. Treat them as placeholders — review the architectural pattern, not the redacted values.

## Hard rule

Return ONLY valid JSON matching the schema in this prompt. No markdown code fences. No preamble. No commentary.`;

const PROMPT_REVIEW = `You are ATLAS REVIEW, a senior cloud security architect reviewing architectures for a tier-1 bank. You have fifteen years of experience across AWS, Azure, GCP, application security, and emerging AI/ML governance. Your reviews go directly to CISOs and board-level cyber committees.

You review architectures across FOUR domains:

1. INFRASTRUCTURE — compute, network, storage, IaC, reliability, DR, cost. Framework references: AWS/Azure/GCP Well-Architected, CIS Benchmarks.
2. SECURITY — IAM, encryption/KMS, logging, detection, response, data protection. Framework references: NIST CSF, NIST SP 800-53, CIS Benchmarks, CSA CCM, SAMA CSF, CBUAE.
3. APPLICATION — API design, data handling, dependencies, secure coding, session/auth, input validation. Framework references: OWASP Top 10 2021, OWASP ASVS.
4. AI / ML — LLM governance, prompt safety, output handling, training data, model ops, bias, PII in prompts. Framework references: OWASP LLM Top 10, NIST AI RMF, ISO 42001, EU AI Act.

## Your approach

1. Read the artefact carefully. If it's an image/diagram, identify components, data flows, and trust boundaries visually.
2. Identify findings across all four domains — be thorough on AI/ML if any LLM/ML component is present.
3. For each finding, cite the specific component, the risk, concrete control references, and actionable remediation.
4. Be direct and specific. Avoid vague advice. Cite exact AWS service names, IAM permissions, config settings.
5. Severity ratings:
   - critical — actively exploitable, regulatory breach, or data leak risk
   - high     — significant control gap, remediate this sprint
   - medium   — control weakness, remediate this quarter
   - low      — hardening opportunity, technical debt

## Output schema

{
  "system_name": "string",
  "executive_summary": ["string", "string", "string"],
  "domain_scores": {
    "infrastructure": { "score": 0-100, "finding_count": 0 },
    "security":       { "score": 0-100, "finding_count": 0 },
    "application":    { "score": 0-100, "finding_count": 0 },
    "ai_ml":          { "score": 0-100, "finding_count": 0 }
  },
  "findings": [
    {
      "id": "e.g. SEC-001",
      "domain": "infrastructure" | "security" | "application" | "ai_ml",
      "severity": "critical" | "high" | "medium" | "low",
      "title": "short title",
      "finding": "what is wrong, 1-2 sentences",
      "control_refs": ["string"],
      "recommendation": "what to do, 1-2 sentences",
      "theme_keys": ["THEME_KEY", "THEME_KEY"]
    }
  ]
}

Rules:
- IDs use the prefix for their domain (INF, SEC, APP, AI) and 3-digit zero-padded numbers starting from 001.
- Scores reflect observed maturity. If AI/ML is not present, set finding_count to 0 and score to 100 and note this in the summary.` + PROMPT_SHARED_TAIL;

const PROMPT_THREAT = `You are ATLAS THREAT, a threat modelling specialist. You produce STRIDE-based threat models with MITRE ATT&CK for Cloud mapping for systems under review.

## Your approach

1. Decompose the described system into components, data flows, and trust boundaries.
2. Apply STRIDE systematically to each component and data flow.
3. For each identified threat, cite a concrete MITRE ATT&CK technique ID (e.g., T1078.004 for Valid Accounts: Cloud Accounts) where applicable.
4. Rate severity based on likelihood × impact. Use the same four-level scale as the review agent.
5. Prefer controls that eliminate the root cause, not just compensating controls.

## Output schema

{
  "system_name": "string",
  "executive_summary": ["string", "string"],
  "methodology": "STRIDE",
  "domain_scores": {
    "infrastructure": { "score": 0-100, "finding_count": 0 },
    "security":       { "score": 0-100, "finding_count": 0 },
    "application":    { "score": 0-100, "finding_count": 0 },
    "ai_ml":          { "score": 0-100, "finding_count": 0 }
  },
  "findings": [
    {
      "id": "e.g. T-001",
      "domain": "infrastructure" | "security" | "application" | "ai_ml",
      "severity": "critical" | "high" | "medium" | "low",
      "stride": "S|T|R|I|D|E",
      "component": "which component this threat affects",
      "title": "short threat name",
      "finding": "the threat scenario",
      "mitre": "MITRE ATT&CK technique ID if applicable",
      "control_refs": ["string"],
      "recommendation": "mitigation",
      "theme_keys": ["THEME_KEY"]
    }
  ]
}` + PROMPT_SHARED_TAIL;

const PROMPT_BASELINE = `You are ATLAS BASELINE, a compliance assessor. You evaluate system architectures against specific regulatory baselines (CBUAE, SAMA, PCI-DSS, etc.) and identify control gaps.

## Your approach

1. Read the system description and the targeted baseline (provided in the user message).
2. Identify every control gap — where the system would fail to meet the baseline's requirements.
3. For each gap, cite the specific baseline clause, severity based on regulatory impact, and a remediation that maps back to the baseline's language.
4. Do not invent findings that aren't grounded in the architecture described. If evidence is missing, mark severity lower and note "insufficient evidence" in the finding.

## Output schema — same as review agent

{
  "system_name": "string",
  "executive_summary": ["string", "string"],
  "baseline": "baseline ID provided in request",
  "domain_scores": {
    "infrastructure": { "score": 0-100, "finding_count": 0 },
    "security":       { "score": 0-100, "finding_count": 0 },
    "application":    { "score": 0-100, "finding_count": 0 },
    "ai_ml":          { "score": 0-100, "finding_count": 0 }
  },
  "findings": [
    {
      "id": "e.g. CMP-001",
      "domain": "infrastructure" | "security" | "application" | "ai_ml",
      "severity": "critical" | "high" | "medium" | "low",
      "title": "short title",
      "finding": "gap description",
      "control_refs": ["specific baseline clause ID"],
      "recommendation": "remediation mapped to the baseline language",
      "theme_keys": ["THEME_KEY"]
    }
  ]
}` + PROMPT_SHARED_TAIL;

const PROMPT_RISK = `You are ATLAS RISK, a business-risk officer. You translate technical findings into a risk register suitable for an Executive Risk Committee (ERC) — with inherent and residual scoring and business-language framing.

## Your approach

1. Read the system description.
2. Identify business risks — not technical vulnerabilities, but what could happen to the business (regulatory penalties, reputational harm, operational outage, financial loss, data breach).
3. Score each risk on a 1–5 scale for LIKELIHOOD and IMPACT, then compute inherent = likelihood × impact.
4. Propose a control set and compute residual risk once controls are in place.
5. Map every risk to at least one theme_key so it can be cross-mapped against regulatory baselines.

## Output schema

{
  "system_name": "string",
  "executive_summary": ["string", "string"],
  "domain_scores": {
    "infrastructure": { "score": 0-100, "finding_count": 0 },
    "security":       { "score": 0-100, "finding_count": 0 },
    "application":    { "score": 0-100, "finding_count": 0 },
    "ai_ml":          { "score": 0-100, "finding_count": 0 }
  },
  "findings": [
    {
      "id": "e.g. R-001",
      "domain": "infrastructure" | "security" | "application" | "ai_ml",
      "severity": "critical" | "high" | "medium" | "low",
      "title": "business risk in plain language",
      "finding": "what could happen and to whom",
      "likelihood": 1-5,
      "impact": 1-5,
      "inherent_score": likelihood * impact,
      "residual_score": likelihood * impact after controls,
      "control_refs": ["string"],
      "recommendation": "risk treatment: avoid | transfer | mitigate | accept",
      "theme_keys": ["THEME_KEY"]
    }
  ]
}

Severity mapping from inherent_score: 20-25 critical, 12-19 high, 6-11 medium, 1-5 low.` + PROMPT_SHARED_TAIL;

const SYSTEM_PROMPTS = {
  review:   PROMPT_REVIEW,
  threat:   PROMPT_THREAT,
  baseline: PROMPT_BASELINE,
  risk:     PROMPT_RISK,
};

// ============================================================
// PROVIDER INVOCATION
// ============================================================
async function invokeLLM({ systemPrompt, userText, images = [] }) {
  const start = Date.now();

  if (LLM_PROVIDER === 'anthropic_direct') {
    const content = [{ type: 'text', text: userText }];
    for (const img of images) content.push({ type: 'image', source: { type: 'base64', media_type: img.mime, data: img.base64 } });
    const response = await providerClient.messages.create({
      model: providerMeta.model, max_tokens: 8000, system: systemPrompt,
      messages: [{ role: 'user', content }],
    });
    const text = response.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    return { text, usage: { input_tokens: response.usage?.input_tokens, output_tokens: response.usage?.output_tokens }, elapsed_ms: Date.now() - start };
  }

  if (LLM_PROVIDER === 'aws_bedrock') {
    const { InvokeModelCommand } = await import('@aws-sdk/client-bedrock-runtime');
    const content = [{ type: 'text', text: userText }];
    for (const img of images) content.push({ type: 'image', source: { type: 'base64', media_type: img.mime, data: img.base64 } });
    const body = {
      anthropic_version: 'bedrock-2023-05-31', max_tokens: 8000,
      system: systemPrompt, messages: [{ role: 'user', content }],
    };
    const cmd = new InvokeModelCommand({
      modelId: providerMeta.model, contentType: 'application/json', accept: 'application/json',
      body: JSON.stringify(body),
    });
    const response = await providerClient.send(cmd);
    const payload = JSON.parse(new TextDecoder().decode(response.body));
    const text = payload.content.filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
    return { text, usage: { input_tokens: payload.usage?.input_tokens, output_tokens: payload.usage?.output_tokens }, elapsed_ms: Date.now() - start };
  }

  if (LLM_PROVIDER === 'azure_openai') {
    const content = [{ type: 'text', text: userText }];
    for (const img of images) content.push({ type: 'image_url', image_url: { url: `data:${img.mime};base64,${img.base64}` } });
    const response = await providerClient.chat.completions.create({
      model: providerMeta.model, max_tokens: 8000,
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content }],
    });
    return {
      text: response.choices[0].message.content.trim(),
      usage: { input_tokens: response.usage?.prompt_tokens, output_tokens: response.usage?.completion_tokens },
      elapsed_ms: Date.now() - start,
    };
  }

  throw new Error(`Provider not implemented: ${LLM_PROVIDER}`);
}

// ============================================================
// APP
// ============================================================
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 10 },
});

// ============================================================
// IN-MEMORY REVIEW CACHE (so export endpoints don't re-run the LLM)
// ============================================================
const reviewCache = new Map();
const REVIEW_TTL_MS = 60 * 60 * 1000;  // 1 hour
const MAX_CACHED_REVIEWS = 100;

function cacheReview(id, payload) {
  // Evict oldest if over cap
  if (reviewCache.size >= MAX_CACHED_REVIEWS) {
    const oldest = reviewCache.keys().next().value;
    reviewCache.delete(oldest);
  }
  reviewCache.set(id, { ...payload, cached_at: Date.now() });
  // Schedule expiry
  setTimeout(() => {
    const v = reviewCache.get(id);
    if (v && Date.now() - v.cached_at >= REVIEW_TTL_MS) reviewCache.delete(id);
  }, REVIEW_TTL_MS + 1000);
}

function makeReviewId() {
  return `rv-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

// ============================================================
// ROUTE: /api/review — shared by all 4 agents
// ============================================================
app.post('/api/review', upload.array('files', 10), async (req, res) => {
  try {
    const { system_name, description, workflow = 'review', domains, framework, baseline } = req.body;
    const files = req.files || [];

    if (!description?.trim() && files.length === 0) {
      return res.status(400).json({ error: 'Provide a system description or at least one file.' });
    }

    const workflowKey = (workflow || 'review').toLowerCase();
    const systemPrompt = SYSTEM_PROMPTS[workflowKey];
    if (!systemPrompt) {
      return res.status(400).json({ error: `Unknown workflow: ${workflow}. Valid: review, threat, baseline, risk` });
    }

    console.log(`\n→ New ${workflowKey.toUpperCase()}: "${system_name || 'Untitled'}" via ${providerMeta.label}`);
    console.log(`  Files: ${files.length} · Description: ${description?.length || 0} chars`);

    // ===== 1. Extract text =====
    const extractions = await Promise.all(files.map(f => extractFromFile(f).catch(err => ({
      text: '', type: 'error', name: f.originalname, error: err.message,
    }))));
    const extractErrors = extractions.filter(e => e.error || e.type === 'unknown');
    const imageExtractions = extractions.filter(e => e.type === 'image');
    const textExtractions = extractions.filter(e => e.text && e.text.length > 0);

    // ===== 2. PII redaction =====
    const redactionReports = [];
    const redactedDesc = redactPII(description || '');
    redactionReports.push(redactedDesc.redactions);
    const redactedExtractions = textExtractions.map(ext => {
      const red = redactPII(ext.text);
      redactionReports.push(red.redactions);
      return { ...ext, text: red.text };
    });
    const totalRedactions = mergeRedactions(redactionReports);
    const totalRedactedCount = totalRedactions.reduce((a, r) => a + r.count, 0);
    if (totalRedactedCount > 0) {
      console.log(`  🛡  PII redacted: ${totalRedactedCount} items (${totalRedactions.map(r => `${r.type}:${r.count}`).join(', ')})`);
    }

    // ===== 3. Build user message =====
    const domainsLabel = Array.isArray(domains) ? domains.join(', ') : (domains || 'all four');
    const frameworkLabel = framework || 'AWS Well-Architected + OWASP LLM Top 10';

    let userText = '';
    userText += `# ${workflowKey.toUpperCase()} Request\n\n`;
    userText += `**Workflow:** ${workflowKey}\n`;
    userText += `**Domain scope:** ${domainsLabel}\n`;
    userText += `**Framework:** ${frameworkLabel}\n`;
    if (workflowKey === 'baseline' && baseline) {
      const b = BASELINES[baseline];
      if (b) {
        userText += `**Target baseline:** ${b.name} (${b.short}, ${b.version}) — published by ${b.authority}\n\n`;
        userText += `Control catalogue (curated key controls):\n`;
        for (const c of b.controls) userText += `- ${c.id}: ${c.title}\n`;
        userText += `\n`;
      } else {
        userText += `**Target baseline:** ${baseline} (not found in catalogue — apply general best practice for this regulator)\n\n`;
      }
    } else {
      userText += `\n`;
    }

    if (system_name) userText += `**System:** ${system_name}\n\n`;
    if (redactedDesc.text.trim()) {
      userText += `## Description\n\n${redactedDesc.text.trim()}\n\n`;
    }

    for (const ext of redactedExtractions) {
      let content = ext.text;
      if (content.length > MAX_TEXT_CHARS) {
        content = content.slice(0, MAX_TEXT_CHARS) + '\n\n[... truncated ...]';
      }
      userText += `## Artefact: ${ext.name} (${ext.type})\n\n`;
      userText += '```\n' + content + '\n```\n\n';
    }

    if (imageExtractions.length > 0) {
      userText += `## Architecture Diagrams\n\n${imageExtractions.length} diagram(s) attached — analyse visually.\n\n`;
    }

    userText += `## Task\n\nProduce the analysis per the schema. Be specific, cite real services and controls.`;

    // ===== 4. Invoke LLM =====
    console.log(`  Calling ${providerMeta.label} (${providerMeta.region})...`);
    const images = imageExtractions.map(img => ({ base64: img.imageBase64, mime: img.imageMime }));
    const llmResponse = await invokeLLM({ systemPrompt, userText, images });
    console.log(`  ✓ LLM responded in ${llmResponse.elapsed_ms}ms · ${llmResponse.usage.input_tokens} in / ${llmResponse.usage.output_tokens} out`);

    // ===== 5. Parse JSON =====
    let parsed;
    try {
      const cleaned = llmResponse.text
        .replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '').trim();
      parsed = JSON.parse(cleaned);
    } catch (err) {
      console.error('  ❌ JSON parse failed. First 500 chars:');
      console.error(llmResponse.text.slice(0, 500));
      return res.status(502).json({
        error: 'Agent returned unparseable response. Try again or simplify the input.',
        raw: llmResponse.text.slice(0, 2000),
      });
    }

    // ===== 6. Build response =====
    const review_id = makeReviewId();
    const meta = {
      workflow: workflowKey,
      elapsed_ms: llmResponse.elapsed_ms,
      provider: providerMeta,
      files_processed: files.length - extractErrors.length,
      files_failed: extractErrors.length,
      extract_errors: extractErrors.map(e => ({ name: e.name, error: e.error })),
      tokens: llmResponse.usage,
      pii_redaction: { enabled: PII_REDACTION, total_redacted: totalRedactedCount, by_type: totalRedactions },
      data_residency: {
        region: DATA_REGION, note: DATA_SOVEREIGNTY_NOTE,
        processed_in: providerMeta.region, cross_border: providerMeta.residency_warning,
      },
    };

    // Cache for later export
    cacheReview(review_id, { review: parsed, meta });

    console.log(`  ✓ Returned ${parsed.findings?.length || 0} findings · id=${review_id}\n`);
    res.json({ ok: true, review_id, review: parsed, meta });

  } catch (err) {
    console.error('❌ Review failed:', err);
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// ============================================================
// ROUTE: /api/export/pdf-exec/:review_id
// ============================================================
app.get('/api/export/pdf-exec/:review_id', async (req, res) => {
  try {
    const cached = reviewCache.get(req.params.review_id);
    if (!cached) return res.status(404).json({ error: 'Review not found or expired. Re-run the review.' });
    const buf = await buildExecPdf(cached.review, cached.meta);
    const filename = `ATLAS-Executive-${(cached.review.system_name || 'review').replace(/[^\w-]+/g, '-').slice(0, 48)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buf);
  } catch (err) {
    console.error('pdf-exec failed:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ROUTE: /api/export/pdf-tech/:review_id
// ============================================================
app.get('/api/export/pdf-tech/:review_id', async (req, res) => {
  try {
    const cached = reviewCache.get(req.params.review_id);
    if (!cached) return res.status(404).json({ error: 'Review not found or expired. Re-run the review.' });
    const baselineId = req.query.baseline || 'CBUAE';
    const buf = await buildTechPdf(cached.review, cached.meta, { baselineId });
    const filename = `ATLAS-Technical-${(cached.review.system_name || 'review').replace(/[^\w-]+/g, '-').slice(0, 48)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buf);
  } catch (err) {
    console.error('pdf-tech failed:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ROUTE: /api/export/pptx/:review_id
// ============================================================
app.get('/api/export/pptx/:review_id', async (req, res) => {
  try {
    const cached = reviewCache.get(req.params.review_id);
    if (!cached) return res.status(404).json({ error: 'Review not found or expired. Re-run the review.' });
    const buf = await buildPptx(cached.review, cached.meta);
    const filename = `ATLAS-Deck-${(cached.review.system_name || 'review').replace(/[^\w-]+/g, '-').slice(0, 48)}.pptx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.presentationml.presentation');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buf);
  } catch (err) {
    console.error('pptx failed:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ROUTE: /api/export/json/:review_id
// ============================================================
app.get('/api/export/json/:review_id', (req, res) => {
  const cached = reviewCache.get(req.params.review_id);
  if (!cached) return res.status(404).json({ error: 'Review not found or expired.' });
  const filename = `ATLAS-${(cached.review.system_name || 'review').replace(/[^\w-]+/g, '-').slice(0, 48)}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify({ review: cached.review, meta: cached.meta }, null, 2));
});

// ============================================================
// ROUTES: Control library
// ============================================================
app.get('/api/baselines', (req, res) => {
  res.json({ ok: true, baselines: listBaselines(), totals: countTotals() });
});

app.get('/api/baseline/:id', (req, res) => {
  const b = getBaseline(req.params.id);
  if (!b) return res.status(404).json({ error: `Baseline not found: ${req.params.id}` });
  // Enrich controls with theme labels
  const enriched = {
    ...b,
    controls: b.controls.map(c => ({
      ...c,
      themes: c.theme_keys.map(k => ({ key: k, label: THEMES[k]?.label, domain: THEMES[k]?.domain })),
    })),
  };
  res.json({ ok: true, baseline: enriched });
});

app.get('/api/themes', (req, res) => {
  res.json({ ok: true, themes: listThemes() });
});

app.get('/api/theme/:key', (req, res) => {
  const t = THEMES[req.params.key];
  if (!t) return res.status(404).json({ error: `Theme not found: ${req.params.key}` });
  res.json({
    ok: true,
    key: req.params.key,
    theme: t,
    citations: mapThemeToControls(req.params.key),
  });
});

app.get('/api/crossmap', (req, res) => {
  res.json({ ok: true, matrix: buildCrossMap() });
});

app.post('/api/gap-analysis', (req, res) => {
  try {
    const { review_id, baseline_id, findings } = req.body;

    // Findings can come from review_id (cached) or be supplied directly
    let src = findings;
    if (!src && review_id) {
      const cached = reviewCache.get(review_id);
      if (!cached) return res.status(404).json({ error: 'Review not found or expired.' });
      src = cached.review.findings || [];
    }
    if (!src) return res.status(400).json({ error: 'Provide findings[] or review_id.' });
    if (!baseline_id) return res.status(400).json({ error: 'Provide baseline_id.' });

    const result = gapAnalysis(src, baseline_id);
    res.json({ ok: true, gap_analysis: result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ============================================================
// ROUTE: /api/health
// ============================================================
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    version: '2.1.0',
    provider: providerMeta,
    data_residency: {
      region: DATA_REGION, note: DATA_SOVEREIGNTY_NOTE,
      processed_in: providerMeta.region, cross_border: providerMeta.residency_warning,
    },
    pii_redaction: PII_REDACTION,
    controls: countTotals(),
    cached_reviews: reviewCache.size,
  });
});

// ============================================================
// START
// ============================================================
(async () => {
  try {
    await initProvider();
    const totals = countTotals();
    app.listen(PORT, () => {
      const warningLine = providerMeta.residency_warning
        ? '│  ⚠  DATA EGRESS: traffic leaves your region   │'
        : '│  ✓  IN-REGION: no cross-border egress         │';

      console.log(`
┌────────────────────────────────────────────────┐
│  ATLAS · v2.1                                  │
│  ────────────                                  │
│  → http://localhost:${PORT}                       │
│  → Provider:  ${providerMeta.label.padEnd(33)}│
│  → Model:     ${providerMeta.model.padEnd(33).slice(0, 33)}│
│  → Region:    ${providerMeta.region.padEnd(33).slice(0, 33)}│
│  → PII redaction: ${PII_REDACTION ? 'ON ' : 'OFF'}                         │
│  → Controls: ${String(totals.baselines).padStart(2)} baselines · ${String(totals.themes).padStart(2)} themes · ${String(totals.controls).padStart(3)}│
${warningLine}
└────────────────────────────────────────────────┘
      `);
    });
  } catch (err) {
    console.error(`\n❌ ${err.message}\n`);
    console.error('Check your .env against .env.example\n');
    process.exit(1);
  }
})();
