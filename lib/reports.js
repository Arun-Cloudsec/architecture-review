/**
 * ATLAS Reports · v2.1
 * ====================
 *
 * Server-side report generation:
 *   - buildExecPdf(review, meta)   → executive summary PDF for CISOs
 *   - buildTechPdf(review, meta)   → full technical findings PDF
 *   - buildPptx(review, meta)      → professional slide deck
 *
 * CRITICAL PDFKit note: doc.text() continues from the last x position by default,
 * which causes cascading layout bugs (headings float to the right of the previous
 * line). Every heading() and major text call in this module anchors at the
 * left margin explicitly.
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const PDFDocument = require('pdfkit');
import PptxGenJS from 'pptxgenjs';
import { BASELINES, THEMES, gapAnalysis } from './controls.js';

// ============================================================
// DESIGN TOKENS — shared across exec + technical PDFs
// ============================================================
const COLOR = {
  navy:       '#0E1B2B',
  navySoft:   '#1E2B3F',
  gold:       '#C9A44C',
  goldSoft:   '#E6D49E',
  text:       '#1A1D27',
  textSoft:   '#52586A',
  textFaint:  '#9AA0B4',
  border:     '#DDE1EA',
  bgLight:    '#F5F6FA',
  bgMuted:    '#ECEEF5',

  crit:       '#B3253D',
  high:       '#CC5C1B',
  medium:     '#C29A2B',
  low:        '#3D7C4E',

  critBg:     '#FBE9EC',
  highBg:     '#FDEADB',
  medBg:      '#FCF4D7',
  lowBg:      '#E8F4E9',
};

const DOMAIN_LABELS = {
  infrastructure: 'Infrastructure',
  security:       'Security',
  application:    'Application',
  ai_ml:          'AI / ML',
};

const sevLabel = s => ({ critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }[s] || s?.toUpperCase() || '—');
const sevColor = s => ({ critical: COLOR.crit, high: COLOR.high, medium: COLOR.medium, low: COLOR.low }[s] || COLOR.textSoft);
const sevBg    = s => ({ critical: COLOR.critBg, high: COLOR.highBg, medium: COLOR.medBg, low: COLOR.lowBg }[s] || COLOR.bgLight);
const sevWeight = s => ({ critical: 4, high: 3, medium: 2, low: 1 }[s] || 0);

function countBySeverity(findings = []) {
  const out = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
  for (const f of findings) if (out[f.severity] !== undefined) out[f.severity]++;
  return out;
}

function today() {
  return new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
}

// ============================================================
// PDFKit HELPERS — always anchor at left margin
// ============================================================
function anchorLeft(doc) {
  doc.x = doc.page.margins.left;
}

function hr(doc, color = COLOR.border, spaceBefore = 6, spaceAfter = 10) {
  doc.moveDown(spaceBefore / 12);
  const y = doc.y;
  doc.save()
     .moveTo(doc.page.margins.left, y)
     .lineTo(doc.page.width - doc.page.margins.right, y)
     .strokeColor(color)
     .lineWidth(0.5)
     .stroke()
     .restore();
  doc.moveDown(spaceAfter / 12);
  anchorLeft(doc);
}

function pageFooter(doc, label) {
  const bottom = doc.page.height - 36;
  doc.save()
     .fontSize(8)
     .fillColor(COLOR.textFaint)
     .text(label, doc.page.margins.left, bottom, {
       width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
       align: 'left',
       lineBreak: false,
     });
  doc.text(`Page ${doc.bufferedPageRange().count}`, doc.page.margins.left, bottom, {
     width: doc.page.width - doc.page.margins.left - doc.page.margins.right,
     align: 'right',
     lineBreak: false,
  });
  doc.restore();
  anchorLeft(doc);
}

// ============================================================
// EXECUTIVE PDF — short, CISO-facing
// ============================================================
export function buildExecPdf(review, meta = {}) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 60, bottom: 60, left: 60, right: 60 },
        bufferPages: true,
        info: {
          Title: `ATLAS Executive Review — ${review.system_name || 'Untitled'}`,
          Author: 'ATLAS',
          Subject: 'Architecture Security Review',
        },
      });

      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // ===== COVER HERO =====
      const heroH = 230;
      doc.save()
         .rect(0, 0, doc.page.width, heroH)
         .fill(COLOR.navy);

      // Gold accent bar
      doc.rect(0, heroH - 6, doc.page.width, 6).fill(COLOR.gold);

      // Label
      doc.fillColor(COLOR.goldSoft)
         .font('Helvetica-Bold')
         .fontSize(9)
         .text('ATLAS · EXECUTIVE SUMMARY', 60, 70, { characterSpacing: 1.5, lineBreak: false });

      // Title
      doc.fillColor('#FFFFFF')
         .font('Helvetica-Bold')
         .fontSize(28)
         .text(review.system_name || 'Architecture Review', 60, 95, {
           width: doc.page.width - 120,
           lineGap: 2,
         });

      // Subtitle
      doc.fillColor(COLOR.goldSoft)
         .font('Helvetica')
         .fontSize(11)
         .text('Cloud Architecture Security Review', 60, doc.y + 6, {
           width: doc.page.width - 120,
         });

      // Meta row at bottom of hero
      doc.fillColor('#D8DCE8')
         .font('Helvetica')
         .fontSize(9)
         .text(`${today()}  ·  ${meta.provider?.label || 'LLM'}  ·  ${meta.provider?.region || '—'}`, 60, heroH - 36);

      doc.restore();

      // ===== SEVERITY TILES =====
      anchorLeft(doc);
      doc.y = heroH + 28;

      const counts = countBySeverity(review.findings);
      const tiles = [
        { label: 'CRITICAL', value: counts.critical, color: COLOR.crit },
        { label: 'HIGH',     value: counts.high,     color: COLOR.high },
        { label: 'MEDIUM',   value: counts.medium,   color: COLOR.medium },
        { label: 'LOW',      value: counts.low,      color: COLOR.low },
      ];
      const tileW = (doc.page.width - 120 - 3 * 10) / 4;
      const tileH = 70;
      const tileY = doc.y;
      tiles.forEach((t, i) => {
        const x = 60 + i * (tileW + 10);
        doc.save()
           .rect(x, tileY, tileW, tileH)
           .fill(COLOR.bgLight);
        doc.rect(x, tileY, 3, tileH).fill(t.color);
        doc.fillColor(COLOR.textSoft)
           .font('Helvetica-Bold')
           .fontSize(8)
           .text(t.label, x + 12, tileY + 12, { characterSpacing: 1.2, lineBreak: false });
        doc.fillColor(COLOR.text)
           .font('Helvetica-Bold')
           .fontSize(28)
           .text(String(t.value), x + 12, tileY + 26, { lineBreak: false });
        doc.restore();
      });

      anchorLeft(doc);
      doc.y = tileY + tileH + 24;

      // ===== EXECUTIVE SUMMARY SECTION =====
      heading(doc, 'Executive Summary');
      const paras = Array.isArray(review.executive_summary)
        ? review.executive_summary
        : review.executive_summary ? [review.executive_summary] : [];

      doc.font('Helvetica')
         .fontSize(10.5)
         .fillColor(COLOR.text);

      for (const para of paras) {
        anchorLeft(doc);
        doc.text(para, { align: 'justify', lineGap: 2, paragraphGap: 8 });
      }

      doc.moveDown(0.8);
      anchorLeft(doc);

      // ===== DOMAIN SCORES =====
      heading(doc, 'Domain Scores');
      const scores = review.domain_scores || {};
      const domains = Object.keys(DOMAIN_LABELS);
      const barWidth = doc.page.width - 120 - 180;
      for (const d of domains) {
        const s = scores[d] || { score: 0, finding_count: 0 };
        const score = Math.max(0, Math.min(100, s.score || 0));
        const barY = doc.y + 4;
        const barX = 60 + 170;

        anchorLeft(doc);
        doc.font('Helvetica-Bold')
           .fontSize(10)
           .fillColor(COLOR.text)
           .text(DOMAIN_LABELS[d], 60, doc.y, { width: 160, lineBreak: false });

        // Background bar
        doc.save()
           .rect(barX, barY, barWidth, 10)
           .fill(COLOR.bgMuted);
        // Filled portion
        const fillColor = score >= 80 ? COLOR.low : score >= 60 ? COLOR.medium : score >= 40 ? COLOR.high : COLOR.crit;
        doc.rect(barX, barY, (barWidth * score) / 100, 10).fill(fillColor);
        doc.restore();

        // Score label
        doc.font('Helvetica-Bold')
           .fontSize(10)
           .fillColor(COLOR.text)
           .text(`${score} / 100`, barX + barWidth + 10, doc.y, { lineBreak: false });

        doc.moveDown(0.1);
        anchorLeft(doc);
        doc.font('Helvetica')
           .fontSize(8.5)
           .fillColor(COLOR.textSoft)
           .text(`${s.finding_count || 0} finding${s.finding_count === 1 ? '' : 's'}`, 60, doc.y, {
             width: 160, lineBreak: false,
           });
        doc.moveDown(0.9);
      }

      anchorLeft(doc);
      doc.moveDown(0.5);

      // ===== TOP FINDINGS =====
      const topFindings = [...(review.findings || [])]
        .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
        .slice(0, 6);

      heading(doc, 'Top Findings');
      if (topFindings.length === 0) {
        anchorLeft(doc);
        doc.font('Helvetica-Oblique').fontSize(10).fillColor(COLOR.textSoft)
           .text('No findings reported.');
      } else {
        for (const f of topFindings) {
          // Break page if we don't have ~100pt of room
          if (doc.y > doc.page.height - 140) {
            doc.addPage();
            anchorLeft(doc);
            doc.y = doc.page.margins.top;
          }
          renderExecFinding(doc, f);
        }
      }

      // Footer on every page
      const range = doc.bufferedPageRange();
      for (let i = range.start; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        pageFooter(doc, `ATLAS · Executive Review · ${review.system_name || 'Untitled'}`);
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

function heading(doc, text) {
  anchorLeft(doc);
  doc.font('Helvetica-Bold')
     .fontSize(14)
     .fillColor(COLOR.navy)
     .text(text, { lineBreak: true });
  // Thin gold underline
  const y = doc.y + 2;
  doc.save()
     .moveTo(doc.page.margins.left, y)
     .lineTo(doc.page.margins.left + 40, y)
     .strokeColor(COLOR.gold)
     .lineWidth(1.5)
     .stroke()
     .restore();
  doc.moveDown(0.8);
  anchorLeft(doc);
}

function renderExecFinding(doc, f) {
  anchorLeft(doc);
  const startY = doc.y;

  // Severity pill — measure with characterSpacing baked in, then pad generously
  const sevText = sevLabel(f.severity);
  doc.font('Helvetica-Bold').fontSize(8);
  // characterSpacing adds N units between each character; widthOfString ignores it
  const baseW = doc.widthOfString(sevText);
  const pillW = baseW + 8 * 0.8 + 18;  // spacing budget + generous padding
  doc.save()
     .roundedRect(60, startY, pillW, 15, 2)
     .fill(sevBg(f.severity))
     .restore();
  doc.fillColor(sevColor(f.severity))
     .font('Helvetica-Bold')
     .fontSize(8)
     .text(sevText, 60, startY + 3.5, { width: pillW, align: 'center', lineBreak: false, characterSpacing: 0.8 });

  // ID + title on same line as pill
  doc.font('Helvetica-Bold').fontSize(10.5).fillColor(COLOR.text);
  const titleX = 60 + pillW + 10;
  const titleW = doc.page.width - 60 - titleX;
  doc.text(`${f.id || ''}  ${f.title || ''}`, titleX, startY + 1, { width: titleW, lineBreak: true });

  anchorLeft(doc);
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(9.5).fillColor(COLOR.text);
  if (f.finding) doc.text(f.finding, { lineGap: 1 });
  if (f.recommendation) {
    anchorLeft(doc);
    doc.moveDown(0.2);
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLOR.textSoft)
       .text(`→ ${f.recommendation}`, { lineGap: 1 });
  }
  doc.moveDown(0.6);
  anchorLeft(doc);
}

// ============================================================
// TECHNICAL PDF — full findings + gap analysis
// ============================================================
export function buildTechPdf(review, meta = {}, options = {}) {
  const { baselineId = 'CBUAE' } = options;

  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 60, bottom: 60, left: 60, right: 60 },
        bufferPages: true,
        info: {
          Title: `ATLAS Technical Report — ${review.system_name || 'Untitled'}`,
          Author: 'ATLAS',
          Subject: 'Architecture Security Review',
        },
      });

      const chunks = [];
      doc.on('data', c => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      // ===== COVER =====
      doc.save()
         .rect(0, 0, doc.page.width, doc.page.height)
         .fill(COLOR.navy);
      doc.rect(0, 0, 6, doc.page.height).fill(COLOR.gold);

      doc.fillColor(COLOR.goldSoft)
         .font('Helvetica-Bold')
         .fontSize(10)
         .text('ATLAS · TECHNICAL REPORT', 60, 180, { characterSpacing: 2, lineBreak: false });

      doc.fillColor('#FFFFFF')
         .font('Helvetica-Bold')
         .fontSize(36)
         .text(review.system_name || 'Architecture Review', 60, 220, {
           width: doc.page.width - 120, lineGap: 4,
         });

      doc.fillColor(COLOR.goldSoft)
         .font('Helvetica')
         .fontSize(14)
         .text('Cloud Architecture Security Review', 60, doc.y + 10, {
           width: doc.page.width - 120,
         });

      // Meta block at bottom of cover
      const metaY = doc.page.height - 160;
      doc.save()
         .moveTo(60, metaY)
         .lineTo(60 + 40, metaY)
         .strokeColor(COLOR.gold)
         .lineWidth(1.5)
         .stroke()
         .restore();

      doc.fillColor(COLOR.goldSoft).font('Helvetica-Bold').fontSize(9).text('ISSUED', 60, metaY + 10, { characterSpacing: 1.3 });
      doc.fillColor('#FFFFFF').font('Helvetica').fontSize(11).text(today(), 60, metaY + 24);

      doc.fillColor(COLOR.goldSoft).font('Helvetica-Bold').fontSize(9).text('PROCESSED BY', 200, metaY + 10, { characterSpacing: 1.3 });
      doc.fillColor('#FFFFFF').font('Helvetica').fontSize(11).text(meta.provider?.label || '—', 200, metaY + 24);

      doc.fillColor(COLOR.goldSoft).font('Helvetica-Bold').fontSize(9).text('REGION', 360, metaY + 10, { characterSpacing: 1.3 });
      doc.fillColor('#FFFFFF').font('Helvetica').fontSize(11).text(meta.provider?.region || '—', 360, metaY + 24);

      doc.fillColor(COLOR.goldSoft)
         .font('Helvetica')
         .fontSize(8)
         .text('CONFIDENTIAL — FOR INTENDED RECIPIENTS ONLY', 60, doc.page.height - 40, { characterSpacing: 1.5 });

      // ===== PAGE 2: TOC + EXEC SUMMARY =====
      doc.addPage();
      anchorLeft(doc);

      techHeading(doc, '01', 'Executive Summary');
      const paras = Array.isArray(review.executive_summary)
        ? review.executive_summary
        : review.executive_summary ? [review.executive_summary] : [];
      doc.font('Helvetica').fontSize(10.5).fillColor(COLOR.text);
      for (const para of paras) {
        anchorLeft(doc);
        doc.text(para, { align: 'justify', lineGap: 2, paragraphGap: 10 });
      }
      anchorLeft(doc);
      doc.moveDown(0.8);

      // Domain scores summary
      techHeading(doc, '02', 'Domain Maturity Scores');
      const scores = review.domain_scores || {};
      const barWidth = doc.page.width - 120 - 180;
      for (const d of Object.keys(DOMAIN_LABELS)) {
        const s = scores[d] || { score: 0, finding_count: 0 };
        const score = Math.max(0, Math.min(100, s.score || 0));
        const barY = doc.y + 4;
        const barX = 60 + 170;

        anchorLeft(doc);
        doc.font('Helvetica-Bold').fontSize(10).fillColor(COLOR.text)
           .text(DOMAIN_LABELS[d], 60, doc.y, { width: 160, lineBreak: false });

        doc.save().rect(barX, barY, barWidth, 10).fill(COLOR.bgMuted);
        const fillColor = score >= 80 ? COLOR.low : score >= 60 ? COLOR.medium : score >= 40 ? COLOR.high : COLOR.crit;
        doc.rect(barX, barY, (barWidth * score) / 100, 10).fill(fillColor);
        doc.restore();

        doc.font('Helvetica-Bold').fontSize(10).fillColor(COLOR.text)
           .text(`${score} / 100`, barX + barWidth + 10, doc.y, { lineBreak: false });
        doc.moveDown(0.1);
        anchorLeft(doc);
        doc.font('Helvetica').fontSize(8.5).fillColor(COLOR.textSoft)
           .text(`${s.finding_count || 0} finding${s.finding_count === 1 ? '' : 's'}`, 60, doc.y, { width: 160, lineBreak: false });
        doc.moveDown(0.9);
      }

      anchorLeft(doc);
      doc.moveDown(0.5);

      // Findings summary table
      techHeading(doc, '03', 'Findings Summary');
      const counts = countBySeverity(review.findings);
      renderSummaryTable(doc, counts);

      // ===== FINDINGS BY DOMAIN =====
      const byDomain = {};
      for (const f of (review.findings || [])) {
        if (!byDomain[f.domain]) byDomain[f.domain] = [];
        byDomain[f.domain].push(f);
      }

      let sectionNum = 4;
      for (const d of Object.keys(DOMAIN_LABELS)) {
        const list = byDomain[d] || [];
        if (list.length === 0) continue;
        doc.addPage();
        anchorLeft(doc);
        techHeading(doc, String(sectionNum).padStart(2, '0'), `${DOMAIN_LABELS[d]} Findings`);
        // Sort by severity within each domain
        list.sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity));
        for (const f of list) {
          if (doc.y > doc.page.height - 160) {
            doc.addPage();
            anchorLeft(doc);
          }
          renderFindingBlock(doc, f);
        }
        sectionNum++;
      }

      // ===== GAP ANALYSIS =====
      if (BASELINES[baselineId]) {
        doc.addPage();
        anchorLeft(doc);
        const baseline = BASELINES[baselineId];
        techHeading(doc, String(sectionNum).padStart(2, '0'), `Gap Analysis · ${baseline.short}`);

        const gap = gapAnalysis(review.findings || [], baselineId);

        // Summary line
        anchorLeft(doc);
        doc.font('Helvetica').fontSize(10).fillColor(COLOR.text)
           .text(`Assessed against ${baseline.name} (${baseline.version}) published by ${baseline.authority}. Coverage is the share of controls where review findings touch at least one of the control's themes; not-assessed controls fall outside this review's scope.`, { lineGap: 2 });
        doc.moveDown(0.8);

        // Summary tiles
        const gapTiles = [
          { label: 'TOTAL CONTROLS', value: gap.summary.total,        color: COLOR.navy },
          { label: 'COVERED',        value: gap.summary.covered,      color: COLOR.low },
          { label: 'AT RISK',        value: gap.summary.at_risk,      color: COLOR.high },
          { label: 'NOT ASSESSED',   value: gap.summary.not_assessed, color: COLOR.textSoft },
        ];
        const tW = (doc.page.width - 120 - 30) / 4;
        const tY = doc.y;
        gapTiles.forEach((t, i) => {
          const x = 60 + i * (tW + 10);
          doc.save().rect(x, tY, tW, 56).fill(COLOR.bgLight);
          doc.rect(x, tY, 3, 56).fill(t.color);
          doc.fillColor(COLOR.textSoft).font('Helvetica-Bold').fontSize(7.5)
             .text(t.label, x + 10, tY + 10, { characterSpacing: 1.1, lineBreak: false });
          doc.fillColor(COLOR.text).font('Helvetica-Bold').fontSize(22)
             .text(String(t.value), x + 10, tY + 22, { lineBreak: false });
          doc.restore();
        });
        anchorLeft(doc);
        doc.y = tY + 56 + 16;

        // Coverage percentage highlight
        anchorLeft(doc);
        doc.font('Helvetica-Bold').fontSize(11).fillColor(COLOR.navy)
           .text(`Coverage: ${gap.summary.coverage_pct}%`, { lineBreak: true });
        doc.moveDown(0.8);

        // Controls table
        anchorLeft(doc);
        const tableX = 60;
        const colW = [ 80, 250, 90, 70 ];
        const tableW = colW.reduce((a, b) => a + b, 0);

        // Header
        const hY = doc.y;
        doc.save().rect(tableX, hY, tableW, 20).fill(COLOR.navy);
        doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(8.5);
        doc.text('CONTROL', tableX + 8, hY + 6, { width: colW[0], lineBreak: false, characterSpacing: 0.8 });
        doc.text('TITLE', tableX + 8 + colW[0], hY + 6, { width: colW[1], lineBreak: false, characterSpacing: 0.8 });
        doc.text('STATUS', tableX + 8 + colW[0] + colW[1], hY + 6, { width: colW[2], lineBreak: false, characterSpacing: 0.8 });
        doc.text('SEV', tableX + 8 + colW[0] + colW[1] + colW[2], hY + 6, { width: colW[3], lineBreak: false, characterSpacing: 0.8 });
        doc.restore();
        doc.y = hY + 20;

        for (const row of gap.controls) {
          if (doc.y > doc.page.height - 80) {
            doc.addPage();
            anchorLeft(doc);
          }
          const rY = doc.y;
          // Compute row height based on title wrap
          doc.font('Helvetica').fontSize(9);
          const titleH = doc.heightOfString(row.control_title, { width: colW[1] - 8 });
          const rowH = Math.max(22, titleH + 10);

          // Zebra
          const index = gap.controls.indexOf(row);
          if (index % 2 === 1) {
            doc.save().rect(tableX, rY, tableW, rowH).fill(COLOR.bgLight).restore();
          }

          doc.fillColor(COLOR.text).font('Helvetica-Bold').fontSize(8.5)
             .text(row.control_id, tableX + 8, rY + 5, { width: colW[0] - 8, lineBreak: true });
          doc.fillColor(COLOR.text).font('Helvetica').fontSize(8.5)
             .text(row.control_title, tableX + 8 + colW[0], rY + 5, { width: colW[1] - 8, lineBreak: true });

          const statusColor = row.status === 'covered'   ? COLOR.low
                           :  row.status === 'at-risk'   ? COLOR.high
                           :                               COLOR.textFaint;
          doc.fillColor(statusColor).font('Helvetica-Bold').fontSize(8)
             .text(row.status.toUpperCase(), tableX + 8 + colW[0] + colW[1], rY + 5, { width: colW[2] - 8, lineBreak: false, characterSpacing: 0.8 });

          if (row.worst_severity) {
            doc.fillColor(sevColor(row.worst_severity)).font('Helvetica-Bold').fontSize(8)
               .text(sevLabel(row.worst_severity), tableX + 8 + colW[0] + colW[1] + colW[2], rY + 5, { width: colW[3] - 8, lineBreak: false });
          }

          doc.y = rY + rowH;
          anchorLeft(doc);
        }
        sectionNum++;
      }

      // ===== REMEDIATION ROADMAP =====
      const hasFindings = (review.findings || []).length > 0;
      if (hasFindings) {
        doc.addPage();
        anchorLeft(doc);
        techHeading(doc, String(sectionNum).padStart(2, '0'), 'Remediation Roadmap');
        const now    = (review.findings || []).filter(f => f.severity === 'critical');
        const thisQ  = (review.findings || []).filter(f => f.severity === 'high');
        const nextQ  = (review.findings || []).filter(f => f.severity === 'medium');
        const later  = (review.findings || []).filter(f => f.severity === 'low');
        const sections = [
          { label: 'IMMEDIATE (WITHIN 2 WEEKS) — CRITICAL', color: COLOR.crit, items: now },
          { label: 'THIS SPRINT (0–30 DAYS) — HIGH',        color: COLOR.high, items: thisQ },
          { label: 'NEXT QUARTER (30–90 DAYS) — MEDIUM',     color: COLOR.medium, items: nextQ },
          { label: 'BACKLOG / HARDENING — LOW',              color: COLOR.low, items: later },
        ];
        for (const s of sections) {
          if (doc.y > doc.page.height - 120) {
            doc.addPage();
            anchorLeft(doc);
          }
          anchorLeft(doc);
          doc.save().rect(60, doc.y, 3, 16).fill(s.color).restore();
          doc.font('Helvetica-Bold').fontSize(9).fillColor(COLOR.text)
             .text(s.label, 70, doc.y + 1, { characterSpacing: 1, lineBreak: true });
          doc.moveDown(0.4);
          anchorLeft(doc);
          if (s.items.length === 0) {
            doc.font('Helvetica-Oblique').fontSize(9.5).fillColor(COLOR.textFaint)
               .text('No findings in this band.', 70, doc.y);
          } else {
            for (const f of s.items) {
              anchorLeft(doc);
              doc.font('Helvetica-Bold').fontSize(9.5).fillColor(COLOR.text)
                 .text(`${f.id}  ·  ${f.title}`, 70, doc.y, { lineBreak: true });
              if (f.recommendation) {
                anchorLeft(doc);
                doc.font('Helvetica').fontSize(9).fillColor(COLOR.textSoft)
                   .text(f.recommendation, 70, doc.y, { lineGap: 1 });
              }
              doc.moveDown(0.5);
            }
          }
          doc.moveDown(0.6);
        }
      }

      // Footer on every page
      const range = doc.bufferedPageRange();
      for (let i = range.start + 1; i < range.start + range.count; i++) {
        doc.switchToPage(i);
        pageFooter(doc, `ATLAS · Technical Report · ${review.system_name || 'Untitled'}`);
      }

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

function techHeading(doc, num, text) {
  anchorLeft(doc);
  const y = doc.y;
  doc.font('Helvetica-Bold').fontSize(9).fillColor(COLOR.gold)
     .text(num, 60, y, { characterSpacing: 1.5, lineBreak: false });
  doc.font('Helvetica-Bold').fontSize(18).fillColor(COLOR.navy)
     .text(text, 90, y - 3, { width: doc.page.width - 150, lineBreak: true });
  anchorLeft(doc);
  doc.moveDown(0.2);
  const underY = doc.y;
  doc.save()
     .moveTo(doc.page.margins.left, underY)
     .lineTo(doc.page.margins.left + 40, underY)
     .strokeColor(COLOR.gold).lineWidth(1.5).stroke().restore();
  doc.moveDown(0.8);
  anchorLeft(doc);
}

function renderSummaryTable(doc, counts) {
  const tableX = 60;
  const rows = [
    ['Critical',       counts.critical, COLOR.crit],
    ['High',           counts.high,     COLOR.high],
    ['Medium',         counts.medium,   COLOR.medium],
    ['Low',            counts.low,      COLOR.low],
    ['Total',          counts.total,    COLOR.navy],
  ];
  const tableW = doc.page.width - 120;
  const rowH = 22;

  // Header
  const hY = doc.y;
  doc.save().rect(tableX, hY, tableW, rowH).fill(COLOR.navy).restore();
  doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(9);
  doc.text('SEVERITY', tableX + 12, hY + 7, { width: tableW - 100, lineBreak: false, characterSpacing: 1 });
  doc.text('COUNT', tableX + tableW - 80, hY + 7, { width: 60, align: 'right', lineBreak: false, characterSpacing: 1 });
  doc.y = hY + rowH;

  for (const [label, count, color] of rows) {
    const rY = doc.y;
    if (rows.indexOf([label, count, color]) === rows.length - 1) {
      doc.save().rect(tableX, rY, tableW, rowH).fill(COLOR.bgMuted).restore();
    }
    doc.save().rect(tableX, rY, 3, rowH).fill(color).restore();
    const weight = label === 'Total' ? 'Helvetica-Bold' : 'Helvetica';
    doc.fillColor(COLOR.text).font(weight).fontSize(10)
       .text(label, tableX + 12, rY + 6, { width: tableW - 100, lineBreak: false });
    doc.font('Helvetica-Bold')
       .text(String(count), tableX + tableW - 80, rY + 6, { width: 60, align: 'right', lineBreak: false });
    doc.y = rY + rowH;
  }
  doc.moveDown(1);
  anchorLeft(doc);
}

function renderFindingBlock(doc, f) {
  anchorLeft(doc);
  const startY = doc.y;

  // Left accent bar
  const barColor = sevColor(f.severity);

  // Severity pill + ID header — measure with characterSpacing baked in
  doc.font('Helvetica-Bold').fontSize(8.5);
  const sevText = sevLabel(f.severity);
  const baseW = doc.widthOfString(sevText);
  const pillW = baseW + 8 * 0.8 + 20;
  doc.save()
     .roundedRect(60, startY, pillW, 15, 2)
     .fill(sevBg(f.severity))
     .restore();
  doc.fillColor(sevColor(f.severity))
     .font('Helvetica-Bold')
     .fontSize(8.5)
     .text(sevText, 60, startY + 3.5, { width: pillW, align: 'center', lineBreak: false, characterSpacing: 0.8 });

  doc.font('Helvetica-Bold').fontSize(8.5).fillColor(COLOR.textSoft)
     .text(f.id || '', 60 + pillW + 8, startY + 3.5, { lineBreak: false });

  // Title
  anchorLeft(doc);
  doc.y = startY + 22;
  doc.font('Helvetica-Bold').fontSize(11.5).fillColor(COLOR.navy)
     .text(f.title || '(untitled)', { width: doc.page.width - 120, lineGap: 1 });

  // Finding body
  if (f.finding) {
    anchorLeft(doc);
    doc.moveDown(0.25);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLOR.textSoft)
       .text('FINDING', { characterSpacing: 1.2 });
    anchorLeft(doc);
    doc.moveDown(0.15);
    doc.font('Helvetica').fontSize(10).fillColor(COLOR.text)
       .text(f.finding, { lineGap: 2, align: 'justify' });
  }

  // Recommendation
  if (f.recommendation) {
    anchorLeft(doc);
    doc.moveDown(0.4);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLOR.textSoft)
       .text('RECOMMENDATION', { characterSpacing: 1.2 });
    anchorLeft(doc);
    doc.moveDown(0.15);
    doc.font('Helvetica').fontSize(10).fillColor(COLOR.text)
       .text(f.recommendation, { lineGap: 2, align: 'justify' });
  }

  // Control refs
  if (f.control_refs && f.control_refs.length > 0) {
    anchorLeft(doc);
    doc.moveDown(0.4);
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLOR.textSoft)
       .text('CONTROL REFERENCES', { characterSpacing: 1.2 });
    anchorLeft(doc);
    doc.moveDown(0.15);
    doc.font('Helvetica').fontSize(9).fillColor(COLOR.text)
       .text(f.control_refs.join('  ·  '), { lineGap: 1 });
  }

  // Divider
  anchorLeft(doc);
  doc.moveDown(0.6);
  const divY = doc.y;
  doc.save()
     .moveTo(60, divY).lineTo(doc.page.width - 60, divY)
     .strokeColor(COLOR.border).lineWidth(0.5).stroke().restore();
  doc.moveDown(0.6);
  anchorLeft(doc);
}

// ============================================================
// PPTX — professional deck
// ============================================================
export async function buildPptx(review, meta = {}, options = {}) {
  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';  // 13.33 x 7.5 inches
  pptx.title = `ATLAS Review — ${review.system_name || 'Untitled'}`;
  pptx.author = 'ATLAS';
  pptx.company = 'ATLAS';

  const NAVY = '0E1B2B', GOLD = 'C9A44C', GOLD_SOFT = 'E6D49E';
  const TEXT = '1A1D27', TEXT_SOFT = '52586A', BG_LIGHT = 'F5F6FA', BORDER = 'DDE1EA';
  const CRIT = 'B3253D', HIGH = 'CC5C1B', MED = 'C29A2B', LOW = '3D7C4E';

  const sevColorPPT = s => ({ critical: CRIT, high: HIGH, medium: MED, low: LOW }[s] || TEXT_SOFT);

  // ===== SLIDE 1: COVER =====
  const cover = pptx.addSlide();
  cover.background = { color: NAVY };
  cover.addShape('rect', { x: 0, y: 0, w: 0.15, h: 7.5, fill: { color: GOLD } });
  cover.addText('ATLAS · ARCHITECTURE REVIEW', {
    x: 0.6, y: 2.4, w: 12, h: 0.4,
    fontFace: 'Calibri', fontSize: 12, bold: true, color: GOLD_SOFT, charSpacing: 4,
  });
  cover.addText(review.system_name || 'Architecture Review', {
    x: 0.6, y: 2.9, w: 12, h: 1.6,
    fontFace: 'Calibri', fontSize: 44, bold: true, color: 'FFFFFF',
  });
  cover.addText('Cloud Architecture Security Review', {
    x: 0.6, y: 4.4, w: 12, h: 0.5,
    fontFace: 'Calibri', fontSize: 18, color: GOLD_SOFT,
  });
  cover.addShape('line', {
    x: 0.6, y: 6.4, w: 0.8, h: 0,
    line: { color: GOLD, width: 2 },
  });
  cover.addText(`${today()}   ·   ${meta.provider?.label || 'LLM'}   ·   ${meta.provider?.region || '—'}`, {
    x: 0.6, y: 6.5, w: 10, h: 0.3,
    fontFace: 'Calibri', fontSize: 10, color: 'D8DCE8',
  });
  cover.addText('CONFIDENTIAL', {
    x: 10.5, y: 7.1, w: 2.5, h: 0.3,
    fontFace: 'Calibri', fontSize: 8, color: GOLD_SOFT, charSpacing: 3, align: 'right',
  });

  // ===== SLIDE 2: EXECUTIVE SUMMARY =====
  const s2 = pptx.addSlide();
  addSlideHeader(s2, 'EXECUTIVE SUMMARY', '02');

  const paras = Array.isArray(review.executive_summary)
    ? review.executive_summary
    : review.executive_summary ? [review.executive_summary] : [];

  s2.addText(paras.map(p => ({ text: p, options: { breakLine: true, paraSpaceAfter: 12 } })), {
    x: 0.6, y: 1.5, w: 12.1, h: 5,
    fontFace: 'Calibri', fontSize: 15, color: TEXT, valign: 'top', lineSpacing: 22,
  });

  addSlideFooter(s2, review.system_name || 'Untitled');

  // ===== SLIDE 3: SEVERITY OVERVIEW =====
  const counts = countBySeverity(review.findings);
  const s3 = pptx.addSlide();
  addSlideHeader(s3, 'SEVERITY OVERVIEW', '03');

  const tiles = [
    { label: 'CRITICAL', value: counts.critical, color: CRIT },
    { label: 'HIGH',     value: counts.high,     color: HIGH },
    { label: 'MEDIUM',   value: counts.medium,   color: MED },
    { label: 'LOW',      value: counts.low,      color: LOW },
  ];
  tiles.forEach((t, i) => {
    const x = 0.6 + i * 3.0;
    s3.addShape('rect', { x, y: 2.0, w: 2.8, h: 2.6, fill: { color: BG_LIGHT }, line: { color: BORDER, width: 0.5 } });
    s3.addShape('rect', { x, y: 2.0, w: 0.08, h: 2.6, fill: { color: t.color }, line: { type: 'none' } });
    s3.addText(t.label, { x: x + 0.2, y: 2.2, w: 2.6, h: 0.4, fontFace: 'Calibri', fontSize: 11, bold: true, color: TEXT_SOFT, charSpacing: 3 });
    s3.addText(String(t.value), { x: x + 0.2, y: 2.7, w: 2.6, h: 1.6, fontFace: 'Calibri', fontSize: 60, bold: true, color: TEXT });
  });
  s3.addText(`${counts.total} total findings across all domains`, {
    x: 0.6, y: 5.0, w: 12, h: 0.5,
    fontFace: 'Calibri', fontSize: 14, italic: true, color: TEXT_SOFT,
  });
  addSlideFooter(s3, review.system_name || 'Untitled');

  // ===== SLIDE 4: DOMAIN SCORES =====
  const s4 = pptx.addSlide();
  addSlideHeader(s4, 'DOMAIN MATURITY', '04');

  const scoreEntries = Object.keys(DOMAIN_LABELS).map(d => {
    const s = (review.domain_scores || {})[d] || { score: 0, finding_count: 0 };
    return { domain: DOMAIN_LABELS[d], score: s.score || 0, count: s.finding_count || 0 };
  });

  scoreEntries.forEach((e, i) => {
    const y = 1.6 + i * 1.1;
    s4.addText(e.domain, { x: 0.6, y: y, w: 2.8, h: 0.4, fontFace: 'Calibri', fontSize: 14, bold: true, color: TEXT });
    // Bar background
    s4.addShape('rect', { x: 3.6, y: y + 0.08, w: 7.5, h: 0.25, fill: { color: 'ECEEF5' }, line: { type: 'none' } });
    // Fill
    const fillC = e.score >= 80 ? LOW : e.score >= 60 ? MED : e.score >= 40 ? HIGH : CRIT;
    const w = Math.max(0.01, 7.5 * e.score / 100);
    s4.addShape('rect', { x: 3.6, y: y + 0.08, w, h: 0.25, fill: { color: fillC }, line: { type: 'none' } });
    s4.addText(`${e.score} / 100`, { x: 11.2, y, w: 1.3, h: 0.4, fontFace: 'Calibri', fontSize: 14, bold: true, color: TEXT, align: 'right' });
    s4.addText(`${e.count} finding${e.count === 1 ? '' : 's'}`, { x: 0.6, y: y + 0.35, w: 2.8, h: 0.3, fontFace: 'Calibri', fontSize: 10, color: TEXT_SOFT });
  });

  addSlideFooter(s4, review.system_name || 'Untitled');

  // ===== SLIDES: TOP FINDINGS (one per slide, up to 8) =====
  const topFindings = [...(review.findings || [])]
    .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    .slice(0, 8);

  topFindings.forEach((f, idx) => {
    const s = pptx.addSlide();
    addSlideHeader(s, `FINDING ${String(idx + 1).padStart(2, '0')}`, String(idx + 5).padStart(2, '0'));

    // Severity pill
    const sevText = sevLabel(f.severity);
    s.addShape('roundRect', {
      x: 0.6, y: 1.55, w: 1.2, h: 0.35,
      fill: { color: sevColorPPT(f.severity) },
      line: { type: 'none' }, rectRadius: 0.05,
    });
    s.addText(sevText, {
      x: 0.6, y: 1.55, w: 1.2, h: 0.35,
      fontFace: 'Calibri', fontSize: 10, bold: true, color: 'FFFFFF', align: 'center', valign: 'middle', charSpacing: 2,
    });
    s.addText(f.id || '', {
      x: 1.9, y: 1.55, w: 2, h: 0.35,
      fontFace: 'Consolas', fontSize: 11, color: TEXT_SOFT, valign: 'middle',
    });

    // Title
    s.addText(f.title || '(untitled)', {
      x: 0.6, y: 2.0, w: 12, h: 0.9,
      fontFace: 'Calibri', fontSize: 24, bold: true, color: NAVY, lineSpacing: 28,
    });

    // Finding body
    if (f.finding) {
      s.addText('FINDING', {
        x: 0.6, y: 3.0, w: 3, h: 0.3, fontFace: 'Calibri', fontSize: 10, bold: true, color: TEXT_SOFT, charSpacing: 3,
      });
      s.addText(f.finding, {
        x: 0.6, y: 3.3, w: 12.1, h: 1.3, fontFace: 'Calibri', fontSize: 13, color: TEXT, valign: 'top', lineSpacing: 20,
      });
    }

    if (f.recommendation) {
      s.addText('RECOMMENDATION', {
        x: 0.6, y: 4.7, w: 3, h: 0.3, fontFace: 'Calibri', fontSize: 10, bold: true, color: TEXT_SOFT, charSpacing: 3,
      });
      s.addText(f.recommendation, {
        x: 0.6, y: 5.0, w: 12.1, h: 1.3, fontFace: 'Calibri', fontSize: 13, color: TEXT, valign: 'top', lineSpacing: 20,
      });
    }

    if (f.control_refs && f.control_refs.length > 0) {
      s.addText(`Controls: ${f.control_refs.join('  ·  ')}`, {
        x: 0.6, y: 6.45, w: 12, h: 0.3,
        fontFace: 'Consolas', fontSize: 10, color: TEXT_SOFT, italic: true,
      });
    }

    addSlideFooter(s, review.system_name || 'Untitled');
  });

  // ===== FINAL SLIDE: RECOMMENDATIONS =====
  if (topFindings.length > 0) {
    const sr = pptx.addSlide();
    addSlideHeader(sr, 'PRIORITY REMEDIATION', String(topFindings.length + 5).padStart(2, '0'));
    const now = topFindings.filter(f => f.severity === 'critical');
    const sprint = topFindings.filter(f => f.severity === 'high');
    const cells = [
      { label: 'IMMEDIATE', desc: 'Within 2 weeks', list: now, color: CRIT },
      { label: 'THIS SPRINT', desc: '0–30 days', list: sprint, color: HIGH },
    ];
    cells.forEach((c, i) => {
      const x = 0.6 + i * 6.3;
      sr.addShape('rect', { x, y: 1.6, w: 6.0, h: 5.2, fill: { color: BG_LIGHT }, line: { color: BORDER, width: 0.5 } });
      sr.addShape('rect', { x, y: 1.6, w: 0.1, h: 5.2, fill: { color: c.color }, line: { type: 'none' } });
      sr.addText(c.label, { x: x + 0.25, y: 1.8, w: 5.6, h: 0.4, fontFace: 'Calibri', fontSize: 14, bold: true, color: c.color, charSpacing: 2 });
      sr.addText(c.desc, { x: x + 0.25, y: 2.2, w: 5.6, h: 0.3, fontFace: 'Calibri', fontSize: 11, color: TEXT_SOFT });

      if (c.list.length === 0) {
        sr.addText('— none —', { x: x + 0.25, y: 2.8, w: 5.6, h: 0.4, fontFace: 'Calibri', fontSize: 11, italic: true, color: TEXT_SOFT });
      } else {
        const itemsText = c.list.slice(0, 5).map(f => ({
          text: `${f.id}  ${f.title}\n`,
          options: { bold: true, color: TEXT, fontSize: 11, breakLine: false },
        })).flatMap(x => [x, { text: '', options: { breakLine: true } }]);

        sr.addText(c.list.slice(0, 5).map(f => `${f.id}  ${f.title}`).join('\n'), {
          x: x + 0.25, y: 2.7, w: 5.6, h: 4.0,
          fontFace: 'Calibri', fontSize: 12, color: TEXT, valign: 'top', lineSpacing: 18, bullet: { type: 'bullet' }, paraSpaceAfter: 6,
        });
      }
    });
    addSlideFooter(sr, review.system_name || 'Untitled');
  }

  // Helpers for headers/footers
  function addSlideHeader(slide, title, num) {
    slide.background = { color: 'FFFFFF' };
    slide.addShape('rect', { x: 0, y: 0, w: 13.33, h: 0.9, fill: { color: NAVY }, line: { type: 'none' } });
    slide.addShape('rect', { x: 0, y: 0.9, w: 13.33, h: 0.06, fill: { color: GOLD }, line: { type: 'none' } });
    slide.addText(num, { x: 0.6, y: 0.25, w: 0.8, h: 0.4, fontFace: 'Calibri', fontSize: 14, bold: true, color: GOLD, charSpacing: 2 });
    slide.addText(title, { x: 1.5, y: 0.2, w: 11, h: 0.5, fontFace: 'Calibri', fontSize: 16, bold: true, color: 'FFFFFF', charSpacing: 3 });
  }

  function addSlideFooter(slide, systemName) {
    slide.addText(`ATLAS · ${systemName}`, {
      x: 0.6, y: 7.15, w: 10, h: 0.25, fontFace: 'Calibri', fontSize: 9, color: TEXT_SOFT,
    });
    slide.addText(today(), {
      x: 10, y: 7.15, w: 3, h: 0.25, fontFace: 'Calibri', fontSize: 9, color: TEXT_SOFT, align: 'right',
    });
  }

  const buf = await pptx.write({ outputType: 'nodebuffer' });
  return buf;
}
