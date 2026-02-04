import cors from "cors";
import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";

import crypto from "node:crypto";
import { createRequire } from "node:module";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const require = createRequire(import.meta.url);

function tryRequireNodemailer() {
  try {
    // nodemailer is optional for endpoints that send email
    return require("nodemailer");
  } catch {
    return null;
  }
}

const app = express();

/**
 * ✅ REQUIRED on Render / any reverse-proxy host
 * Fixes express-rate-limit 500 errors caused by X-Forwarded-For headers.
 */
app.set("trust proxy", 1);
const PORT = Number(process.env.PORT || 8787);

// ---------- Body parsing ----------
app.use(express.json({ limit: "1mb" }));

// ---------- CORS ----------
const allowedOrigins = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    const isDev = process.env.NODE_ENV !== "production";
    const isLocalhost =
      origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:");

    const isLan =
      /^http:\/\/192\.168\.\d{1,3}\.\d{1,3}:\d+$/.test(origin) ||
      /^http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(origin) ||
      /^http:\/\/172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}:\d+$/.test(origin);

    if (allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    if (isDev && (isLocalhost || isLan)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Admin-Key"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ---------- Rate limiting ----------
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
});

const careersLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
});

const proposalsTokenLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

const proposalsViewLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
});

const newsletterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const decisionFeedbackLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- Health ----------
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// ---------- Mail transporter ----------
function createTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure =
    String(process.env.SMTP_SECURE || "").toLowerCase() === "true" || port === 465;

  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error(
      "Missing SMTP env. Required: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS"
    );
  }

  const nodemailer = tryRequireNodemailer();
  if (!nodemailer) {
    throw new Error("Email service is temporarily unavailable");
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}

// =====================================================
// ✅ NEWSLETTER: subscribe / unsubscribe / send (admin)
// =====================================================

// Data directory (documents + small JSON indices)
// In production, set DATA_DIR to a persistent disk mount path (e.g. /var/data on Render).
let DATA_DIR =
  process.env.DATA_DIR ||
  process.env.RENDER_DISK_PATH ||
  process.env.DISK_PATH ||
  (process.env.RENDER === "true" ? "/var/data" : path.join(__dirname, "data"));

DATA_DIR = path.resolve(DATA_DIR);

// Ensure DATA_DIR is writable. If not, fall back to backend/data to avoid 500s in prod.
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.accessSync(DATA_DIR, fs.constants.W_OK);
} catch (err) {
  console.warn("DATA_DIR_NOT_WRITABLE: falling back to local backend/data", {
    dataDir: DATA_DIR,
    error: err?.message || String(err),
  });
  DATA_DIR = path.resolve(path.join(__dirname, "data"));
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  } catch (e2) {
    console.error("DATA_DIR_FALLBACK_FAILED:", e2);
  }
}

const NEWSLETTER_FILE = path.join(DATA_DIR, "newsletter_subscribers.json");


// =====================================================
// ✅ DECISION FEEDBACK: store documents + index (file DB)
// =====================================================

const DECISION_FEEDBACK_DOCS_DIR = path.join(DATA_DIR, "decision_feedback_docs");
const DECISION_FEEDBACK_INDEX_FILE = path.join(DATA_DIR, "decision_feedback_index.json");

async function writeFileAtomic(filePath, content) {
  const dir = path.dirname(filePath);
  await fsPromises.mkdir(dir, { recursive: true });
  const tmp = `${filePath}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  await fsPromises.writeFile(tmp, content, "utf-8");
  await fsPromises.rename(tmp, filePath);
}

async function ensureDecisionFeedbackStore() {
  await fsPromises.mkdir(DECISION_FEEDBACK_DOCS_DIR, { recursive: true });
  try {
    await fsPromises.access(DECISION_FEEDBACK_INDEX_FILE);
  } catch {
    await writeFileAtomic(DECISION_FEEDBACK_INDEX_FILE, JSON.stringify([], null, 2));
  }
}

async function readDecisionFeedbackIndex() {
  await ensureDecisionFeedbackStore();
  const raw = await fsPromises.readFile(DECISION_FEEDBACK_INDEX_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeDecisionFeedbackIndex(list) {
  await ensureDecisionFeedbackStore();
  const safe = Array.isArray(list) ? list : [];
  await writeFileAtomic(DECISION_FEEDBACK_INDEX_FILE, JSON.stringify(safe, null, 2));
}

function buildDecisionFeedbackMarkdown(doc) {
  const p = doc?.payload || {};
  const lines = [];
  lines.push(`# Decision Feedback`);
  lines.push("");
  lines.push(`**Document ID:** ${doc.id}`);
  lines.push(`**Created:** ${doc.createdAt}`);
  lines.push(`**Client:** ${doc.clientName}`);
  lines.push("");

  const pushField = (label, value) => {
    const v = typeof value === "string" ? value.trim() : value;
    if (v === undefined || v === null || v === "") return;
    lines.push(`**${label}:** ${String(v).replace(/\n+/g, " ")}`);
  };

  pushField("Anonymous", p.anonymous ? "Yes" : "No");
  pushField("Company/Name", p.companyOrName);
  pushField("Email", p.email);
  pushField("Project type", p.projectType);
  pushField("Stage", p.stage);
  pushField("Budget", p.budgetRange);
  pushField("Timeline", p.timeline);
  pushField("Overall score", p.overallScore);
  pushField("Trust score", p.trustScore);

  if (Array.isArray(p.decisionFactors) && p.decisionFactors.length) {
    lines.push("");
    lines.push("## Decision factors");
    for (const f of p.decisionFactors) lines.push(`- ${String(f)}`);
  }

  pushField("Other factor", p.otherFactor);
  pushField("Alternative / competitor", p.competitorOrAlternative);

  if (p.biggestPositive) {
    lines.push("");
    lines.push("## Biggest positive");
    lines.push(String(p.biggestPositive).trim());
  }

  if (p.improvementNotes) {
    lines.push("");
    lines.push("## Improvement notes");
    lines.push(String(p.improvementNotes).trim());
  }

  pushField("Reconsider", p.reconsider);
  if (p.openToFollowUp) {
    pushField("Follow up", p.followUpMethod);
    pushField("Contact", p.followUpContact);
    pushField("Timezone", p.followUpTimezone);
  }

  lines.push("");
  lines.push("---");
  lines.push("_Generated by HazeEdge feedback intake._");
  return lines.join("\n");
}

async function ensureNewsletterFile() {
  await fsPromises.mkdir(DATA_DIR, { recursive: true });
  try {
    await fsPromises.access(NEWSLETTER_FILE);
  } catch {
    await fsPromises.writeFile(NEWSLETTER_FILE, JSON.stringify([], null, 2), "utf-8");
  }
}

async function readNewsletterSubscribers() {
  await ensureNewsletterFile();
  const raw = await fsPromises.readFile(NEWSLETTER_FILE, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeNewsletterSubscribers(list) {
  await ensureNewsletterFile();
  await fsPromises.writeFile(NEWSLETTER_FILE, JSON.stringify(list, null, 2), "utf-8");
}

function normalizeEmail(v) {
  return String(v || "").trim().toLowerCase();
}

function isValidEmail(v) {
  const email = normalizeEmail(v);
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function publicBaseUrl() {
  const base =
    process.env.PUBLIC_BASE_URL ||
    process.env.PUBLIC_SITE_URL ||
    `http://localhost:${PORT}`;
  return String(base).replace(/\/$/, "");
}

function unsubscribeUrl(token) {
  return `${publicBaseUrl()}/api/newsletter/unsubscribe?token=${encodeURIComponent(token)}`;
}

// 1) Subscribe
app.post("/api/newsletter/subscribe", newsletterLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    const normalized = normalizeEmail(email);
    const now = new Date().toISOString();

    const list = await readNewsletterSubscribers();
    const idx = list.findIndex((s) => normalizeEmail(s?.email) === normalized);

    let token;
    if (idx === -1) {
      token = crypto.randomBytes(24).toString("hex");
      list.push({
        email: normalized,
        status: "active",
        token,
        created_at: now,
        updated_at: now,
      });
    } else {
      const cur = list[idx] || {};
      const wasUnsubscribed = String(cur.status || "") !== "active";

      token = wasUnsubscribed
        ? crypto.randomBytes(24).toString("hex")
        : cur.token || crypto.randomBytes(24).toString("hex");

      list[idx] = {
        ...cur,
        email: normalized,
        status: "active",
        token,
        unsubscribed_at: wasUnsubscribed ? null : cur.unsubscribed_at || null,
        updated_at: now,
      };
    }

    await writeNewsletterSubscribers(list);

    // Optional: welcome email (deterministic test + includes unsubscribe link)
    const sendWelcome =
      String(process.env.NEWSLETTER_SEND_WELCOME || "true").toLowerCase() !== "false";

    if (sendWelcome) {
      try {
        const transporter = createTransporter();
        const to = normalized;
        const from =
          process.env.NEWSLETTER_FROM ||
          process.env.FROM_EMAIL ||
          process.env.SMTP_USER ||
          process.env.COMPANY_EMAIL ||
          "contact@hazeedge.com";

        const unsub = unsubscribeUrl(token);

        await transporter.sendMail({
          from,
          to,
          subject: "You're subscribed — HazeEdge updates",
          text: `You're subscribed to HazeEdge updates.\n\nUnsubscribe anytime: ${unsub}`,
          html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
              <h2>You're subscribed</h2>
              <p>Thanks for subscribing. We'll email you when we publish new insights, playbooks, and research.</p>
              <p style="margin-top:16px; font-size:12px; color:#555;">
                Unsubscribe anytime: <a href="${unsub}">Unsubscribe</a>
              </p>
            </div>
          `,
        });
      } catch (e) {
        console.error("NEWSLETTER_WELCOME_EMAIL_ERROR:", e);
      }
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("NEWSLETTER_SUBSCRIBE_ERROR:", err);
    return res.status(500).json({ error: "Server failed to subscribe" });
  }
});

// 2) Unsubscribe
app.get("/api/newsletter/unsubscribe", async (req, res) => {
  try {
    const token = typeof req.query?.token === "string" ? req.query.token : "";
    const now = new Date().toISOString();

    if (token) {
      const list = await readNewsletterSubscribers();
      const idx = list.findIndex((s) => String(s?.token || "") === token);
      if (idx !== -1) {
        list[idx] = {
          ...list[idx],
          status: "unsubscribed",
          unsubscribed_at: now,
          updated_at: now,
        };
        await writeNewsletterSubscribers(list);
      }
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(`
      <!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <title>Unsubscribed</title>
          <style>
            body{font-family:Arial,sans-serif;background:#f6f7fb;margin:0;padding:40px;color:#0f172a;}
            .card{max-width:640px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(2,6,23,.06)}
            h1{margin:0 0 10px;font-size:22px}
            p{margin:0 0 14px;line-height:1.6;color:#334155}
            a{color:#004aad;text-decoration:none}
            a:hover{text-decoration:underline}
          </style>
        </head>
        <body>
          <div class="card">
            <h1>You're unsubscribed</h1>
            <p>You will no longer receive HazeEdge updates.</p>
            <p><a href="${publicBaseUrl()}">Return to HazeEdge</a></p>
          </div>
        </body>
      </html>
    `);
  } catch (err) {
    console.error("NEWSLETTER_UNSUBSCRIBE_ERROR:", err);
    return res.status(500).json({ error: "Server failed to unsubscribe" });
  }
});

// 3) Send newsletter to all active subscribers (admin-only)
// Use header: X-Admin-Key: <NEWSLETTER_ADMIN_KEY>
app.post("/api/newsletter/send", async (req, res) => {
  try {
    const adminKey = process.env.NEWSLETTER_ADMIN_KEY;
    if (!adminKey) {
      return res.status(501).json({
        error: "Set NEWSLETTER_ADMIN_KEY in backend/.env to enable sending.",
      });
    }

    const incomingKey = String(req.headers["x-admin-key"] || "");
    if (incomingKey !== adminKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { subject, html, text } = req.body || {};

    if (!subject || typeof subject !== "string") {
      return res.status(400).json({ error: "Missing required field: subject" });
    }

    if (!html && !text) {
      return res.status(400).json({ error: "Provide html and/or text" });
    }

    const list = await readNewsletterSubscribers();
    const active = list.filter((s) => s?.status === "active" && isValidEmail(s?.email));

    const transporter = createTransporter();
    const from =
      process.env.NEWSLETTER_FROM ||
      process.env.FROM_EMAIL ||
      process.env.SMTP_USER ||
      process.env.COMPANY_EMAIL ||
      "contact@hazeedge.com";

    let sent = 0;
    let failed = 0;

    for (const sub of active) {
      try {
        const unsub = unsubscribeUrl(sub.token);

        const footerHtml = `
          <hr style="margin:24px 0;border:0;border-top:1px solid #e5e7eb"/>
          <p style="font-size:12px;color:#64748b;margin:0;">
            You're receiving this because you subscribed on HazeEdge.
            <a href="${unsub}">Unsubscribe</a>
          </p>
        `;

        const finalHtml = `${html ? String(html) : `<p>${escapeHtml(text || "")}</p>`}${footerHtml}`;
        const finalText = `${text ? String(text) : ""}\n\nUnsubscribe: ${unsub}`.trim();

        await transporter.sendMail({
          from,
          to: normalizeEmail(sub.email),
          subject: String(subject),
          ...(finalHtml ? { html: finalHtml } : {}),
          ...(finalText ? { text: finalText } : {}),
        });

        sent += 1;
      } catch (e) {
        failed += 1;
        console.error("NEWSLETTER_SEND_ONE_ERROR:", e);
      }
    }

    return res.json({ ok: true, sent, failed });
  } catch (err) {
    console.error("NEWSLETTER_SEND_ERROR:", err);
    return res.status(500).json({ error: "Server failed to send newsletter" });
  }
});



// =====================================================
// ✅ DECISION FEEDBACK: intake endpoint
// Stores:
// 1) A feedback document (JSON + Markdown) in decision_feedback_docs/
// 2) An index DB (JSON) with { clientName, docId, createdAt }
// =====================================================

app.post("/api/decision-feedback", decisionFeedbackLimiter, async (req, res) => {
  try {
    const payload = req.body || {};
    const createdAt = new Date().toISOString();

    const docId = typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString("hex");

    const isAnonymous = Boolean(payload?.anonymous);
    const companyOrName = String(payload?.companyOrName || "").trim();
    const email = String(payload?.email || "").trim();

    const clientName = isAnonymous
      ? "Anonymous"
      : (companyOrName || email || "Unknown");

    await ensureDecisionFeedbackStore();

    const doc = {
      id: docId,
      createdAt,
      clientName,
      payload,
      meta: {
        ip: req.ip,
        userAgent: String(req.get("user-agent") || ""),
      },
    };

    const jsonPath = path.join(DECISION_FEEDBACK_DOCS_DIR, `${docId}.json`);
    const mdPath = path.join(DECISION_FEEDBACK_DOCS_DIR, `${docId}.md`);

    await writeFileAtomic(jsonPath, JSON.stringify(doc, null, 2));
    await writeFileAtomic(mdPath, buildDecisionFeedbackMarkdown(doc));

    const index = await readDecisionFeedbackIndex();
    index.push({ id: docId, clientName, createdAt });
    await writeDecisionFeedbackIndex(index);

    return res.json({ ok: true, id: docId, createdAt });
  } catch (err) {
    console.error("DECISION_FEEDBACK_ERROR:", err);
    return res.status(500).json({ error: "Server failed to store feedback" });
  }
});

// -----------------------------------------------------
// ✅ DECISION FEEDBACK (admin): list + fetch documents
// Protect using header: X-Admin-Key: <DECISION_FEEDBACK_ADMIN_KEY>
// -----------------------------------------------------

function requireDecisionFeedbackAdmin(req, res) {
  const adminKey =
    process.env.DECISION_FEEDBACK_ADMIN_KEY ||
    process.env.ADMIN_KEY ||
    "";
  if (!adminKey) {
    return res
      .status(501)
      .json({ error: "Admin access not configured" });
  }
  const incoming = String(req.headers["x-admin-key"] || "");
  if (incoming !== adminKey) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return null;
}

// List index (supports ?q=search)
app.get("/api/decision-feedback/admin/list", async (req, res) => {
  const deny = requireDecisionFeedbackAdmin(req, res);
  if (deny) return;

  try {
    const q = String(req.query?.q || "").trim().toLowerCase();
    const index = await readDecisionFeedbackIndex();
    const filtered = q
      ? index.filter((r) => String(r?.clientName || "").toLowerCase().includes(q))
      : index;

    const sorted = [...filtered].sort((a, b) =>
      String(b?.createdAt || "").localeCompare(String(a?.createdAt || ""))
    );

    return res.json({ ok: true, count: sorted.length, items: sorted });
  } catch (err) {
    console.error("DECISION_FEEDBACK_ADMIN_LIST_ERROR:", err);
    return res.status(500).json({ error: "Failed to read index" });
  }
});

// Fetch a document by id
// Defaults to markdown. Use ?format=json for JSON.
app.get("/api/decision-feedback/admin/doc/:id", async (req, res) => {
  const deny = requireDecisionFeedbackAdmin(req, res);
  if (deny) return;

  try {
    const id = String(req.params?.id || "").trim();
    if (!id) return res.status(400).json({ error: "Missing id" });

    const format = String(req.query?.format || "md").toLowerCase();
    const isJson = format === "json";
    const filePath = path.join(
      DECISION_FEEDBACK_DOCS_DIR,
      `${id}.${isJson ? "json" : "md"}`
    );

    const content = await fsPromises.readFile(filePath, "utf-8");
    res.setHeader(
      "Content-Type",
      isJson ? "application/json; charset=utf-8" : "text/markdown; charset=utf-8"
    );

    // Optional: force download via ?download=1
    if (String(req.query?.download || "") === "1") {
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${id}.${isJson ? "json" : "md"}"`
      );
    }

    return res.status(200).send(content);
  } catch (err) {
    if (String(err?.code || "") === "ENOENT") {
      return res.status(404).json({ error: "Document not found" });
    }
    console.error("DECISION_FEEDBACK_ADMIN_DOC_ERROR:", err);
    return res.status(500).json({ error: "Failed to read document" });
  }
});

// ---------- Contact endpoint ----------
app.post("/api/contact", contactLimiter, async (req, res) => {
  try {
    const { name, workEmail, company = "", role = "", budget = "", message } = req.body || {};

    if (!name || !workEmail || !message) {
      return res.status(400).json({
        error: "Missing required fields: name, workEmail, message",
      });
    }

    const to = process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.SMTP_USER || to;

    const subject = `New website message: ${name}${company ? ` (${company})` : ""}`;

    const text = [
      "New contact form submission",
      "--------------------------",
      `Name: ${name}`,
      `Work Email: ${workEmail}`,
      `Company: ${company || "-"}`,
      `Role: ${role || "-"}`,
      `Budget: ${budget || "-"}`,
      "",
      "Message:",
      message,
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.5;">
        <h2>New contact form submission</h2>
        <hr/>
        <p><b>Name:</b> ${escapeHtml(name)}</p>
        <p><b>Work Email:</b> ${escapeHtml(workEmail)}</p>
        <p><b>Company:</b> ${escapeHtml(company || "-")}</p>
        <p><b>Role:</b> ${escapeHtml(role || "-")}</p>
        <p><b>Budget:</b> ${escapeHtml(budget || "-")}</p>
        <h3>Message</h3>
        <pre style="white-space: pre-wrap; background:#f7f7f7; padding:12px; border-radius:8px;">${escapeHtml(
          message
        )}</pre>
      </div>
    `;

    const transporter = createTransporter();

    await transporter.sendMail({
      from,
      to,
      replyTo: workEmail,
      subject,
      text,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("CONTACT_SEND_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to send email",
      detail:
        process.env.NODE_ENV !== "production" ? (err?.message || String(err)) : undefined,
    });
  }
});

// ---------- Careers: role-specific application ----------
app.post("/api/careers/apply", careersLimiter, async (req, res) => {
  try {
    const {
      roleId = "",
      roleTitle,
      name,
      email,
      linkedin = "",
      resumeUrl = "",
      note = "",
      acceptedPolicies = false,
    } = req.body || {};

    if (!roleTitle || !name || !email) {
      return res.status(400).json({
        error: "Missing required fields: roleTitle, name, email",
      });
    }

    if (!acceptedPolicies) {
      return res.status(400).json({
        error: "You must accept Terms & Privacy to submit.",
      });
    }

    const to =
      process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.SMTP_USER || to;

    const subject = `Application for "${String(roleTitle).trim()}"`;

    const text = [
      "New career application (Posting)",
      "-------------------------------",
      `Posting: ${roleTitle}`,
      `Role ID: ${roleId || "-"}`,
      "",
      `Applicant: ${name}`,
      `Email: ${email}`,
      `LinkedIn/GitHub: ${linkedin || "-"}`,
      `Resume URL: ${resumeUrl || "-"}`,
      `Accepted Terms/Privacy: Yes`,
      "",
      "Why HazeEdge:",
      note || "-",
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.5;">
        <h2>New career application (Posting)</h2>
        <hr/>
        <p><b>Posting:</b> ${escapeHtml(roleTitle)}</p>
        <p><b>Role ID:</b> ${escapeHtml(roleId || "-")}</p>

        <h3>Applicant</h3>
        <p><b>Name:</b> ${escapeHtml(name)}</p>
        <p><b>Email:</b> ${escapeHtml(email)}</p>
        <p><b>LinkedIn/GitHub:</b> ${escapeHtml(linkedin || "-")}</p>
        <p><b>Resume URL:</b> ${
          resumeUrl
            ? `<a href="${escapeHtml(resumeUrl)}">${escapeHtml(resumeUrl)}</a>`
            : "-"
        }</p>
        <p><b>Accepted Terms/Privacy:</b> Yes</p>

        <h3>Why HazeEdge?</h3>
        <pre style="white-space: pre-wrap; background:#f7f7f7; padding:12px; border-radius:8px;">${escapeHtml(
          note || "-"
        )}</pre>
      </div>
    `;

    const transporter = createTransporter();

    await transporter.sendMail({
      from,
      to,
      replyTo: email,
      subject,
      text,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("CAREERS_APPLY_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to send application email",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

// ---------- Careers: general application ----------
app.post("/api/careers/general", careersLimiter, async (req, res) => {
  try {
    const {
      name,
      email,
      roleInterest = "",
      linkedin = "",
      note = "",
      acceptedPolicies = false,
    } = req.body || {};

    if (!name || !email) {
      return res.status(400).json({
        error: "Missing required fields: name, email",
      });
    }

    if (!acceptedPolicies) {
      return res.status(400).json({
        error: "You must accept Terms & Privacy to submit.",
      });
    }

    const to =
      process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.SMTP_USER || to;

    const cleanedRole = String(roleInterest || "").trim();
    const subject = cleanedRole
      ? `General Application — ${cleanedRole}`
      : "General Application";

    const text = [
      "New career application (General)",
      "-------------------------------",
      `Role of Interest: ${cleanedRole || "-"}`,
      "",
      `Applicant: ${name}`,
      `Email: ${email}`,
      `LinkedIn/GitHub: ${linkedin || "-"}`,
      `Accepted Terms/Privacy: Yes`,
      "",
      "Why HazeEdge:",
      note || "-",
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.5;">
        <h2>New career application (General)</h2>
        <hr/>
        <p><b>Role of Interest:</b> ${escapeHtml(cleanedRole || "-")}</p>

        <h3>Applicant</h3>
        <p><b>Name:</b> ${escapeHtml(name)}</p>
        <p><b>Email:</b> ${escapeHtml(email)}</p>
        <p><b>LinkedIn/GitHub:</b> ${escapeHtml(linkedin || "-")}</p>
        <p><b>Accepted Terms/Privacy:</b> Yes</p>

        <h3>Why HazeEdge?</h3>
        <pre style="white-space: pre-wrap; background:#f7f7f7; padding:12px; border-radius:8px;">${escapeHtml(
          note || "-"
        )}</pre>
      </div>
    `;

    const transporter = createTransporter();

    await transporter.sendMail({
      from,
      to,
      replyTo: email,
      subject,
      text,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("CAREERS_GENERAL_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to send general application email",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

// ===============================
// ✅ PROPOSALS: view-only endpoint
// ===============================

const PROPOSALS_DIR = path.join(__dirname, "private", "proposals");
const TOKEN_SECRET = process.env.PROPOSAL_TOKEN_SECRET || "";
const TOKEN_TTL_SECONDS = Number(process.env.PROPOSAL_TOKEN_TTL_SECONDS || 120);

function isSafeKey(key) {
  return typeof key === "string" && /^[a-z0-9_-]+$/i.test(key);
}

function signToken(payloadObj) {
  if (!TOKEN_SECRET) throw new Error("Missing PROPOSAL_TOKEN_SECRET");
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(payloadB64).digest("base64url");
  return `${payloadB64}.${sig}`;
}

function verifyToken(token) {
  if (!TOKEN_SECRET) return { ok: false, error: "Server not configured" };
  if (!token || typeof token !== "string") return { ok: false, error: "Missing token" };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "Bad token format" };

  const [payloadB64, sig] = parts;
  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(payloadB64).digest("base64url");

  // timing-safe compare
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return { ok: false, error: "Invalid token" };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, error: "Invalid token" };

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return { ok: false, error: "Invalid token payload" };
  }

  if (!payload || typeof payload !== "object") return { ok: false, error: "Invalid token payload" };
  if (!payload.docKey || !isSafeKey(payload.docKey)) return { ok: false, error: "Invalid docKey" };
  if (!payload.exp || typeof payload.exp !== "number") return { ok: false, error: "Invalid exp" };

  const now = Math.floor(Date.now() / 1000);
  if (now > payload.exp) return { ok: false, error: "Token expired" };

  return { ok: true, payload };
}

// 1) Get a short-lived token for a proposal
app.post("/api/proposals/token", proposalsTokenLimiter, (req, res) => {
  try {
    const { docKey } = req.body || {};
    if (!isSafeKey(docKey)) return res.status(400).json({ error: "Invalid docKey" });

    const filePath = path.join(PROPOSALS_DIR, `${docKey}.pdf`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Proposal not found" });

    const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
    const token = signToken({ docKey, exp });

    return res.json({ token, exp });
  } catch (e) {
    console.error("PROPOSAL_TOKEN_ERROR:", e);
    return res.status(500).json({ error: "Failed to issue token" });
  }
});

// 2) Stream the PDF (no-store + inline). Frontend should fetch and render it.
app.get("/api/proposals/:docKey", proposalsViewLimiter, (req, res) => {
  try {
    const docKey = req.params.docKey;
    const token = String(req.query.token || "");

    if (!isSafeKey(docKey)) return res.status(400).json({ error: "Invalid docKey" });

    const v = verifyToken(token);
    if (!v.ok) return res.status(401).json({ error: v.error || "Unauthorized" });
    if (v.payload.docKey !== docKey) return res.status(401).json({ error: "Token doc mismatch" });

    const filePath = path.join(PROPOSALS_DIR, `${docKey}.pdf`);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Proposal not found" });

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `inline; filename="${docKey}.pdf"`);

    // “view-only” style headers (deterrents + no caching)
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cross-Origin-Resource-Policy", "same-site");

    // Stream file
    const stream = fs.createReadStream(filePath);
    stream.on("error", (err) => {
      console.error("PROPOSAL_STREAM_ERROR:", err);
      res.status(500).end();
    });
    stream.pipe(res);
  } catch (e) {
    console.error("PROPOSAL_VIEW_ERROR:", e);
    return res.status(500).json({ error: "Failed to serve proposal" });
  }
});

// ---------- Error handler ----------
app.use((err, _req, res, _next) => {
  console.error("UNHANDLED_ERROR:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`HazeEdge local backend running on http://localhost:${PORT}`);
});

// ---------- helper ----------
function escapeHtml(input) {
  return String(input)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
