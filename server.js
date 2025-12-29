import cors from "cors";
import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 8787);

// ✅ REQUIRED on Render / reverse-proxy hosts (Cloudflare/Render/etc.)
// Set TRUST_PROXY in Render env (usually 1–3). Start with 2 if unsure.
app.set("trust proxy", Number(process.env.TRUST_PROXY || 2));

// ---------- Body parsing ----------
app.use(express.json({ limit: "1mb" }));

// ---------- CORS ----------
const allowedOrigins = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function normalizeOrigin(o) {
  if (!o) return "";
  return String(o).trim().replace(/\/+$/, "");
}
function stripProto(o) {
  return normalizeOrigin(o).replace(/^https?:\/\//i, "");
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true); // curl / server-to-server

    const o = normalizeOrigin(origin);
    const oNoProto = stripProto(o);

    // ✅ allow exact whitelist (+ tolerate missing scheme in env)
    if (allowedOrigins.length > 0) {
      const ok =
        allowedOrigins.some((x) => normalizeOrigin(x) === o) ||
        allowedOrigins.some((x) => stripProto(x) === oNoProto);
      if (ok) return callback(null, true);
    }

    // ✅ dev convenience
    const isDev = process.env.NODE_ENV !== "production";
    const isLocalhost =
      o.startsWith("http://localhost:") || o.startsWith("http://127.0.0.1:");
    const isLan =
      /^http:\/\/192\.168\.\d{1,3}\.\d{1,3}:\d+$/.test(o) ||
      /^http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(o) ||
      /^http:\/\/172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}:\d+$/.test(o);

    if (isDev && (isLocalhost || isLan)) return callback(null, true);

    return callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
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
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

// ---------- Health ----------
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// ✅ TEMP DEBUG (remove later)
app.get("/api/debug/ip", (req, res) => {
  res.json({
    ip: req.ip,
    ips: req.ips,
    xForwardedFor: req.headers["x-forwarded-for"] || null,
    cfConnectingIp: req.headers["cf-connecting-ip"] || null,
    remoteAddress: req.socket?.remoteAddress || null,
    trustProxy: req.app.get("trust proxy"),
  });
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
    throw new Error("Missing SMTP env. Required: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS");
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },

    // ✅ prevents long hangs (and Netlify/CF timeouts)
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 20_000,
  });
}

function shouldExposeErrorDetails() {
  return process.env.NODE_ENV !== "production" || String(process.env.EXPOSE_ERROR_DETAILS) === "true";
}

function formatErr(err) {
  const e = err || {};
  return {
    message: e?.message || String(err),
    code: e?.code,
    command: e?.command,
    response: e?.response,
    responseCode: e?.responseCode,
  };
}

function isValidEmail(email) {
  const s = String(email || "").trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

// ---------- Contact endpoint ----------
app.post("/api/contact", contactLimiter, async (req, res) => {
  try {
    const { name, workEmail, company = "", role = "", budget = "", message } = req.body || {};

    if (!name || !workEmail || !message) {
      return res.status(400).json({ error: "Missing required fields: name, workEmail, message" });
    }
    if (!isValidEmail(workEmail)) {
      return res.status(400).json({ error: "Invalid workEmail" });
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
      ...(shouldExposeErrorDetails() ? { detail: formatErr(err) } : {}),
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
      return res.status(400).json({ error: "Missing required fields: roleTitle, name, email" });
    }
    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid email" });

    if (!acceptedPolicies) {
      return res.status(400).json({ error: "You must accept Terms & Privacy to submit." });
    }

    const to = process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
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
          resumeUrl ? `<a href="${escapeHtml(resumeUrl)}">${escapeHtml(resumeUrl)}</a>` : "-"
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
      ...(shouldExposeErrorDetails() ? { detail: formatErr(err) } : {}),
    });
  }
});

// ---------- Careers: general application ----------
app.post("/api/careers/general", careersLimiter, async (req, res) => {
  try {
    const { name, email, roleInterest = "", linkedin = "", note = "", acceptedPolicies = false } =
      req.body || {};

    if (!name || !email) {
      return res.status(400).json({ error: "Missing required fields: name, email" });
    }
    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid email" });

    if (!acceptedPolicies) {
      return res.status(400).json({ error: "You must accept Terms & Privacy to submit." });
    }

    const to = process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.SMTP_USER || to;

    const cleanedRole = String(roleInterest || "").trim();
    const subject = cleanedRole ? `General Application — ${cleanedRole}` : "General Application";

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
      ...(shouldExposeErrorDetails() ? { detail: formatErr(err) } : {}),
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

  if (!payload?.docKey || !isSafeKey(payload.docKey)) return { ok: false, error: "Invalid docKey" };
  if (!payload?.exp || typeof payload.exp !== "number") return { ok: false, error: "Invalid exp" };

  const now = Math.floor(Date.now() / 1000);
  if (now > payload.exp) return { ok: false, error: "Token expired" };

  return { ok: true, payload };
}

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
    return res.status(500).json({
      error: "Failed to issue token",
      ...(shouldExposeErrorDetails() ? { detail: formatErr(e) } : {}),
    });
  }
});

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

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cross-Origin-Resource-Policy", "same-site");

    const stream = fs.createReadStream(filePath);
    stream.on("error", (err) => {
      console.error("PROPOSAL_STREAM_ERROR:", err);
      res.status(500).end();
    });
    stream.pipe(res);
  } catch (e) {
    console.error("PROPOSAL_VIEW_ERROR:", e);
    return res.status(500).json({
      error: "Failed to serve proposal",
      ...(shouldExposeErrorDetails() ? { detail: formatErr(e) } : {}),
    });
  }
});

// =====================
// ✅ NEWSLETTER (simple)
// =====================
const DATA_DIR = path.join(__dirname, "data");
const NEWSLETTER_FILE = path.join(DATA_DIR, "newsletter.json");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function readNewsletter() {
  ensureDir(DATA_DIR);
  if (!fs.existsSync(NEWSLETTER_FILE)) return { subscribers: [] };
  try {
    return JSON.parse(fs.readFileSync(NEWSLETTER_FILE, "utf8"));
  } catch {
    return { subscribers: [] };
  }
}

function writeNewsletter(data) {
  ensureDir(DATA_DIR);
  fs.writeFileSync(NEWSLETTER_FILE, JSON.stringify(data, null, 2), "utf8");
}

function baseUrl() {
  // Use your site domain for links (recommended)
  // e.g. PUBLIC_BASE_URL=https://hazeedge.com
  return (process.env.PUBLIC_BASE_URL || "http://localhost:8787").replace(/\/+$/, "");
}

function makeUnsubLink(token) {
  return `${baseUrl()}/api/newsletter/unsubscribe?token=${encodeURIComponent(token)}`;
}

app.post("/api/newsletter/subscribe", newsletterLimiter, async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!isValidEmail(email)) return res.status(400).json({ error: "Invalid email" });

    const store = readNewsletter();
    const existing = store.subscribers.find((s) => s.email === email);

    const token = crypto.randomBytes(24).toString("base64url");
    const now = new Date().toISOString();

    if (existing) {
      existing.unsubscribedAt = null;
      existing.token = token; // rotate token
      existing.updatedAt = now;
    } else {
      store.subscribers.push({
        email,
        token,
        createdAt: now,
        updatedAt: now,
        unsubscribedAt: null,
      });
    }

    writeNewsletter(store);

    // Optional welcome email
    const sendWelcome = String(process.env.NEWSLETTER_SEND_WELCOME || "").toLowerCase() === "true";
    if (sendWelcome) {
      const from = process.env.NEWSLETTER_FROM || process.env.FROM_EMAIL || process.env.SMTP_USER;
      const transporter = createTransporter();
      const unsubLink = makeUnsubLink(token);

      await transporter.sendMail({
        from,
        to: email,
        subject: "You're subscribed — HazeEdge updates",
        text: `Thanks for subscribing. We'll email you when we publish new insights, playbooks, and research.\n\nUnsubscribe anytime: ${unsubLink}\n`,
        html: `
          <div style="font-family:Arial,sans-serif;line-height:1.6">
            <h2>You're subscribed</h2>
            <p>Thanks for subscribing. We'll email you when we publish new insights, playbooks, and research.</p>
            <p style="margin-top:18px">Unsubscribe anytime: <a href="${unsubLink}">Unsubscribe</a></p>
          </div>
        `,
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("NEWSLETTER_SUBSCRIBE_ERROR:", err);
    return res.status(500).json({
      error: "Failed to subscribe",
      ...(shouldExposeErrorDetails() ? { detail: formatErr(err) } : {}),
    });
  }
});

app.get("/api/newsletter/unsubscribe", (req, res) => {
  try {
    const token = String(req.query.token || "");
    if (!token) return res.status(400).send("Missing token");

    const store = readNewsletter();
    const sub = store.subscribers.find((s) => s.token === token);

    if (sub && !sub.unsubscribedAt) {
      sub.unsubscribedAt = new Date().toISOString();
      sub.updatedAt = new Date().toISOString();
      writeNewsletter(store);
    }

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(`
      <div style="font-family:Arial,sans-serif;max-width:720px;margin:40px auto;line-height:1.6">
        <h2>You're unsubscribed</h2>
        <p>You will no longer receive HazeEdge updates.</p>
        <p><a href="${baseUrl()}">Back to HazeEdge</a></p>
      </div>
    `);
  } catch (err) {
    console.error("NEWSLETTER_UNSUB_ERROR:", err);
    return res.status(500).send("Failed to unsubscribe");
  }
});

// ---------- Error handler ----------
app.use((err, _req, res, _next) => {
  console.error("UNHANDLED_ERROR:", err);
  res.status(500).json({
    error: "Internal server error",
    ...(shouldExposeErrorDetails() ? { detail: formatErr(err) } : {}),
  });
});

app.listen(PORT, () => {
  console.log(`HazeEdge backend running on port ${PORT}`);
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
