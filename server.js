import cors from "cors";
import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";
import { Resend } from "resend";

import crypto from "node:crypto";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

// ✅ REQUIRED on Render / any reverse-proxy host (fixes express-rate-limit + req.ip)
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 8787);

// ---------- Body parsing ----------
app.use(express.json({ limit: "1mb" }));

// ---------- CORS ----------
const allowedOrigins = String(process.env.CORS_ORIGINS || "")
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

    // Allow localhost/LAN only in dev
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

// ---------- Rate limit ----------
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// ---------- Health ----------
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// =========================
// ✅ RESEND (HTTP EMAIL)
// =========================
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

async function sendEmail({ from, to, subject, text, html, replyTo }) {
  if (!resend) {
    throw new Error("Missing RESEND_API_KEY (set it in your environment variables)");
  }

  const payload = {
    from,
    to,
    subject,
    ...(html ? { html } : {}),
    ...(text ? { text } : {}),
    ...(replyTo ? { replyTo } : {}),
  };

  const { data, error } = await resend.emails.send(payload);
  if (error) {
    throw new Error(error.message || JSON.stringify(error));
  }
  return data;
}

// =====================================================
// ✅ NEWSLETTER: subscribe / unsubscribe / send (admin)
// =====================================================

// ✅ FIX: Render can't mkdir /var/data. Use /tmp in production by default.
// You can override with DATA_DIR env var if you want.
const DEFAULT_DATA_DIR =
  process.env.NODE_ENV === "production" ? "/tmp/hazeedge-data" : path.join(__dirname, "data");
const DATA_DIR = process.env.DATA_DIR || DEFAULT_DATA_DIR;

const NEWSLETTER_FILE = path.join(DATA_DIR, "newsletter_subscribers.json");

async function ensureDataDir() {
  await fsPromises.mkdir(DATA_DIR, { recursive: true });
  if (!fs.existsSync(NEWSLETTER_FILE)) {
    await fsPromises.writeFile(NEWSLETTER_FILE, JSON.stringify([], null, 2), "utf8");
  }
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function isValidEmail(email) {
  const e = normalizeEmail(email);
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

async function readNewsletterSubscribers() {
  await ensureDataDir();
  const raw = await fsPromises.readFile(NEWSLETTER_FILE, "utf8");
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function writeNewsletterSubscribers(list) {
  await ensureDataDir();
  await fsPromises.writeFile(NEWSLETTER_FILE, JSON.stringify(list, null, 2), "utf8");
}

function baseUrl() {
  return String(process.env.PUBLIC_BASE_URL || "").trim().replace(/\/+$/, "");
}

function unsubscribeUrl(token) {
  const base = baseUrl();
  const url = `${base}/api/newsletter/unsubscribe?token=${encodeURIComponent(token)}`;
  return url;
}

app.post("/api/newsletter/subscribe", async (req, res) => {
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
      list.push({ email: normalized, token, status: "active", createdAt: now });
    } else {
      token = list[idx].token || crypto.randomBytes(24).toString("hex");
      list[idx] = {
        ...list[idx],
        email: normalized,
        token,
        status: "active",
        updatedAt: now,
      };
    }

    await writeNewsletterSubscribers(list);

    // Optional welcome email
    const sendWelcome =
      String(process.env.NEWSLETTER_SEND_WELCOME || "true").toLowerCase() === "true";

    if (sendWelcome) {
      const to = normalized;
      const from =
        process.env.NEWSLETTER_FROM ||
        process.env.FROM_EMAIL ||
        process.env.COMPANY_EMAIL ||
        "contact@hazeedge.com";

      const unsub = unsubscribeUrl(token);

      await sendEmail({
        from,
        to,
        subject: "You're subscribed — HazeEdge updates",
        text: `You're subscribed to HazeEdge updates.\n\nUnsubscribe anytime: ${unsub}`,
        html: `
          <div style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2>You're subscribed</h2>
            <p>Thanks for subscribing to HazeEdge updates.</p>
            <p style="margin-top:16px;">
              <a href="${unsub}" style="color:#666;">Unsubscribe</a>
            </p>
          </div>
        `,
      });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("NEWSLETTER_SUBSCRIBE_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to subscribe",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

app.get("/api/newsletter/unsubscribe", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).send("Missing token");

    const list = await readNewsletterSubscribers();
    const idx = list.findIndex((s) => String(s?.token || "") === token);

    if (idx === -1) {
      return res.status(404).send("Invalid token");
    }

    list[idx] = {
      ...list[idx],
      status: "unsubscribed",
      unsubscribedAt: new Date().toISOString(),
    };
    await writeNewsletterSubscribers(list);

    return res.send("You have been unsubscribed.");
  } catch (err) {
    console.error("NEWSLETTER_UNSUB_ERROR:", err);
    return res.status(500).send("Server error");
  }
});

app.post("/api/newsletter/send", async (req, res) => {
  try {
    const adminKey = req.get("X-Admin-Key") || "";
    if (!process.env.NEWSLETTER_ADMIN_KEY || adminKey !== process.env.NEWSLETTER_ADMIN_KEY) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { subject, html, text } = req.body || {};
    if (!subject || typeof subject !== "string") {
      return res.status(400).json({ error: "Missing subject" });
    }
    if (!html && !text) {
      return res.status(400).json({ error: "Provide html and/or text" });
    }

    const list = await readNewsletterSubscribers();
    const active = list.filter((s) => s?.status === "active" && isValidEmail(s?.email));

    const from =
      process.env.NEWSLETTER_FROM ||
      process.env.FROM_EMAIL ||
      process.env.COMPANY_EMAIL ||
      "contact@hazeedge.com";

    let sent = 0;
    let failed = 0;

    for (const sub of active) {
      try {
        const unsub = unsubscribeUrl(sub.token);
        const finalHtml = html
          ? `${String(html)}<hr/><p style="font-size:12px;color:#666;">Unsubscribe: <a href="${unsub}">${unsub}</a></p>`
          : undefined;

        const finalText = `${text ? String(text) : ""}\n\nUnsubscribe: ${unsub}`.trim();

        await sendEmail({
          from,
          to: normalizeEmail(sub.email),
          subject: String(subject),
          html: finalHtml,
          text: finalText,
        });

        sent++;
      } catch (e) {
        console.error("NEWSLETTER_SEND_ONE_ERROR:", normalizeEmail(sub.email), e);
        failed++;
      }
    }

    return res.json({ ok: true, total: active.length, sent, failed });
  } catch (err) {
    console.error("NEWSLETTER_SEND_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to send newsletter",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

// ===============================
// ✅ CONTACT: main contact form
// ===============================

app.post("/api/contact", async (req, res) => {
  try {
    const { name, workEmail, company, message } = req.body || {};

    if (!name || !workEmail || !message) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidEmail(workEmail)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    const to = process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.COMPANY_EMAIL || to;

    const subject = `New website message: ${name}${company ? ` (${company})` : ""}`;

    const text = [
      "New contact form submission",
      "--------------------------",
      `Name: ${name}`,
      `Work Email: ${workEmail}`,
      `Company: ${company || "-"}`,
      "",
      "Message:",
      String(message),
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>New contact form submission</h2>
        <p><b>Name:</b> ${String(name)}</p>
        <p><b>Work Email:</b> ${String(workEmail)}</p>
        <p><b>Company:</b> ${company ? String(company) : "-"}</p>
        <hr />
        <p style="white-space: pre-wrap;">${String(message)}</p>
      </div>
    `;

    await sendEmail({
      from,
      to,
      subject,
      text,
      html,
      replyTo: normalizeEmail(workEmail),
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("CONTACT_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to send email",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

// ===============================
// ✅ CAREERS: Apply + General
// ===============================

app.post("/api/careers/apply", async (req, res) => {
  try {
    const { name, email, phone, role, message, portfolio, linkedin } = req.body || {};

    if (!name || !email || !role) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    const to = process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.COMPANY_EMAIL || to;

    const subject = `Career Application: ${role} — ${name}`;

    const text = [
      "New career application",
      "---------------------",
      `Name: ${name}`,
      `Email: ${email}`,
      `Phone: ${phone || "-"}`,
      `Role: ${role}`,
      `Portfolio: ${portfolio || "-"}`,
      `LinkedIn: ${linkedin || "-"}`,
      "",
      "Message:",
      message ? String(message) : "-",
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>New career application</h2>
        <p><b>Name:</b> ${String(name)}</p>
        <p><b>Email:</b> ${String(email)}</p>
        <p><b>Phone:</b> ${phone ? String(phone) : "-"}</p>
        <p><b>Role:</b> ${String(role)}</p>
        <p><b>Portfolio:</b> ${portfolio ? String(portfolio) : "-"}</p>
        <p><b>LinkedIn:</b> ${linkedin ? String(linkedin) : "-"}</p>
        <hr />
        <p style="white-space: pre-wrap;">${message ? String(message) : "-"}</p>
      </div>
    `;

    await sendEmail({
      from,
      to,
      subject,
      text,
      html,
      replyTo: normalizeEmail(email),
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

app.post("/api/careers/general", async (req, res) => {
  try {
    const { name, email, phone, message, portfolio, linkedin } = req.body || {};

    if (!name || !email) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Invalid email address" });
    }

    const to = process.env.CAREERS_EMAIL || process.env.COMPANY_EMAIL || "contact@hazeedge.com";
    const from = process.env.FROM_EMAIL || process.env.COMPANY_EMAIL || to;

    const subject = `General Application — ${name}`;

    const text = [
      "New general application",
      "----------------------",
      `Name: ${name}`,
      `Email: ${email}`,
      `Phone: ${phone || "-"}`,
      `Portfolio: ${portfolio || "-"}`,
      `LinkedIn: ${linkedin || "-"}`,
      "",
      "Message:",
      message ? String(message) : "-",
    ].join("\n");

    const html = `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>New general application</h2>
        <p><b>Name:</b> ${String(name)}</p>
        <p><b>Email:</b> ${String(email)}</p>
        <p><b>Phone:</b> ${phone ? String(phone) : "-"}</p>
        <p><b>Portfolio:</b> ${portfolio ? String(portfolio) : "-"}</p>
        <p><b>LinkedIn:</b> ${linkedin ? String(linkedin) : "-"}</p>
        <hr />
        <p style="white-space: pre-wrap;">${message ? String(message) : "-"}</p>
      </div>
    `;

    await sendEmail({
      from,
      to,
      subject,
      text,
      html,
      replyTo: normalizeEmail(email),
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
// ✅ PROPOSALS: view-only end
// ===============================

function proposalSecret() {
  const s = String(process.env.PROPOSAL_TOKEN_SECRET || "");
  if (!s) throw new Error("Missing PROPOSAL_TOKEN_SECRET");
  return s;
}

function proposalTtlSeconds() {
  const v = Number(process.env.PROPOSAL_TOKEN_TTL_SECONDS || 120);
  return Number.isFinite(v) ? v : 120;
}

function signProposalToken(docKey, exp) {
  const secret = proposalSecret();
  const payload = `${docKey}.${exp}`;
  const sig = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  return `${payload}.${sig}`;
}

function verifyProposalToken(token, docKey) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return false;

  const [k, expStr, sig] = parts;
  if (k !== docKey) return false;

  const exp = Number(expStr);
  if (!Number.isFinite(exp)) return false;
  if (Date.now() > exp) return false;

  const expected = crypto
    .createHmac("sha256", proposalSecret())
    .update(`${k}.${expStr}`)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

app.post("/api/proposals/token", (req, res) => {
  try {
    const { docKey } = req.body || {};
    if (!docKey) return res.status(400).json({ error: "Missing docKey" });

    const exp = Date.now() + proposalTtlSeconds() * 1000;
    const token = signProposalToken(String(docKey), exp);

    return res.json({ ok: true, token, expiresAt: exp });
  } catch (err) {
    console.error("PROPOSAL_TOKEN_ERROR:", err);
    return res.status(500).json({
      error: "Server failed to issue token",
      detail:
        process.env.NODE_ENV !== "production" ? err?.message || String(err) : undefined,
    });
  }
});

app.get("/api/proposals/:docKey", (req, res) => {
  try {
    const docKey = String(req.params.docKey || "");
    const token = String(req.query.token || "");

    if (!docKey) return res.status(400).send("Missing docKey");
    if (!verifyProposalToken(token, docKey)) return res.status(401).send("Unauthorized");

    const filePath = path.join(__dirname, "proposals", `${docKey}.pdf`);
    if (!fs.existsSync(filePath)) return res.status(404).send("Not found");

    res.setHeader("Content-Type", "application/pdf");
    return fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    console.error("PROPOSAL_VIEW_ERROR:", err);
    return res.status(500).send("Server error");
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Backend listening on :${PORT}`);
});
