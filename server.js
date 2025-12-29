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

/**
 * ✅ REQUIRED on Render / any reverse-proxy host
 * Fixes express-rate-limit 500 errors caused by X-Forwarded-For headers.
 */
// ✅ safer than true, and works across Cloudflare/Render/Netlify setups
app.set("trust proxy", Number(process.env.TRUST_PROXY || 2));


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

    // ✅ allow exact whitelist
    if (allowedOrigins.length > 0 && allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // ✅ dev convenience
    if (isDev && (isLocalhost || isLan)) {
      return callback(null, true);
    }

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

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },

    // ✅ prevents long hangs -> avoids Netlify 504
    connectionTimeout: 15_000,
    greetingTimeout: 15_000,
    socketTimeout: 20_000,
  });
}

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

// ---------- Error handler ----------
app.use((err, _req, res, _next) => {
  console.error("UNHANDLED_ERROR:", err);
  res.status(500).json({ error: "Internal server error" });
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
