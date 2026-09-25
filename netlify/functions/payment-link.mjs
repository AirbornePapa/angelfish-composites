// Stores and serves the QuickBooks payment link used by payment.html.
// GET  -> { link: "<url or empty>" }
// POST -> { password, check: true }  verify the admin password only
//         { password, link }         save a new link (https:// URL, or "" to clear)
// The admin password lives ONLY in the Netlify environment variable ADMIN_PASSWORD.
import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

const STORE_NAME = "site-settings";
const KEY = "quickbooks-link";

const HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  "Pragma": "no-cache",
  "Expires": "0",
};

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: HEADERS });

// Constant-time comparison (hash both sides so lengths always match).
function passwordMatches(given, expected) {
  if (typeof given !== "string" || typeof expected !== "string" || expected.length === 0) return false;
  const a = createHash("sha256").update(given, "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b);
}

function isValidHttpsUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !!u.hostname;
  } catch {
    return false;
  }
}

export default async (req) => {
  const store = getStore({ name: STORE_NAME, consistency: "strong" });

  if (req.method === "GET") {
    try {
      const link = (await store.get(KEY)) || "";
      return json(200, { link });
    } catch (err) {
      console.error("Read failed:", err);
      return json(500, { link: "", error: "Could not read the payment link." });
    }
  }

  if (req.method === "POST") {
    let data;
    try {
      data = await req.json();
    } catch {
      return json(400, { ok: false, error: "Invalid JSON body." });
    }
    const expected = Netlify.env.get("ADMIN_PASSWORD") || process.env.ADMIN_PASSWORD || "";
    if (!expected) {
      return json(500, { ok: false, error: "Admin password is not configured on the server." });
    }
    if (!data || !passwordMatches(data.password, expected)) {
      return json(401, { ok: false, error: "Incorrect password." });
    }
    if (data.check === true) {
      return json(200, { ok: true });
    }
    if (typeof data.link !== "string") {
      return json(400, { ok: false, error: "Missing link." });
    }
    const link = data.link.trim();
    if (link !== "" && !isValidHttpsUrl(link)) {
      return json(400, { ok: false, error: "The link must be a full https:// URL." });
    }
    if (link.length > 2000) {
      return json(400, { ok: false, error: "The link is too long." });
    }
    try {
      await store.set(KEY, link);
      return json(200, { ok: true, link });
    } catch (err) {
      console.error("Write failed:", err);
      return json(500, { ok: false, error: "Could not save the payment link." });
    }
  }

  return new Response(JSON.stringify({ error: "Method not allowed" }), {
    status: 405,
    headers: { ...HEADERS, Allow: "GET, POST" },
  });
};
