// Shared QuickBooks Online (Intuit) Accounting API helpers — SANDBOX ONLY.
//
// Credentials come ONLY from Netlify environment variables:
//   QBO_CLIENT_ID, QBO_CLIENT_SECRET            (required)
//   QBO_ENVIRONMENT  (default "sandbox"; anything else is refused for now)
//   QBO_REDIRECT_URI (default https://angelfishhomes.com/qbo/callback)
//   ADMIN_PASSWORD   (guards every admin/test endpoint)
//
// OAuth tokens (access token, refresh token, expiries, realmId) are stored in
// Netlify Blobs (store "qbo", key "tokens"), NOT in env vars: Intuit rotates the
// refresh token on every refresh, and a function cannot rewrite env vars.
//
// This file lives in netlify/functions/lib/ and is NOT itself a function
// (Netlify only treats lib/index.mjs or lib/lib.mjs as a function).
import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

export const MINOR_VERSION = 75; // Intuit base minor version since Aug 2025 (1-74 deprecated)
export const SCOPE = "com.intuit.quickbooks.accounting";
export const AUTHORIZE_URL = "https://appcenter.intuit.com/connect/oauth2";
export const TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
export const API_BASES = { sandbox: "https://sandbox-quickbooks.api.intuit.com" };
export const DEFAULT_REDIRECT_URI = "https://angelfishhomes.com/qbo/callback";
const REFRESH_MARGIN_MS = 5 * 60 * 1000; // refresh when within 5 minutes of expiry

/* ================================================================
   PRICING CONFIG — per-grade composite price (USD).
   Pricing is NOT defined yet. 0 is a placeholder. Callers (e.g. the
   qbo-test function) may pass opts.unitPrice to override it.
   ================================================================ */
export const PRICE_PER_GRADE = 0;

export const SERVICE_ITEM_NAME = "Composite - Grade";

// ---------------------------------------------------------------- errors
export class QboError extends Error {
  constructor(status, code, message, detail) {
    super(message);
    this.name = "QboError";
    this.status = status;
    this.code = code;
    if (detail !== undefined) this.detail = detail;
  }
}

const NO_CACHE = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
  Expires: "0",
};

export function json(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...NO_CACHE, ...extraHeaders },
  });
}

export function html(status, body) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", ...NO_CACHE, "X-Robots-Tag": "noindex, nofollow" },
  });
}

// Turn any thrown error into a clean JSON response (never leaks tokens/secrets).
export function errorResponse(err) {
  if (err instanceof QboError) {
    const body = { ok: false, error: err.code, message: err.message };
    if (err.detail !== undefined) body.detail = err.detail;
    return json(err.status, body);
  }
  console.error("Unexpected error:", err);
  return json(500, { ok: false, error: "internal_error", message: "Unexpected server error. Check the function logs." });
}

export function env(name) {
  try {
    if (typeof Netlify !== "undefined" && Netlify.env) {
      const v = Netlify.env.get(name);
      if (v !== undefined && v !== null) return v;
    }
  } catch { /* ignore */ }
  return process.env[name];
}

// ---------------------------------------------------------------- admin auth
function passwordMatches(given, expected) {
  if (typeof given !== "string" || typeof expected !== "string" || expected.length === 0) return false;
  const a = createHash("sha256").update(given, "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b); // constant-time
}

// Throws QboError(401/500) unless the password matches ADMIN_PASSWORD.
export function requireAdmin(password) {
  const expected = env("ADMIN_PASSWORD") || "";
  if (!expected) throw new QboError(500, "admin_not_configured", "ADMIN_PASSWORD is not configured on the server.");
  if (!passwordMatches(password, expected)) throw new QboError(401, "unauthorized", "Incorrect or missing admin password.");
}

// Password from query (?password=), X-Admin-Password header, or JSON body.
export function passwordFromRequest(req, body) {
  const url = new URL(req.url);
  return (
    req.headers.get("x-admin-password") ||
    url.searchParams.get("password") ||
    (body && typeof body.password === "string" ? body.password : "") ||
    ""
  );
}

// ---------------------------------------------------------------- config
export function configStatus() {
  const environment = (env("QBO_ENVIRONMENT") || "sandbox").trim().toLowerCase();
  const missing = ["QBO_CLIENT_ID", "QBO_CLIENT_SECRET"].filter((k) => !env(k));
  return { environment, missing, configured: missing.length === 0 && environment === "sandbox" };
}

export function getConfig() {
  const { environment, missing } = configStatus();
  if (environment !== "sandbox") {
    throw new QboError(500, "unsupported_environment",
      `QBO_ENVIRONMENT is "${environment}". Only "sandbox" is allowed in this build; production is refused.`);
  }
  if (missing.length) {
    throw new QboError(503, "not_configured",
      `QuickBooks is not configured yet. Missing environment variable(s): ${missing.join(", ")}.`, { missing });
  }
  return {
    clientId: env("QBO_CLIENT_ID"),
    clientSecret: env("QBO_CLIENT_SECRET"),
    environment,
    redirectUri: env("QBO_REDIRECT_URI") || DEFAULT_REDIRECT_URI,
    apiBase: API_BASES[environment],
  };
}

// ---------------------------------------------------------------- blobs
export function qboStore() {
  return getStore({ name: "qbo", consistency: "strong" });
}

export async function loadTokens() {
  const t = await qboStore().get("tokens", { type: "json" });
  return t || null;
}

export async function saveTokens(tokens) {
  await qboStore().setJSON("tokens", tokens);
  return tokens;
}

export async function clearTokens() {
  await qboStore().delete("tokens");
}

// OAuth state (CSRF protection) for the connect -> callback round trip.
export async function saveOAuthState(state) {
  await qboStore().setJSON("oauth-state", { state, createdAt: Date.now() });
}

export async function consumeOAuthState(state, maxAgeMs = 10 * 60 * 1000) {
  const store = qboStore();
  const saved = await store.get("oauth-state", { type: "json" });
  if (!saved || typeof state !== "string" || !state) return false;
  const a = createHash("sha256").update(state).digest();
  const b = createHash("sha256").update(String(saved.state)).digest();
  const ok = timingSafeEqual(a, b) && Date.now() - saved.createdAt <= maxAgeMs;
  if (ok) await store.delete("oauth-state"); // one-time use
  return ok;
}

// ---------------------------------------------------------------- OAuth token calls
async function tokenRequest(params) {
  const cfg = getConfig();
  const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params).toString(),
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) {
    const code = data.error || `http_${res.status}`;
    const reconnect = code === "invalid_grant";
    throw new QboError(reconnect ? 401 : 502, reconnect ? "reconnect_required" : "token_error",
      reconnect
        ? "QuickBooks refused the stored authorization (invalid_grant). Run the one-time connect again."
        : `Intuit token endpoint error: ${code}`,
      { intuitError: code, description: data.error_description, intuit_tid: res.headers.get("intuit_tid") || undefined });
  }
  return data;
}

function tokensFromResponse(data, prev = {}) {
  const now = Date.now();
  return {
    realmId: prev.realmId,
    accessToken: data.access_token,
    refreshToken: data.refresh_token || prev.refreshToken, // Intuit may rotate this on every refresh
    tokenType: data.token_type || "bearer",
    accessTokenExpiresAt: now + (Number(data.expires_in) || 3600) * 1000,
    refreshTokenExpiresAt: data.x_refresh_token_expires_in
      ? now + Number(data.x_refresh_token_expires_in) * 1000
      : prev.refreshTokenExpiresAt,
    connectedAt: prev.connectedAt || now,
    lastRefreshedAt: now,
    environment: "sandbox",
  };
}

export async function exchangeCode(code, realmId) {
  const cfg = getConfig();
  if (!code) throw new QboError(400, "missing_code", "Missing authorization code from Intuit.");
  if (!realmId) throw new QboError(400, "missing_realm", "Missing realmId from Intuit.");
  const data = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: cfg.redirectUri });
  const tokens = tokensFromResponse(data, { realmId: String(realmId), connectedAt: Date.now() });
  await saveTokens(tokens);
  return tokens;
}

export async function refreshTokens(prev) {
  if (!prev || !prev.refreshToken) throw new QboError(409, "not_connected", "QuickBooks is not connected yet. Run the one-time connect.");
  const data = await tokenRequest({ grant_type: "refresh_token", refresh_token: prev.refreshToken });
  const tokens = tokensFromResponse(data, prev);
  await saveTokens(tokens); // persist the (possibly rotated) refresh token immediately
  return tokens;
}

// Returns { accessToken, realmId }, refreshing if expired / within 5 min of expiry.
export async function getAccessToken({ forceRefresh = false } = {}) {
  getConfig();
  let tokens = await loadTokens();
  if (!tokens || !tokens.refreshToken || !tokens.realmId) {
    throw new QboError(409, "not_connected", "QuickBooks is not connected yet. Run the one-time connect (qbo-connect).");
  }
  if (forceRefresh || !tokens.accessToken || Date.now() >= (tokens.accessTokenExpiresAt || 0) - REFRESH_MARGIN_MS) {
    tokens = await refreshTokens(tokens);
  }
  return { accessToken: tokens.accessToken, realmId: tokens.realmId };
}

// ---------------------------------------------------------------- API calls
function faultDetail(data) {
  const f = data && (data.Fault || data.fault);
  if (!f) return null;
  const errors = (f.Error || f.error || []).map((e) => ({
    code: e.code, message: e.Message || e.message, detail: e.Detail || e.detail, element: e.element,
  }));
  return { type: f.type, errors };
}

// qboFetch("customer", { method: "POST", body }) -> parsed JSON
// qboFetch("invoice/123", { query: { include: "invoiceLink" } })
export async function qboFetch(path, { method = "GET", body, query = {} } = {}) {
  const cfg = getConfig();
  let attempt = 0;
  let { accessToken, realmId } = await getAccessToken();
  while (true) {
    const url = new URL(`${cfg.apiBase}/v3/company/${encodeURIComponent(realmId)}/${path.replace(/^\/+/, "")}`);
    url.searchParams.set("minorversion", String(MINOR_VERSION));
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401 && attempt === 0) {
      attempt++;
      ({ accessToken, realmId } = await getAccessToken({ forceRefresh: true })); // retry once after refresh
      continue;
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : {}; } catch { data = null; }
    const fault = faultDetail(data);
    if (!res.ok || fault) {
      const first = fault && fault.errors[0];
      throw new QboError(res.ok ? 400 : (res.status >= 500 ? 502 : res.status), "qbo_fault",
        first ? `QuickBooks error: ${first.message}${first.detail ? " — " + first.detail : ""}` : `QuickBooks API HTTP ${res.status}`,
        { httpStatus: res.status, fault: fault || undefined, raw: fault ? undefined : (text || "").slice(0, 500),
          intuit_tid: res.headers.get("intuit_tid") || undefined });
    }
    return data;
  }
}

// Escape a value for a QBO query string literal.
export function qEsc(v) {
  return String(v).replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

export async function qboQuery(sql) {
  const data = await qboFetch("query", { query: { query: sql } });
  return (data && data.QueryResponse) || {};
}

// ---------------------------------------------------------------- customers
function cleanName(s, max = 100) {
  // DisplayName/Name may not contain colon, tab or newline.
  return String(s || "").replace(/[:\t\r\n]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

// quote: { firstName, lastName, email, phone, street, city, state, zip, schoolName, displayName? }
// Reuses an existing customer found by DisplayName, then by email. Returns { customer, reused }.
export async function createCustomer(quote = {}) {
  const first = cleanName(quote.firstName);
  const last = cleanName(quote.lastName);
  const school = cleanName(quote.schoolName);
  const email = String(quote.email || "").trim();
  const person = [first, last].filter(Boolean).join(" ");
  const displayName = cleanName(quote.displayName || [person, school].filter(Boolean).join(" - ") || email);
  if (!displayName) throw new QboError(400, "invalid_customer", "Customer needs a name, school name or email.");

  const byName = await qboQuery(`select * from Customer where DisplayName = '${qEsc(displayName)}'`);
  if (byName.Customer && byName.Customer.length) return { customer: byName.Customer[0], reused: true, matchedBy: "DisplayName" };
  if (email) {
    try {
      const byEmail = await qboQuery(`select * from Customer where PrimaryEmailAddr = '${qEsc(email)}'`);
      if (byEmail.Customer && byEmail.Customer.length) return { customer: byEmail.Customer[0], reused: true, matchedBy: "email" };
    } catch (e) {
      if (!(e instanceof QboError && e.code === "qbo_fault")) throw e; // email filter unsupported -> just create
    }
  }

  const body = {
    DisplayName: displayName,
    ...(first ? { GivenName: first } : {}),
    ...(last ? { FamilyName: last } : {}),
    ...(school ? { CompanyName: school } : {}),
    ...(email ? { PrimaryEmailAddr: { Address: email } } : {}),
    ...(quote.phone ? { PrimaryPhone: { FreeFormNumber: String(quote.phone).trim().slice(0, 30) } } : {}),
    BillAddr: {
      ...(quote.street ? { Line1: String(quote.street).trim() } : {}),
      ...(quote.city ? { City: String(quote.city).trim() } : {}),
      ...(quote.state ? { CountrySubDivisionCode: String(quote.state).trim().toUpperCase() } : {}),
      ...(quote.zip ? { PostalCode: String(quote.zip).trim() } : {}),
      Country: "USA",
    },
    ...(school ? { Notes: `School: ${school}${quote.schoolLocation ? " (" + quote.schoolLocation + ")" : ""}`.slice(0, 2000) } : {}),
  };
  const data = await qboFetch("customer", { method: "POST", body });
  return { customer: data.Customer, reused: false };
}

// ---------------------------------------------------------------- items
export async function findIncomeAccount() {
  const r = await qboQuery("select * from Account where AccountType = 'Income' maxresults 100");
  const accts = (r.Account || []).filter((a) => a.Active !== false);
  if (!accts.length) throw new QboError(409, "no_income_account", "No Income account found in the QuickBooks company.");
  const prefer = accts.find((a) => /services/i.test(a.Name)) || accts.find((a) => /sales/i.test(a.Name));
  return prefer || accts[0];
}

export async function findOrCreateServiceItem(name = SERVICE_ITEM_NAME) {
  const r = await qboQuery(`select * from Item where Name = '${qEsc(name)}'`);
  if (r.Item && r.Item.length) return r.Item[0];
  const acct = await findIncomeAccount();
  const data = await qboFetch("item", {
    method: "POST",
    body: { Name: name, Type: "Service", IncomeAccountRef: { value: acct.Id, name: acct.Name } },
  });
  return data.Item;
}

// ---------------------------------------------------------------- invoices
// grades: ["3rd Grade", "4th Grade", ...] — one invoice line per grade.
// opts: { unitPrice?, billEmail?, schoolName?, memo?, dueDate? (YYYY-MM-DD) }
export async function createInvoice(customerId, grades, opts = {}) {
  if (!customerId) throw new QboError(400, "invalid_invoice", "customerId is required.");
  if (!Array.isArray(grades) || !grades.length) throw new QboError(400, "invalid_invoice", "At least one grade is required.");
  const price = opts.unitPrice !== undefined ? Number(opts.unitPrice) : PRICE_PER_GRADE;
  if (!Number.isFinite(price) || price < 0) throw new QboError(400, "invalid_invoice", "unitPrice must be a number >= 0.");
  const unit = Math.round(price * 100) / 100;
  const item = await findOrCreateServiceItem();
  const school = cleanName(opts.schoolName, 200);
  const lines = grades.map((g) => ({
    DetailType: "SalesItemLineDetail",
    Amount: unit,
    Description: `Composite - ${String(g).trim()}${school ? " - " + school : ""}`.slice(0, 4000),
    SalesItemLineDetail: { ItemRef: { value: item.Id, name: item.Name }, Qty: 1, UnitPrice: unit },
  }));
  const body = {
    CustomerRef: { value: String(customerId) },
    Line: lines,
    AllowOnlineCreditCardPayment: true,
    AllowOnlineACHPayment: true,
    ...(opts.billEmail ? { BillEmail: { Address: String(opts.billEmail).trim() } } : {}),
    ...(opts.memo ? { CustomerMemo: { value: String(opts.memo).slice(0, 1000) } } : {}),
    ...(opts.dueDate ? { DueDate: opts.dueDate } : {}),
  };
  const data = await qboFetch("invoice", { method: "POST", body });
  return data.Invoice;
}

// InvoiceLink only appears when QuickBooks Payments is enabled for the company
// AND the invoice has a BillEmail. Sandbox companies often lack it.
export async function getInvoicePaymentLink(invoiceId) {
  const data = await qboFetch(`invoice/${encodeURIComponent(invoiceId)}`, { query: { include: "invoiceLink" } });
  const inv = data.Invoice || {};
  const link = inv.InvoiceLink || "";
  return {
    link,
    message: link
      ? "Payment link available."
      : "No InvoiceLink returned. QuickBooks only provides one when QuickBooks Payments is enabled for the company and the invoice has a BillEmail. Sandbox companies often don't have Payments enabled.",
    invoice: inv,
  };
}
