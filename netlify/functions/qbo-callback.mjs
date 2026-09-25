// GET /.netlify/functions/qbo-callback?code=...&state=...&realmId=...
// Intuit redirects here after the admin approves the connection. Validates the
// state, exchanges the code for tokens, and stores tokens + realmId in Blobs.
import { QboError, consumeOAuthState, exchangeCode, getConfig, html } from "./lib/qbo.mjs";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page(title, message, ok) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow"><title>${esc(title)} — Angelfish Composites</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=DM+Sans:wght@400;600&display=swap" rel="stylesheet">
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:'DM Sans',sans-serif;
    background:linear-gradient(135deg,#0d1b2a 0%,#1a2f45 60%,#0f3248 100%);color:#fff;padding:24px;box-sizing:border-box}
  .card{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:20px;padding:40px;max-width:520px;text-align:center}
  .icon{font-size:3rem;margin-bottom:12px}
  .label{font-size:.78rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#48bfb2;margin-bottom:8px}
  h1{font-family:'Playfair Display',serif;font-size:1.9rem;margin:0 0 12px;color:${ok ? "#fff" : "#ffd0d0"}}
  p{color:rgba(255,255,255,.7);line-height:1.7;margin:0 0 8px}
  a{color:#48bfb2}
</style></head><body><div class="card">
<div class="icon">${ok ? "✅" : "⚠️"}</div><div class="label">Angelfish Composites · QuickBooks</div>
<h1>${esc(title)}</h1>${message}
</div></body></html>`;
}

export default async (req) => {
  const url = new URL(req.url);
  try {
    getConfig();
    const error = url.searchParams.get("error");
    if (error) throw new QboError(400, "authorization_denied", `Intuit returned: ${error}`);
    const state = url.searchParams.get("state");
    if (!(await consumeOAuthState(state))) {
      throw new QboError(400, "invalid_state", "The connect request expired or its state did not match. Start again from qbo-connect.");
    }
    const tokens = await exchangeCode(url.searchParams.get("code"), url.searchParams.get("realmId"));
    return html(200, page("Connected to QuickBooks sandbox",
      `<p>QuickBooks sandbox company <strong>${esc(tokens.realmId)}</strong> is now connected.</p>
       <p>Tokens are stored securely on the server. You can close this window.</p>`, true));
  } catch (err) {
    const msg = err instanceof QboError ? err.message : "Unexpected error while connecting. Check the function logs.";
    if (!(err instanceof QboError)) console.error("qbo-callback error:", err);
    return html(err instanceof QboError ? err.status : 500, page("QuickBooks connection failed", `<p>${esc(msg)}</p>`, false));
  }
};
