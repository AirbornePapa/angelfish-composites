// GET /.netlify/functions/qbo-connect?password=<ADMIN_PASSWORD>
// Admin-only. Starts the one-time OAuth connect: redirects to Intuit's authorize page
// with a random state stored in Netlify Blobs. SANDBOX ONLY.
import { randomBytes } from "node:crypto";
import { AUTHORIZE_URL, SCOPE, errorResponse, getConfig, json, passwordFromRequest, requireAdmin, saveOAuthState } from "./lib/qbo.mjs";

export default async (req) => {
  try {
    if (req.method !== "GET") return json(405, { ok: false, error: "method_not_allowed" }, { Allow: "GET" });
    requireAdmin(passwordFromRequest(req));
    const cfg = getConfig();
    const state = randomBytes(24).toString("hex");
    await saveOAuthState(state);
    const url = new URL(AUTHORIZE_URL);
    url.searchParams.set("client_id", cfg.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", SCOPE);
    url.searchParams.set("redirect_uri", cfg.redirectUri);
    url.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: { Location: url.toString(), "Cache-Control": "no-store" } });
  } catch (err) {
    return errorResponse(err);
  }
};
