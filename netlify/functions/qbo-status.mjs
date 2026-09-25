// GET /.netlify/functions/qbo-status   (admin: ?password=... or X-Admin-Password header)
// Returns configuration/connection status. Never returns tokens or the client secret.
import { configStatus, errorResponse, json, loadTokens, passwordFromRequest, requireAdmin } from "./lib/qbo.mjs";

const iso = (ms) => (ms ? new Date(ms).toISOString() : null);

export default async (req) => {
  try {
    if (req.method !== "GET") return json(405, { ok: false, error: "method_not_allowed" }, { Allow: "GET" });
    requireAdmin(passwordFromRequest(req));
    const cfg = configStatus();
    const t = await loadTokens();
    const now = Date.now();
    return json(200, {
      ok: true,
      environment: cfg.environment,
      environmentAllowed: cfg.environment === "sandbox",
      configured: cfg.configured,
      missingEnv: cfg.missing,
      connected: !!(t && t.refreshToken && t.realmId),
      realmId: t ? t.realmId : null,
      accessTokenExpiresAt: t ? iso(t.accessTokenExpiresAt) : null,
      accessTokenValid: !!(t && t.accessTokenExpiresAt > now),
      refreshTokenExpiresAt: t ? iso(t.refreshTokenExpiresAt) : null,
      connectedAt: t ? iso(t.connectedAt) : null,
      lastRefreshedAt: t ? iso(t.lastRefreshedAt) : null,
    });
  } catch (err) {
    return errorResponse(err);
  }
};
