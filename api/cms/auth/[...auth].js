import { createOAuthAppAuth } from "@octokit/auth-oauth-app";
import crypto from "crypto";

function sendJson(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
}

export default async function handler(req, res) {
  const parts = (req.query.auth || []);
  const action = parts[0];

  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return sendJson(res, 500, {
      error: "Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET in Vercel env vars."
    });
  }

  // Start OAuth: /api/cms/auth/authorize
  if (action === "authorize") {
    const state = crypto.randomBytes(16).toString("hex");
    const proto = req.headers["x-forwarded-proto"] || "https";
    const host = req.headers.host;
    const redirectUri = `${proto}://${host}/api/cms/auth/callback`;

    const url =
      `https://github.com/login/oauth/authorize` +
      `?client_id=${encodeURIComponent(clientId)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent("repo")}` +
      `&state=${encodeURIComponent(state)}`;

    res.statusCode = 302;
    res.setHeader("Set-Cookie", `cms_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax`);
    res.setHeader("Location", url);
    res.end();
    return;
  }

  // Callback: /api/cms/auth/callback
  if (action === "callback") {
    const { code, state } = req.query;

    const cookies = req.headers.cookie || "";
    const match = cookies.match(/cms_oauth_state=([^;]+)/);
    const savedState = match ? match[1] : null;

    if (!code) return sendJson(res, 400, { error: "Missing code" });
    if (!state || !savedState || state !== savedState) {
      return sendJson(res, 400, { error: "Invalid state" });
    }

    const auth = createOAuthAppAuth({
      clientType: "oauth-app",
      clientId,
      clientSecret,
      code,
    });

    const { token } = await auth({ type: "token" });

    res.statusCode = 302;
    res.setHeader("Set-Cookie", `cms_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
    res.setHeader("Location", `/admin/#access_token=${encodeURIComponent(token)}&token_type=bearer`);
    res.end();
    return;
  }

  return sendJson(res, 404, { error: "Not found" });
}
