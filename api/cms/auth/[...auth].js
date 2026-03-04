import crypto from "crypto";

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(data));
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader("Location", location);
  res.end();
}

export default async function handler(req, res) {
  try {
    const parts = Array.isArray(req.query.auth) ? req.query.auth : [req.query.auth];
    const action = parts?.[0];

    const clientId = process.env.GITHUB_CLIENT_ID;
    const clientSecret = process.env.GITHUB_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return json(res, 500, {
        error: "Missing GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET in Vercel environment variables.",
      });
    }

    const proto = req.headers["x-forwarded-proto"] || "https";
    const host = req.headers.host;
    const baseUrl = `${proto}://${host}`;
    const callbackUrl = `${baseUrl}/api/cms/auth/callback`;

    // STEP 1: Start OAuth
    if (action === "authorize") {
      const state = crypto.randomBytes(16).toString("hex");

      // Store state in a short-lived cookie (10 minutes)
      res.setHeader(
        "Set-Cookie",
        `cms_oauth_state=${state}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure`
      );

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: callbackUrl,
        scope: "repo",
        state,
      });

      return redirect(res, `https://github.com/login/oauth/authorize?${params.toString()}`);
    }

    // STEP 2: OAuth callback
    if (action === "callback") {
      const url = new URL(req.url, baseUrl);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      if (!code || !state) {
        return json(res, 400, { error: "Missing code or state." });
      }

      // Verify state cookie
      const cookieHeader = req.headers.cookie || "";
      const stateCookie = cookieHeader
        .split(";")
        .map((c) => c.trim())
        .find((c) => c.startsWith("cms_oauth_state="));

      const expectedState = stateCookie ? stateCookie.split("=")[1] : null;
      if (!expectedState || expectedState !== state) {
        return json(res, 400, { error: "Invalid state. Try logging in again." });
      }

      // Exchange code for access token
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
          state,
        }),
      });

      const tokenData = await tokenRes.json();
      if (!tokenRes.ok || tokenData.error) {
        return json(res, 500, { error: "Token exchange failed.", details: tokenData });
      }

      // Netlify CMS expects: { token: "..." }
      return json(res, 200, { token: tokenData.access_token });
    }

    return json(res, 404, { error: "Not found" });
  } catch (e) {
    return json(res, 500, { error: "Server error", details: String(e) });
  }
}

