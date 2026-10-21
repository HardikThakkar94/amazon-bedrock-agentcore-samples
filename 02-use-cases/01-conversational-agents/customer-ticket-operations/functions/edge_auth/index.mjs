// CloudFront viewer-request auth (Lambda@Edge, us-east-1). Dependency-free.
//
// Every request needs a valid Cognito access token in an HttpOnly cookie. Two realms keep two
// independent sessions in one browser: the operator console (/, /api/*) and the customer portal
// (/portal/*, /api/portal/*). Logins go through Cognito's Hosted UI with PKCE; each login first
// ends the Hosted UI session so a different persona can sign in. Lambda@Edge has no environment
// variables, so configuration is read once from SSM in us-east-1. Missing config fails closed.
import crypto from "node:crypto";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const SSM_PATH = "__SSM_PATH__"; // replaced at build time with /<project>/<env>/edge/
const ssm = new SSMClient({ region: "us-east-1" });
let config;
let jwks;

async function getConfig() {
  if (config) return config;
  const keys = ["client_id", "domain", "issuer"];
  const values = await Promise.all(
    keys.map((k) => ssm.send(new GetParameterCommand({ Name: `${SSM_PATH}${k}` })).then((r) => r.Parameter.Value)),
  );
  const c = Object.fromEntries(keys.map((k, i) => [k, values[i]]));
  if (!c.client_id || !c.domain || !c.issuer) throw new Error("edge auth config missing");
  config = c;
  return config;
}

async function getKeys(issuer) {
  if (jwks) return jwks;
  const res = await fetch(`${issuer}/.well-known/jwks.json`);
  if (!res.ok) throw new Error("jwks unavailable");
  jwks = Object.fromEntries((await res.json()).keys.map((k) => [k.kid, crypto.createPublicKey({ key: k, format: "jwk" })]));
  return jwks;
}

const b64url = (buf) => Buffer.from(buf).toString("base64url");

async function verify(token, cfg) {
  const [h, p, s] = (token || "").split(".");
  if (!s) return null;
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const claims = JSON.parse(Buffer.from(p, "base64url"));
  const key = (await getKeys(cfg.issuer))[header.kid];
  if (!key || header.alg !== "RS256") return null;
  const ok = crypto.verify("RSA-SHA256", Buffer.from(`${h}.${p}`), key, Buffer.from(s, "base64url"));
  const now = Math.floor(Date.now() / 1000);
  if (!ok || claims.iss !== cfg.issuer || claims.token_use !== "access" || claims.client_id !== cfg.client_id || claims.exp <= now) return null;
  return claims;
}

function cookies(headers) {
  const out = {};
  for (const { value } of headers.cookie || []) {
    for (const part of value.split(";")) {
      const i = part.indexOf("=");
      if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
  }
  return out;
}

const realmOf = (uri) => (uri.startsWith("/portal") || uri.startsWith("/api/portal") ? "portal" : "op");
const cookieName = (realm) => `sec310_${realm}`;
const setCookie = (name, value, maxAge) => ({
  key: "Set-Cookie",
  value: `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`,
});

function redirect(location, extraCookies = []) {
  return {
    status: "302",
    statusDescription: "Found",
    headers: {
      location: [{ key: "Location", value: location }],
      "cache-control": [{ key: "Cache-Control", value: "no-store" }],
      ...(extraCookies.length ? { "set-cookie": extraCookies } : {}),
    },
  };
}

const deny = (status, message) => ({
  status: String(status),
  headers: {
    "content-type": [{ key: "Content-Type", value: "application/json" }],
    "cache-control": [{ key: "Cache-Control", value: "no-store" }],
  },
  body: JSON.stringify({ error: message }),
});

function startLogin(cfg, host, uri, realm) {
  // End any Hosted UI session first so the next persona can sign in; then /auth/login authorizes.
  const verifier = b64url(crypto.randomBytes(32));
  const nonce = b64url(crypto.randomBytes(16));
  const back = realm === "portal" ? "/portal/" : uri.startsWith("/api") ? "/" : uri;
  const pkce = b64url(JSON.stringify({ v: verifier, n: nonce, r: realm, b: back }));
  const logout = new URL(`https://${cfg.domain}/logout`);
  logout.searchParams.set("client_id", cfg.client_id);
  logout.searchParams.set("logout_uri", `https://${host}/auth/login`);
  return redirect(logout.toString(), [setCookie("sec310_pkce", pkce, 600)]);
}

function authorize(cfg, host, jar) {
  let state;
  try {
    state = JSON.parse(Buffer.from(jar.sec310_pkce || "", "base64url"));
  } catch {
    return redirect("/");
  }
  const url = new URL(`https://${cfg.domain}/oauth2/authorize`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", cfg.client_id);
  url.searchParams.set("redirect_uri", `https://${host}/auth/callback`);
  url.searchParams.set("scope", "openid");
  url.searchParams.set("state", state.n);
  url.searchParams.set("code_challenge", b64url(crypto.createHash("sha256").update(state.v).digest()));
  url.searchParams.set("code_challenge_method", "S256");
  return redirect(url.toString());
}

async function callback(cfg, host, query, jar) {
  let state;
  try {
    state = JSON.parse(Buffer.from(jar.sec310_pkce || "", "base64url"));
  } catch {
    return deny(400, "login state missing");
  }
  const params = new URLSearchParams(query);
  if (!params.get("code") || params.get("state") !== state.n) return deny(400, "login state mismatch");
  const res = await fetch(`https://${cfg.domain}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: cfg.client_id,
      code: params.get("code"),
      redirect_uri: `https://${host}/auth/callback`,
      code_verifier: state.v,
    }),
  });
  if (!res.ok) return deny(401, "login failed");
  const tokens = await res.json();
  const claims = await verify(tokens.access_token, cfg);
  if (!claims) return deny(401, "login failed");
  if (state.r === "op" && claims.role !== "operator") return deny(403, "operators only: sign in as an operator persona");
  if (state.r === "portal" && claims.role !== "customer") return deny(403, "customers only: sign in as a customer persona");
  return redirect(state.b, [
    setCookie(cookieName(state.r), tokens.access_token, tokens.expires_in || 3600),
    setCookie("sec310_pkce", "", 0),
  ]);
}

export const handler = async (event) => {
  const request = event.Records[0].cf.request;
  const host = request.headers.host[0].value;
  const uri = request.uri;
  delete request.headers["x-sec310-access-token"]; // never trust a client-supplied value
  let cfg;
  try {
    cfg = await getConfig();
  } catch (err) {
    console.error("edge config unavailable", err?.name, err?.message);
    return deny(503, "authentication unavailable");
  }
  const jar = cookies(request.headers);
  if (uri === "/auth/login") return authorize(cfg, host, jar);
  if (uri === "/auth/callback") return callback(cfg, host, request.querystring, jar);
  if (uri === "/auth/logout") {
    return redirect(`https://${cfg.domain}/logout?client_id=${cfg.client_id}&logout_uri=${encodeURIComponent(`https://${host}/signed-out`)}`, [
      setCookie(cookieName("op"), "", 0),
      setCookie(cookieName("portal"), "", 0),
    ]);
  }
  if (uri === "/signed-out") return deny(200, "signed out");

  const realm = realmOf(uri);
  let claims = null;
  try {
    claims = await verify(jar[cookieName(realm)], cfg);
  } catch (err) {
    console.error("token verification unavailable", err?.name, err?.message);
    return deny(503, "authentication unavailable");
  }
  if (!claims) return uri.startsWith("/api") ? deny(401, "session expired: reload the page") : startLogin(cfg, host, uri, realm);

  if (uri.startsWith("/api")) {
    request.headers["x-sec310-access-token"] = [{ key: "x-sec310-access-token", value: jar[cookieName(realm)] }];
  } else if (uri === "/" || uri === "/index.html") {
    request.uri = "/index.html";
  } else if (uri === "/portal" || uri === "/portal/") {
    request.uri = "/portal/index.html";
  }
  return request;
};
