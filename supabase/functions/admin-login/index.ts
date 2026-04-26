import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

function getCorsHeaders(req: Request) {
  const allowedOrigins = (Deno.env.get("ALLOWED_ORIGINS") || "*").split(",");
  const origin = req.headers.get("Origin") || "";
  const allowOrigin = allowedOrigins.includes("*") ? "*" : (allowedOrigins.includes(origin) ? origin : "null");
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
  };
}

function jsonResponse(req: Request, body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
  });
}

async function readJsonObject(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch {
    return null;
  }
}

// Hash SHA-256 simples (sem bcrypt, sem dependências extras)
async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// JWT manual usando Web Crypto (sem djwt)
function base64url(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function createJWT(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = new TextEncoder();

  const headerB64 = base64url(enc.encode(JSON.stringify(header)));
  const payloadB64 = base64url(enc.encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );

  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
  const sigB64 = base64url(new Uint8Array(sig));

  return `${signingInput}.${sigB64}`;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCorsHeaders(req) });
  }

  if (req.method !== "POST") {
    return jsonResponse(req, { error: "Method not allowed" }, 405);
  }

  try {
    const body = await readJsonObject(req);
    if (!body) return jsonResponse(req, { error: "JSON inválido" }, 400);

    const { username, password } = body;

    if (typeof username !== "string" || typeof password !== "string" || !username.trim() || !password) {
      return jsonResponse(req, { error: "Username e password são obrigatórios" }, 400);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data: user, error } = await supabase
      .from("admin_users")
      .select("*")
      .eq("username", username.trim().toLowerCase())
      .single();

    if (error || !user) {
      return jsonResponse(req, { error: "Credenciais inválidas" }, 401);
    }

    const passwordHash = await sha256(password);
    if (passwordHash !== user.password_hash) {
      return jsonResponse(req, { error: "Credenciais inválidas" }, 401);
    }

    const secret = Deno.env.get("ADMIN_JWT_SECRET");
    if (!secret) {
      return jsonResponse(req, { error: "Erro de configuração do servidor" }, 500);
    }
    const now = Math.floor(Date.now() / 1000);
    const token = await createJWT(
      { sub: user.id.toString(), username: user.username, iat: now, exp: now + 86400 },
      secret
    );

    return jsonResponse(req, { token, username: user.username }, 200);
  } catch {
    return jsonResponse(req, { error: "Erro interno" }, 500);
  }
});
