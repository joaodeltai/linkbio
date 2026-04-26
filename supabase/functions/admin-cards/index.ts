import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

function getCorsHeaders(req: Request) {
  const allowedOrigins = (Deno.env.get("ALLOWED_ORIGINS") || "*").split(",");
  const origin = req.headers.get("Origin") || "";
  const allowOrigin = allowedOrigins.includes("*") ? "*" : (allowedOrigins.includes(origin) ? origin : "null");
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Token",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  };
}

function base64urlDecode(str: string): Uint8Array {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

const VALID_PAGES = ["index", "projetos", "prompts", "ferramentas"];
const VALID_LINK_TYPES = ["external", "internal", "gated"];
const VALID_STATUSES = ["active", "soon", "beta", ""];
const VALID_HIGHLIGHTS = ["orange", "blue", ""];

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

function isValidUrl(url: string): boolean {
  if (!url) return true;
  if (url.startsWith("//")) return false;
  try {
    const parsed = new URL(url, "https://joaoquintana.dev");
    return ["http:", "https:", "mailto:", "tel:"].includes(parsed.protocol);
  } catch {
    // Allow relative URLs (e.g. "projetos.html")
    return !url.includes(":") && !url.startsWith("//");
  }
}

function validateCardBody(body: Record<string, unknown>): string | null {
  if (typeof body.title !== "string" || !body.title.trim() || body.title.length > 160) return "Título é obrigatório";
  if (typeof body.page !== "string" || !VALID_PAGES.includes(body.page)) return "Página inválida";
  if (body.icon != null && typeof body.icon !== "string") return "Ícone inválido";
  if (body.description != null && typeof body.description !== "string") return "Descrição inválida";
  if (body.url != null && typeof body.url !== "string") return "URL inválida";
  if (body.link_type != null && !VALID_LINK_TYPES.includes(body.link_type as string)) return "Tipo de link inválido";
  if (body.gate_source != null && body.gate_source !== "" && !VALID_PAGES.includes(body.gate_source as string)) return "Gate source inválido";
  if (body.status != null && !VALID_STATUSES.includes(body.status as string)) return "Status inválido";
  if (body.highlight != null && !VALID_HIGHLIGHTS.includes(body.highlight as string)) return "Destaque inválido";
  if (body.sort_order != null && (!Number.isInteger(body.sort_order) || body.sort_order < 0)) return "Ordem inválida";
  if (body.visible != null && typeof body.visible !== "boolean") return "Visibilidade inválida";
  if (typeof body.url === "string" && body.url && !isValidUrl(body.url)) return "URL inválida — protocolos permitidos: http, https, mailto, tel";
  return null;
}

function validId(value: unknown): value is number {
  return Number.isInteger(value) && value > 0;
}

function cleanOptionalString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

async function verifyToken(req: Request): Promise<boolean> {
  try {
    const token = req.headers.get("X-Admin-Token");
    if (!token) return false;

    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const secret = Deno.env.get("ADMIN_JWT_SECRET");
    if (!secret) return false;
    const enc = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw", enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );

    const signingInput = `${parts[0]}.${parts[1]}`;
    const signature = base64urlDecode(parts[2]);
    const valid = await crypto.subtle.verify("HMAC", key, signature, enc.encode(signingInput));
    if (!valid) return false;

    const header = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0])));
    if (header.alg !== "HS256" || header.typ !== "JWT") return false;

    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])));
    if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) return false;
    if (typeof payload.sub !== "string" || !payload.sub) return false;

    return true;
  } catch {
    return false;
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCorsHeaders(req) });
  }

  const authenticated = await verifyToken(req);
  if (!authenticated) {
    return jsonResponse(req, { error: "Não autorizado" }, 401);
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  try {
    if (req.method === "GET") {
      const url = new URL(req.url);
      const page = url.searchParams.get("page");
      if (page && !VALID_PAGES.includes(page)) return jsonResponse(req, { error: "Página inválida" }, 400);
      let query = supabase.from("cards").select("*").order("sort_order", { ascending: true });
      if (page) query = query.eq("page", page);
      const { data, error } = await query;
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 200, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "POST") {
      const body = await readJsonObject(req);
      if (!body) return jsonResponse(req, { error: "JSON inválido" }, 400);
      const validationError = validateCardBody(body);
      if (validationError) {
        return jsonResponse(req, { error: validationError }, 400);
      }
      const { data, error } = await supabase.from("cards").insert({
        page: body.page, icon: cleanOptionalString(body.icon), title: (body.title as string).trim(),
        description: cleanOptionalString(body.description), url: cleanOptionalString(body.url),
        link_type: body.link_type || "external", gate_source: cleanOptionalString(body.gate_source),
        status: cleanOptionalString(body.status), highlight: cleanOptionalString(body.highlight),
        sort_order: body.sort_order || 0, visible: body.visible !== false,
      }).select().single();
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 201, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "PUT") {
      const body = await readJsonObject(req);
      if (!body) return jsonResponse(req, { error: "JSON inválido" }, 400);
      if (!validId(body.id)) {
        return jsonResponse(req, { error: "ID é obrigatório" }, 400);
      }
      const validationError = validateCardBody(body);
      if (validationError) {
        return jsonResponse(req, { error: validationError }, 400);
      }
      const { data, error } = await supabase.from("cards").update({
        page: body.page, icon: cleanOptionalString(body.icon), title: (body.title as string).trim(),
        description: cleanOptionalString(body.description), url: cleanOptionalString(body.url),
        link_type: body.link_type || "external", gate_source: cleanOptionalString(body.gate_source),
        status: cleanOptionalString(body.status), highlight: cleanOptionalString(body.highlight),
        sort_order: body.sort_order || 0, visible: body.visible !== false,
        updated_at: new Date().toISOString(),
      }).eq("id", body.id).select().single();
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 200, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "DELETE") {
      const body = await readJsonObject(req);
      if (!body) return jsonResponse(req, { error: "JSON inválido" }, 400);
      if (!validId(body.id)) {
        return jsonResponse(req, { error: "ID é obrigatório" }, 400);
      }
      const { error } = await supabase.from("cards").delete().eq("id", body.id);
      if (error) throw error;
      return new Response(JSON.stringify({ success: true }), {
        status: 200, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
    });
  } catch {
    return new Response(JSON.stringify({ error: "Erro interno" }), {
      status: 500, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
    });
  }
});
