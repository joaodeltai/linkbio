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
const VALID_HIGHLIGHTS = ["orange", ""];

function isValidUrl(url: string): boolean {
  if (!url) return true;
  try {
    const parsed = new URL(url);
    return ["http:", "https:", "mailto:", "tel:"].includes(parsed.protocol);
  } catch {
    // Allow relative URLs (e.g. "projetos.html")
    return !url.includes(":") || url.startsWith("/");
  }
}

function validateCardBody(body: Record<string, unknown>): string | null {
  if (!body.title || typeof body.title !== "string") return "Título é obrigatório";
  if (!body.page || !VALID_PAGES.includes(body.page as string)) return "Página inválida";
  if (body.link_type && !VALID_LINK_TYPES.includes(body.link_type as string)) return "Tipo de link inválido";
  if (body.status && !VALID_STATUSES.includes(body.status as string)) return "Status inválido";
  if (body.highlight && !VALID_HIGHLIGHTS.includes(body.highlight as string)) return "Destaque inválido";
  if (body.url && !isValidUrl(body.url as string)) return "URL inválida — protocolos permitidos: http, https, mailto, tel";
  return null;
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

    // Check expiry
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return false;

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
    return new Response(
      JSON.stringify({ error: "Não autorizado" }),
      { status: 401, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" } }
    );
  }

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );

  try {
    if (req.method === "GET") {
      const url = new URL(req.url);
      const page = url.searchParams.get("page");
      let query = supabase.from("cards").select("*").order("sort_order", { ascending: true });
      if (page) query = query.eq("page", page);
      const { data, error } = await query;
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 200, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "POST") {
      const body = await req.json();
      const validationError = validateCardBody(body);
      if (validationError) {
        return new Response(JSON.stringify({ error: validationError }), {
          status: 400, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
        });
      }
      const { data, error } = await supabase.from("cards").insert({
        page: body.page, icon: body.icon || null, title: body.title,
        description: body.description || null, url: body.url || null,
        link_type: body.link_type || "external", gate_source: body.gate_source || null,
        status: body.status || null, highlight: body.highlight || null,
        sort_order: body.sort_order || 0, visible: body.visible !== false,
      }).select().single();
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 201, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "PUT") {
      const body = await req.json();
      if (!body.id) {
        return new Response(JSON.stringify({ error: "ID é obrigatório" }), {
          status: 400, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
        });
      }
      const validationError = validateCardBody(body);
      if (validationError) {
        return new Response(JSON.stringify({ error: validationError }), {
          status: 400, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
        });
      }
      const { data, error } = await supabase.from("cards").update({
        page: body.page, icon: body.icon || null, title: body.title,
        description: body.description || null, url: body.url || null,
        link_type: body.link_type || "external", gate_source: body.gate_source || null,
        status: body.status || null, highlight: body.highlight || null,
        sort_order: body.sort_order || 0, visible: body.visible !== false,
        updated_at: new Date().toISOString(),
      }).eq("id", body.id).select().single();
      if (error) throw error;
      return new Response(JSON.stringify(data), {
        status: 200, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
      });
    }

    if (req.method === "DELETE") {
      const body = await req.json();
      if (!body.id) {
        return new Response(JSON.stringify({ error: "ID é obrigatório" }), {
          status: 400, headers: { ...getCorsHeaders(req), "Content-Type": "application/json" },
        });
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
