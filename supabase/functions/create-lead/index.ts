import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const VALID_SOURCES = ["prompts", "ferramentas", "the-claw"];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function jsonResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
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

Deno.serve(async (req) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    const body = await readJsonObject(req);
    if (!body) return jsonResponse({ error: "JSON inválido" }, 400);

    const { name, email, whatsapp, source } = body;

    // Validação
    if (typeof name !== "string" || typeof email !== "string" || typeof source !== "string") {
      return jsonResponse({ error: "Campos name, email e source são obrigatórios" }, 400);
    }

    const cleanedName = name.trim();
    const cleanedEmail = email.trim().toLowerCase();
    const cleanedSource = source.trim();
    const cleanedWhatsapp = typeof whatsapp === "string" ? whatsapp.trim() : "";

    if (!cleanedName || cleanedName.length > 120) {
      return jsonResponse({ error: "Nome inválido" }, 400);
    }

    if (!EMAIL_RE.test(cleanedEmail) || cleanedEmail.length > 254) {
      return jsonResponse({ error: "Email inválido" }, 400);
    }

    if (!VALID_SOURCES.includes(cleanedSource)) {
      return jsonResponse({ error: "Origem inválida" }, 400);
    }

    // Validação básica de telefone (E.164: 7-15 dígitos, quando informado)
    if (cleanedWhatsapp) {
      const digits = cleanedWhatsapp.replace(/\D/g, "");
      if (digits.length < 7 || digits.length > 15) {
        return jsonResponse({ error: "Número de telefone inválido." }, 400);
      }
    } else if (whatsapp != null) {
      return jsonResponse({ error: "Número de telefone inválido." }, 400);
    }

    // Validação do domínio via UserCheck
    const usercheckKey = Deno.env.get("USERCHECK_API_KEY");
    if (usercheckKey) {
      const domain = cleanedEmail.split("@")[1];
      try {
        const ucRes = await fetch(`https://api.usercheck.com/domain/${domain}`, {
          headers: { "Authorization": `Bearer ${usercheckKey}` }
        });
        if (ucRes.ok) {
          const ucData = await ucRes.json();
          if (ucData.disposable || !ucData.mx) {
            return jsonResponse({ error: "Por favor, use um email válido (não temporário)." }, 400);
          }
        }
      } catch {
        // Se UserCheck falhar, permite seguir (fallback gracioso)
      }
    }

    // Supabase client com service_role (server-side)
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { error } = await supabase.from("leads").insert({
      name: cleanedName,
      email: cleanedEmail,
      whatsapp: cleanedWhatsapp || null,
      source: cleanedSource,
    });

    if (error) {
      return jsonResponse({ error: "Erro ao salvar lead" }, 500);
    }

    return jsonResponse({ success: true }, 201);
  } catch {
    return jsonResponse({ error: "Erro interno" }, 500);
  }
});
