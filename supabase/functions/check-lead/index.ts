import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

function jsonResponse(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    const url = new URL(req.url);
    const email = url.searchParams.get("email");

    if (!email) {
      return jsonResponse({ error: "Parâmetro email é obrigatório" }, 400);
    }

    const cleanedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanedEmail) || cleanedEmail.length > 254) {
      return jsonResponse({ error: "Email inválido" }, 400);
    }

    // Supabase client com service_role (server-side)
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { data, error } = await supabase
      .from("leads")
      .select("id")
      .eq("email", cleanedEmail)
      .limit(1);

    if (error) {
      return jsonResponse({ error: "Erro ao consultar" }, 500);
    }

    return jsonResponse({ exists: data.length > 0 }, 200);
  } catch {
    return jsonResponse({ error: "Erro interno" }, 500);
  }
});
