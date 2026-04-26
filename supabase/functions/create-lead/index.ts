import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  // CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const { name, email, whatsapp, source } = await req.json();

    // Validação
    if (!name || !email || !source) {
      return new Response(
        JSON.stringify({ error: "Campos name, email e source são obrigatórios" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return new Response(
        JSON.stringify({ error: "Email inválido" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validação básica de telefone (E.164: 7-15 dígitos, quando informado)
    if (whatsapp) {
      const digits = whatsapp.replace(/\D/g, "");
      if (digits.length < 7 || digits.length > 15) {
        return new Response(
          JSON.stringify({ error: "Número de telefone inválido." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
    }

    // Validação do domínio via UserCheck
    const domain = email.trim().toLowerCase().split("@")[1];
    try {
      const ucRes = await fetch(`https://api.usercheck.com/domain/${domain}`, {
        headers: { "Authorization": `Bearer ${Deno.env.get("USERCHECK_API_KEY")}` }
      });
      if (ucRes.ok) {
        const ucData = await ucRes.json();
        if (ucData.disposable || !ucData.mx) {
          return new Response(
            JSON.stringify({ error: "Por favor, use um email válido (não temporário)." }),
            { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
      }
    } catch {
      // Se UserCheck falhar, permite seguir (fallback gracioso)
    }

    // Supabase client com service_role (server-side)
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
    );

    const { error } = await supabase.from("leads").insert({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      whatsapp: whatsapp?.trim() || null,
      source,
    });

    if (error) {
      return new Response(
        JSON.stringify({ error: "Erro ao salvar lead" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ success: true }),
      { status: 201, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch {
    return new Response(
      JSON.stringify({ error: "Erro interno" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
