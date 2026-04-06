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

    // Validação de telefone brasileiro (quando informado)
    if (whatsapp) {
      const digits = whatsapp.replace(/\D/g, "");
      // Formato básico: 11 dígitos (DDD + 9 + 8) ou 13 dígitos (55 + DDD + 9 + 8)
      const phoneRegex = /^(?:55)?([1-9][1-9])(9\d{8})$/;
      if (!phoneRegex.test(digits)) {
        return new Response(
          JSON.stringify({ error: "Número de WhatsApp inválido. Use o formato (DD) 9XXXX-XXXX." }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Validação real via numverify
      const fullNumber = digits.length === 11 ? `55${digits}` : digits;
      try {
        const nvRes = await fetch(
          `https://api.apilayer.com/number_verification/validate?number=${fullNumber}`,
          { headers: { "apikey": Deno.env.get("NUMVERIFY_API_KEY")! } }
        );
        if (nvRes.ok) {
          const nvData = await nvRes.json();
          if (!nvData.valid) {
            return new Response(
              JSON.stringify({ error: "Número de WhatsApp não existe. Verifique e tente novamente." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }
        }
      } catch {
        // Se numverify falhar, permite seguir (fallback gracioso)
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
