import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders, status: 204 });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const supabaseUrl = Deno.env.get("PRIVATE_SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("PRIVATE_SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceRoleKey) {
    return new Response(JSON.stringify({ error: "Missing server config" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const authHeader = req.headers.get("Authorization") || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) {
    return new Response(JSON.stringify({ error: "Missing auth token" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false },
  });

  const { data: userData, error: userError } = await supabaseAdmin.auth.getUser(
    token,
  );
  if (userError || !userData?.user) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  let body: { email?: string } = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const email = (body.email || "").trim().toLowerCase();
  if (!email) {
    return new Response(JSON.stringify({ error: "Email is required" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const { data: companyUser, error: companyError } = await supabaseAdmin
    .from("company_users")
    .select("company_id,is_admin")
    .eq("user_id", userData.user.id)
    .maybeSingle();

  if (companyError || !companyUser?.company_id) {
    return new Response(JSON.stringify({ error: "Company not found" }), {
      status: 403,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  if (!companyUser.is_admin) {
    return new Response(JSON.stringify({ error: "Admin access required" }), {
      status: 403,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const { error: upsertError } = await supabaseAdmin
    .from("company_allowed_emails")
    .upsert(
      [{ company_id: companyUser.company_id, email, is_admin: false }],
      { onConflict: "company_id,email" },
    );

  if (upsertError) {
    return new Response(JSON.stringify({ error: upsertError.message }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const inviteResult = await supabaseAdmin.auth.admin.inviteUserByEmail(email, {
    redirectTo: "https://jaybuildsthings.github.io/BinDetectiveV1/set-password.html",
    data: {
      login_url: "https://jaybuildsthings.github.io/BinDetectiveV1/login.html",
      manage_url: "https://jaybuildsthings.github.io/BinDetectiveV1/manage.html",
      dashboard_url:
        "https://jaybuildsthings.github.io/BinDetectiveV1/dashboard.html",
      users_url: "https://jaybuildsthings.github.io/BinDetectiveV1/users.html",
    },
  });

  if (inviteResult.error) {
    const msg = inviteResult.error.message || "Invite failed";
    if (msg.toLowerCase().includes("already been registered")) {
      return new Response(
        JSON.stringify({
          ok: true,
          warning: "User already exists. Access has been granted.",
        }),
        {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }
    return new Response(JSON.stringify({ error: msg }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
