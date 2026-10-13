import { createClient } from "@/lib/supabase/server";

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { body } = await req.json();
  await supabase.from("notes").insert({ user_id: user.id, body });
  return Response.json({ ok: true });
}
