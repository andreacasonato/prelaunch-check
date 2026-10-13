import { db } from "@/lib/db";

export async function GET() {
  return Response.json(await db.users.findMany());
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  return Response.json(await db.users.delete({ where: { id } }));
}
