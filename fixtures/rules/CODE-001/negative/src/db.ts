import { pool } from "./pool";

export async function findUser(id: string) {
  return pool.query("SELECT * FROM users WHERE id = $1", [id]);
}

export async function safePrisma(id: string) {
  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}

// pool.query(`SELECT * FROM users WHERE id = ${id}`)  <- old version, commented out
const label = `Selected ${count} items`;
export const url = new URLSearchParams(location.search).get("query");
