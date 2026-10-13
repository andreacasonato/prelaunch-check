import { pool } from "./pool";

export async function findUser(id: string) {
  return pool.query(`SELECT * FROM users WHERE id = ${id}`);
}

export async function search(term: string) {
  return pool.query("select * from posts where title like '%" + term + "%'");
}

export async function remove(id: string) {
  return prisma.$executeRawUnsafe(`DELETE FROM sessions WHERE id = '${id}'`);
}
