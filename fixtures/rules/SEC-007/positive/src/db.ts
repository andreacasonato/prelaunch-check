import { Pool } from "pg";

export const pool = new Pool({
  connectionString: "postgres://admin:__PLC_FAKE_DB_PASSWORD__@db.prod.example.com:5432/app",
});
