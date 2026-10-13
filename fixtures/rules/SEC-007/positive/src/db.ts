import { Pool } from "pg";

export const pool = new Pool({
  connectionString: "__PLC_FAKE_POSTGRES_PROD_URL__",
});
