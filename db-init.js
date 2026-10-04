import "dotenv/config";
import pg from "pg";
const { Pool } = pg;
const pool = new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:false}:undefined});
try { await pool.query('SELECT 1'); console.log('PostgreSQL connection OK. The application initializes/updates its schema automatically on startup.'); } finally { await pool.end(); }
