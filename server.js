import "dotenv/config";
import express from "express";
import multer from "multer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import OpenAI from "openai";
import nodemailer from "nodemailer";
import helmet from "helmet";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const MODEL = process.env.OPENAI_MODEL || "gpt-5";
const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 8);
const DAILY_ANALYSIS_LIMIT = Number(process.env.DAILY_ANALYSIS_LIMIT || 10);
const APP_URL = String(process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  ...(process.env.DATABASE_SSL === "true" ? { ssl: { rejectUnauthorized: false } } : {})
});

const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
const smtp = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
}) : null;
const FROM_EMAIL = process.env.EMAIL_FROM || process.env.SMTP_USER || "no-reply@example.com";

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
    CREATE TABLE IF NOT EXISTS analyses (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      result_json JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS analyses_user_id_id_idx ON analyses(user_id, id DESC);
    CREATE TABLE IF NOT EXISTS auth_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL CHECK (type IN ('verify','reset')),
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS auth_tokens_lookup_idx ON auth_tokens(token_hash, type, used_at, expires_at);
    CREATE TABLE IF NOT EXISTS rate_limits (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      reset_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS daily_usage (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      usage_date DATE NOT NULL,
      analysis_count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(user_id, usage_date)
    );
  `);
  if (ADMIN_EMAIL) await pool.query("UPDATE users SET role='admin' WHERE email=$1", [ADMIN_EMAIL]);
}

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "same-site" }, referrerPolicy: { policy: "no-referrer" } }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = new Set(["image/png", "image/jpeg", "image/webp"]);
    cb(allowed.has(file.mimetype) ? null : new Error("Only PNG, JPG and WEBP images are allowed."), allowed.has(file.mimetype));
  }
});

function normalizeEmail(v) { return String(v || "").trim().toLowerCase(); }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function hashToken(token) { return crypto.createHash("sha256").update(token).digest("hex"); }
function createToken() { return crypto.randomBytes(32).toString("hex"); }
function sign(user) { return jwt.sign({ sub: String(user.id), email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" }); }
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Authentication required." });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "Session expired. Please sign in again." }); }
}
async function currentUser(req) {
  const r = await pool.query("SELECT id,email,role,email_verified,is_active,created_at FROM users WHERE id=$1", [req.user.sub]);
  return r.rows[0];
}
async function verifiedAuth(req, res, next) {
  const user = await currentUser(req);
  if (!user || !user.is_active) return res.status(403).json({ error: "Account is unavailable." });
  if (!user.email_verified) return res.status(403).json({ error: "Please verify your email before using the analyzer." });
  req.account = user; next();
}
function adminAuth(req, res, next) {
  auth(req, res, async () => {
    const user = await currentUser(req);
    if (!user || !user.is_active || user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
    req.account = user; next();
  });
}
async function rateLimit(key, limit, windowMs) {
  const now = new Date();
  const reset = new Date(now.getTime() + windowMs);
  const r = await pool.query(`
    INSERT INTO rate_limits(key,count,reset_at) VALUES($1,1,$2)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN rate_limits.reset_at <= NOW() THEN 1 ELSE rate_limits.count + 1 END,
      reset_at = CASE WHEN rate_limits.reset_at <= NOW() THEN EXCLUDED.reset_at ELSE rate_limits.reset_at END
    RETURNING count, reset_at`, [key, reset]);
  const row = r.rows[0];
  return { allowed: row.count <= limit, retryAfter: Math.max(1, Math.ceil((new Date(row.reset_at).getTime() - Date.now()) / 1000)) };
}
async function limitMiddleware(name, limit, windowMs) {
  return async (req, res, next) => {
    try {
      const identity = req.user?.sub || req.ip || "unknown";
      const rl = await rateLimit(`${name}:${identity}`, limit, windowMs);
      if (!rl.allowed) { res.set("Retry-After", String(rl.retryAfter)); return res.status(429).json({ error: "Too many requests. Please try again later." }); }
      next();
    } catch { res.status(503).json({ error: "Rate limiter unavailable." }); }
  };
}
const authRate = (limit, ms) => (req, res, next) => { rateLimit(`ip:${req.ip}:${req.path}`, limit, ms).then(x => x.allowed ? next() : (res.set("Retry-After", String(x.retryAfter)), res.status(429).json({error:"Too many requests. Please try again later."}))).catch(()=>res.status(503).json({error:"Rate limiter unavailable."})); };

async function sendMail(to, subject, html) {
  if (!smtp) throw new Error("SMTP is not configured.");
  await smtp.sendMail({ from: FROM_EMAIL, to, subject, html });
}
async function issueToken(userId, type, hours) {
  await pool.query("DELETE FROM auth_tokens WHERE user_id=$1 AND type=$2 AND (used_at IS NOT NULL OR expires_at < NOW())", [userId, type]);
  const raw = createToken();
  await pool.query("INSERT INTO auth_tokens(user_id,token_hash,type,expires_at) VALUES($1,$2,$3,NOW()+($4 * INTERVAL '1 hour'))", [userId, hashToken(raw), type, hours]);
  return raw;
}
function safeResult(text) {
  const cleaned = text.trim().replace(/^```json/i, "").replace(/^```/i, "").replace(/```$/i, "").trim();
  const start = cleaned.indexOf("{"); const end = cleaned.lastIndexOf("}");
  if (start < 0 || end < start) throw new Error("AI returned an invalid result.");
  return JSON.parse(cleaned.slice(start, end + 1));
}

app.post("/api/auth/register", authRate(5, 15 * 60 * 1000), async (req,res)=>{
  const email=normalizeEmail(req.body.email), password=String(req.body.password||"");
  if(!validEmail(email)) return res.status(400).json({error:"Enter a valid email."});
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  try {
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query("INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role",[email,hash]);
    const user=r.rows[0];
    if(ADMIN_EMAIL && email===ADMIN_EMAIL) await pool.query("UPDATE users SET role='admin' WHERE id=$1",[user.id]);
    const raw=await issueToken(user.id,"verify",24);
    const verifyUrl=`${APP_URL}/verify-email?token=${encodeURIComponent(raw)}`;
    try { await sendMail(email,"Verify your Instant Virtuals account",`<p>Welcome to Instant Virtuals.</p><p><a href="${verifyUrl}">Verify your email</a>. This link expires in 24 hours.</p>`); }
    catch(e){ await pool.query("DELETE FROM users WHERE id=$1",[user.id]); throw e; }
    res.status(201).json({message:"Account created. Check your email to verify your account."});
  } catch(e) {
 if(e.code==="23505"){ console.error("DUPLICATE CONSTRAINT:",e.constraint,e.detail); return res.status(409).json({error:"An account with that email already exists."}); }
    console.error(e); res.status(500).json({error:"Could not create account."});
  }
});

app.post("/api/auth/login", authRate(10, 15*60*1000), async(req,res)=>{
  const email=normalizeEmail(req.body.email), password=String(req.body.password||"");
  const r=await pool.query("SELECT * FROM users WHERE email=$1",[email]); const user=r.rows[0];
  if(!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Invalid email or password."});
  if(!user.is_active) return res.status(403).json({error:"This account is disabled."});
  if(!user.email_verified) return res.status(403).json({error:"Please verify your email before signing in."});
  res.json({token:sign(user),user:{id:user.id,email:user.email,role:user.role}});
});

app.post("/api/auth/resend-verification", authRate(3,60*60*1000), async(req,res)=>{
  const email=normalizeEmail(req.body.email); const r=await pool.query("SELECT id,email,email_verified FROM users WHERE email=$1",[email]);
  if(r.rows[0] && !r.rows[0].email_verified){ const raw=await issueToken(r.rows[0].id,"verify",24); try{await sendMail(email,"Verify your Instant Virtuals account",`<p><a href="${APP_URL}/verify-email?token=${encodeURIComponent(raw)}">Verify your email</a>. This link expires in 24 hours.</p>`);}catch(e){console.error(e);} }
  res.json({message:"If an unverified account exists for that email, a verification email has been sent."});
});

app.get("/api/auth/verify-email", authRate(20,15*60*1000), async(req,res)=>{
  const token=String(req.query.token||""); const h=hashToken(token);
  const r=await pool.query("SELECT user_id FROM auth_tokens WHERE token_hash=$1 AND type='verify' AND used_at IS NULL AND expires_at>NOW()",[h]);
  if(!r.rows[0]) return res.status(400).json({error:"Verification link is invalid or expired."});
  await pool.query("BEGIN"); try{await pool.query("UPDATE users SET email_verified=true WHERE id=$1",[r.rows[0].user_id]);await pool.query("UPDATE auth_tokens SET used_at=NOW() WHERE token_hash=$1",[h]);await pool.query("COMMIT");res.json({message:"Email verified. You can now sign in."});}catch(e){await pool.query("ROLLBACK");throw e;}
});

app.post("/api/auth/forgot-password", authRate(5,60*60*1000), async(req,res)=>{
  const email=normalizeEmail(req.body.email); const r=await pool.query("SELECT id,email FROM users WHERE email=$1 AND is_active=true",[email]);
  if(r.rows[0]) { const raw=await issueToken(r.rows[0].id,"reset",1); try{await sendMail(email,"Reset your Instant Virtuals password",`<p><a href="${APP_URL}/reset-password?token=${encodeURIComponent(raw)}">Reset your password</a>. This link expires in 1 hour.</p>`);}catch(e){console.error(e);} }
  res.json({message:"If an account exists for that email, a password reset link has been sent."});
});

app.post("/api/auth/reset-password", authRate(10,15*60*1000), async(req,res)=>{
  const token=String(req.body.token||""), password=String(req.body.password||"");
  if(password.length<8) return res.status(400).json({error:"Password must be at least 8 characters."});
  const h=hashToken(token); const r=await pool.query("SELECT user_id FROM auth_tokens WHERE token_hash=$1 AND type='reset' AND used_at IS NULL AND expires_at>NOW()",[h]);
  if(!r.rows[0]) return res.status(400).json({error:"Reset link is invalid or expired."});
  const hash=await bcrypt.hash(password,12); await pool.query("BEGIN"); try{await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2",[hash,r.rows[0].user_id]);await pool.query("UPDATE auth_tokens SET used_at=NOW() WHERE token_hash=$1",[h]);await pool.query("UPDATE auth_tokens SET used_at=NOW() WHERE user_id=$1 AND type='reset' AND used_at IS NULL",[r.rows[0].user_id]);await pool.query("COMMIT");res.json({message:"Password reset successfully. Please sign in."});}catch(e){await pool.query("ROLLBACK");throw e;}
});

app.get("/api/me", auth, async(req,res)=>{ const u=await currentUser(req); if(!u||!u.is_active)return res.status(403).json({error:"Account unavailable."}); res.json({user:u,usage:{limit:DAILY_ANALYSIS_LIMIT}}); });

app.get("/api/analyses", auth, verifiedAuth, async(req,res)=>{
  const r=await pool.query("SELECT id,original_name,result_json,created_at FROM analyses WHERE user_id=$1 ORDER BY id DESC LIMIT 30",[req.user.sub]);
  res.json(r.rows.map(x=>({...x,result:x.result_json})));
});

app.post("/api/analyze", auth, verifiedAuth, authRate(20,60*60*1000), upload.single("image"), async(req,res)=>{
  if(!req.file)return res.status(400).json({error:"Please upload a screenshot."});
  try {
    const usage=await pool.query(`INSERT INTO daily_usage(user_id,usage_date,analysis_count) VALUES($1,CURRENT_DATE,1) ON CONFLICT(user_id,usage_date) DO UPDATE SET analysis_count=daily_usage.analysis_count+1 RETURNING analysis_count`,[req.user.sub]);
    if(usage.rows[0].analysis_count>DAILY_ANALYSIS_LIMIT){ await pool.query("UPDATE daily_usage SET analysis_count=analysis_count-1 WHERE user_id=$1 AND usage_date=CURRENT_DATE",[req.user.sub]); return res.status(429).json({error:`Daily analysis limit reached (${DAILY_ANALYSIS_LIMIT}). Try again tomorrow.`}); }
    if(!openai)return res.status(503).json({error:"AI analysis is not configured."});
    const base64=fs.readFileSync(req.file.path).toString("base64"), dataUrl=`data:${req.file.mimetype};base64,${base64}`;
    const prompt=`You are the analysis engine for Instant Virtuals, a football screenshot analysis service. Inspect the screenshot carefully. Extract only visible virtual-football fixtures/markets. Provide cautious probabilistic analysis. Never claim certainty, guaranteed wins, insider information, or invented teams, odds, scores, or statistics. If unreadable or not football, return empty picks. Return ONLY valid JSON: {"summary":"short explanation","confidence":0,"picks":[{"fixture":"visible fixture or market","selection":"suggested selection","confidence":0,"reason":"brief evidence-based reason"}],"warnings":["important limitations"]}. Confidence 0-100, max 5 picks.`;
    const response=await openai.responses.create({model:MODEL,input:[{role:"user",content:[{type:"input_text",text:prompt},{type:"input_image",image_url:dataUrl,detail:"high"}]}]});
    const result=safeResult(response.output_text); if(!Array.isArray(result.picks))result.picks=[];if(!Array.isArray(result.warnings))result.warnings=[];
    const saved=await pool.query("INSERT INTO analyses(user_id,original_name,result_json) VALUES($1,$2,$3::jsonb) RETURNING id",[req.user.sub,req.file.originalname,JSON.stringify(result)]);
    res.json({id:saved.rows[0].id,result,usage:{used:usage.rows[0].analysis_count,limit:DAILY_ANALYSIS_LIMIT}});
  } catch(e){console.error(e);res.status(500).json({error:"Analysis failed. Please try a clearer screenshot."});}
  finally{try{fs.unlinkSync(req.file.path)}catch{}}
});

app.get("/api/admin/stats", adminAuth, async(req,res)=>{
  const [users,verified,analyses,today]=await Promise.all([
    pool.query("SELECT COUNT(*)::int count FROM users"), pool.query("SELECT COUNT(*)::int count FROM users WHERE email_verified=true"),
    pool.query("SELECT COUNT(*)::int count FROM analyses"), pool.query("SELECT COALESCE(SUM(analysis_count),0)::int count FROM daily_usage WHERE usage_date=CURRENT_DATE")
  ]); res.json({users:users.rows[0].count,verified:verified.rows[0].count,analyses:analyses.rows[0].count,analysesToday:today.rows[0].count,dailyLimit:DAILY_ANALYSIS_LIMIT});
});
app.get("/api/admin/users", adminAuth, async(req,res)=>{const r=await pool.query("SELECT id,email,role,email_verified,is_active,created_at,(SELECT COUNT(*) FROM analyses a WHERE a.user_id=u.id)::int analyses FROM users u ORDER BY id DESC LIMIT 200");res.json(r.rows);});
app.patch("/api/admin/users/:id", adminAuth, async(req,res)=>{const id=req.params.id; const active=req.body.is_active; const role=req.body.role; if(active!==undefined)await pool.query("UPDATE users SET is_active=$1 WHERE id=$2",[Boolean(active),id]); if(role!==undefined && ["user","admin"].includes(role))await pool.query("UPDATE users SET role=$1 WHERE id=$2",[role,id]); res.json({ok:true});});
app.get("/admin", adminAuth, (_req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));

app.get("/health",async(_req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,database:"connected"})}catch{res.status(503).json({ok:false,database:"unavailable"})}});
app.use((err,_req,res,_next)=>{if(err instanceof multer.MulterError||err?.message?.includes("Only PNG"))return res.status(400).json({error:err.message||"Invalid upload."});console.error(err);res.status(500).json({error:"Server error."})});
app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

async function start(){await initDatabase();app.listen(PORT,"0.0.0.0",()=>console.log(`Instant Virtuals running on port ${PORT}`));}
process.on("SIGTERM",async()=>{await pool.end();process.exit(0)});process.on("SIGINT",async()=>{await pool.end();process.exit(0)});
start().catch(e=>{console.error("Startup failed:",e);process.exit(1)});
