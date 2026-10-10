"use strict";
/* QuestBoss (TagesBoss) server - no external dependencies, Node >= 18 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const DB_FILE = path.join(DATA, "db.json");
const ALLOW_REG_ENV = (process.env.ALLOW_REGISTER || "true") !== "false";
const ADMIN_USER = String(process.env.ADMIN_USER || "admin").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";
const MAX_USERS = parseInt(process.env.MAX_USERS || "1000", 10);
const SESSION_MS = 30 * 24 * 3600 * 1000;
const MAX_BODY = 1024 * 1024;
const COOKIE = "qb_session";
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

fs.mkdirSync(DATA, { recursive: true });
let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); } catch (e) { /* new database */ }
if (!db || typeof db !== "object") db = {};
db.users = db.users || {};
db.sessions = db.sessions || {};
db.settings = db.settings || {};
const allowReg = () => (typeof db.settings.allowReg === "boolean" ? db.settings.allowReg : ALLOW_REG_ENV);

/* ---- Persistence (atomic, batched) ---- */
let writing = false, again = false, timer = null;
function persist() { clearTimeout(timer); timer = setTimeout(flush, 300); }
function flush() {
  if (writing) { again = true; return; }
  writing = true;
  const tmp = DB_FILE + ".tmp";
  fs.writeFile(tmp, JSON.stringify(db), (err) => {
    if (err) { writing = false; console.error("Write error:", err.message); return; }
    fs.rename(tmp, DB_FILE, (e) => {
      writing = false;
      if (e) console.error("Rename failed:", e.message);
      if (again) { again = false; flush(); }
    });
  });
}
function flushSync() { try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); } catch (e) { console.error(e.message); } }

/* ---- Helpers ---- */
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, k) => (e ? rej(e) : res(k))));
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  let h = hits.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
  h.n++;
  return h.n > max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, h] of hits) if (h.reset < now) hits.delete(k);
  let ch = false;
  for (const k of Object.keys(db.sessions)) if (db.sessions[k].exp < now) { delete db.sessions[k]; ch = true; }
  if (ch) persist();
}, 10 * 60 * 1000).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const x = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (x) return x;
  }
  return req.socket.remoteAddress || "?";
}
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function baseHeaders(extra) {
  return Object.assign({
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin"
  }, extra || {});
}
function sendJson(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, baseHeaders(Object.assign({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(body)
  }, extra)));
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("too_big")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch (e) { reject(new Error("bad_json")); }
    });
    req.on("error", reject);
  });
}
function sessionUser(req) {
  const tok = parseCookies(req)[COOKIE];
  if (!tok) return null;
  const s = db.sessions[sha(tok)];
  if (!s || s.exp < Date.now() || !has(db.users, s.u)) return null;
  return { key: s.u, user: db.users[s.u] };
}
function setSession(res, key) {
  const tok = crypto.randomBytes(32).toString("hex");
  db.sessions[sha(tok)] = { u: key, exp: Date.now() + SESSION_MS };
  persist();
  return `${COOKIE}=${tok}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}${COOKIE_SECURE ? "; Secure" : ""}`;
}
function deleteUser(key) {
  const kids = Object.keys(db.users).filter((k) => db.users[k].parent === key);
  [key].concat(kids).forEach((k) => {
    delete db.users[k];
    for (const t of Object.keys(db.sessions)) if (db.sessions[t].u === k) delete db.sessions[t];
  });
}
const USER_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{2,19}$/;

/* ---- Static file ---- */
const INDEX = path.join(__dirname, "public", "index.html");
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
function serveIndex(res) {
  fs.readFile(INDEX, (err, buf) => {
    if (err) { res.writeHead(500, baseHeaders({ "Content-Type": "text/plain" })); res.end("index.html missing"); return; }
    res.writeHead(200, baseHeaders({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      "Content-Security-Policy": CSP
    }));
    res.end(buf);
  });
}

/* ---- Default admin account ---- */
let adminLogged = false;
async function ensureAdmin() {
  if (!USER_RE.test(ADMIN_USER)) { console.error("ADMIN_USER is invalid (3-20 characters: letters, digits, _ and -)."); return; }
  const key = ADMIN_USER.toLowerCase();
  const envOk = ADMIN_PASSWORD.length >= 8 && ADMIN_PASSWORD.length <= 100;
  if (ADMIN_PASSWORD && !envOk) console.error("ADMIN_PASSWORD must be 8 to 100 characters long and is ignored.");
  const u = has(db.users, key) ? db.users[key] : null;
  let pw = "", generated = false;
  if (!u) {
    pw = envOk ? ADMIN_PASSWORD : crypto.randomBytes(9).toString("base64url");
    generated = !envOk;
  } else if (envOk) {
    const m = db.settings.adminEnv;
    let changed = true;
    if (m && m.salt && m.hash) {
      const got = await scrypt(ADMIN_PASSWORD, m.salt), good = Buffer.from(m.hash, "hex");
      changed = !(got.length === good.length && crypto.timingSafeEqual(got, good));
    }
    if (changed || !u.isAdmin) pw = ADMIN_PASSWORD;
  } else if (!u.isAdmin) {
    console.error(`A regular account '${ADMIN_USER}' already exists. Set ADMIN_PASSWORD to turn it into the admin account.`);
    return;
  }
  if (!pw) return;
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = (await scrypt(pw, salt)).toString("hex");
  const rec = { salt, hash, isAdmin: true, role: "adult", mustChange: true };
  if (u) {
    Object.assign(u, rec);
    for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === key) delete db.sessions[k];
  } else db.users[key] = Object.assign({ name: ADMIN_USER, state: {}, created: new Date().toISOString() }, rec);
  if (envOk) db.settings.adminEnv = { salt, hash };
  flushSync();
  adminLogged = true;
  if (generated) {
    try { fs.writeFileSync(path.join(DATA, "admin-initial-password.txt"), `User: ${ADMIN_USER}\nPassword: ${pw}\n(The password must be changed on first login; this file is then deleted.)\n`, { mode: 0o600 }); } catch (e) { /* ignore */ }
    console.log(`Admin account created. User: ${ADMIN_USER}  Password: ${pw}  (also in data/admin-initial-password.txt). The password must be changed on first login.`);
  } else console.log(`Admin account '${ADMIN_USER}' ready (password from ADMIN_PASSWORD, must be changed on first login).`);
}

function adminHint() {
  if (adminLogged || !USER_RE.test(ADMIN_USER)) return;
  const u = has(db.users, ADMIN_USER.toLowerCase()) ? db.users[ADMIN_USER.toLowerCase()] : null;
  if (!u || !u.isAdmin || !u.mustChange) return;
  const f = path.join(DATA, "admin-initial-password.txt");
  console.log(`NOTICE: Admin account '${u.name}' still has its initial password and must change it on first login. ` +
    (fs.existsSync(f) ? "The password is in data/admin-initial-password.txt." : "The password is the value of the ADMIN_PASSWORD variable."));
}

/* ---- Router ---- */
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    const p = url.pathname;

    if (req.method === "GET" && (p === "/" || p === "/index.html")) return serveIndex(res);
    if (req.method === "GET" && p === "/favicon.ico") { res.writeHead(204); return res.end(); }
    if (req.method === "GET" && p === "/healthz") return sendJson(res, 200, { ok: true });
    if (!p.startsWith("/api/")) return sendJson(res, 404, { error: "not_found" });

    if (req.method !== "GET") {
      const origin = req.headers.origin;
      if (origin) {
        let ok = false;
        try { ok = new URL(origin).host === req.headers.host; } catch (e) { /* ignore */ }
        if (!ok) return sendJson(res, 403, { error: "origin" });
      }
      if (!String(req.headers["content-type"] || "").startsWith("application/json"))
        return sendJson(res, 415, { error: "type" });
    }

    if (p === "/api/me" && req.method === "GET") {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 200, { user: null });
      return sendJson(res, 200, { user: s.user.name, role: s.user.role || "adult", admin: !!s.user.isAdmin, mustChange: !!s.user.mustChange, state: s.user.state || {} });
    }

    if (p === "/api/register" && req.method === "POST") {
      const ip = clientIp(req);
      if (limited("reg:" + ip, 10, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      if (!allowReg()) return sendJson(res, 403, { error: "closed" });
      const b = await readBody(req);
      const name = String(b.username || "").trim(), pw = String(b.password || "");
      if (!USER_RE.test(name)) return sendJson(res, 400, { error: "user" });
      const role = b.role === "child" ? "child" : "adult";
      if (pw.length < 8 || pw.length > 100) return sendJson(res, 400, { error: "pass" });
      const key = name.toLowerCase();
      if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
      if (Object.keys(db.users).length >= MAX_USERS) return sendJson(res, 403, { error: "closed" });
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = (await scrypt(pw, salt)).toString("hex");
      if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
      db.users[key] = { name, salt, hash, state: {}, created: new Date().toISOString(), role };
      const cookie = setSession(res, key);
      persist();
      return sendJson(res, 200, { user: name, role, admin: false, mustChange: false, state: {} }, { "Set-Cookie": cookie });
    }

    if (p === "/api/login" && req.method === "POST") {
      const ip = clientIp(req);
      if (limited("ip:" + ip, 20, 15 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      const b = await readBody(req);
      const name = String(b.username || "").trim(), pw = String(b.password || "");
      const key = name.toLowerCase();
      if (!USER_RE.test(name) || pw.length > 100) return sendJson(res, 401, { error: "bad" });
      if (limited("u:" + key, 10, 15 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      const u = has(db.users, key) ? db.users[key] : null;
      const salt = u ? u.salt : "0".repeat(32);
      const got = await scrypt(pw, salt);
      const good = u ? Buffer.from(u.hash, "hex") : Buffer.alloc(64);
      if (!u || good.length !== got.length || !crypto.timingSafeEqual(got, good)) return sendJson(res, 401, { error: "bad" });
      hits.delete("u:" + key);
      const cookie = setSession(res, key);
      return sendJson(res, 200, { user: u.name, role: u.role || "adult", admin: !!u.isAdmin, mustChange: !!u.mustChange, state: u.state || {} }, { "Set-Cookie": cookie });
    }

    if (p === "/api/logout" && req.method === "POST") {
      const tok = parseCookies(req)[COOKIE];
      if (tok && db.sessions[sha(tok)]) { delete db.sessions[sha(tok)]; persist(); }
      return sendJson(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${COOKIE_SECURE ? "; Secure" : ""}` });
    }

    if (p === "/api/state" && req.method === "PUT") {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      if (limited("put:" + s.key, 300, 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      const b = await readBody(req);
      if (!b || typeof b !== "object" || Array.isArray(b)) return sendJson(res, 400, { error: "state" });
      s.user.state = b;
      persist();
      return sendJson(res, 200, { ok: true });
    }

    if (p === "/api/password" && req.method === "POST") {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      if (limited("pw:" + s.key, 10, 15 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      const b = await readBody(req);
      const oldp = String(b.oldPassword || "").slice(0, 100), np = String(b.newPassword || "");
      if (np.length < 8 || np.length > 100) return sendJson(res, 400, { error: "pass" });
      const got = await scrypt(oldp, s.user.salt), good = Buffer.from(s.user.hash, "hex");
      if (got.length !== good.length || !crypto.timingSafeEqual(got, good)) return sendJson(res, 403, { error: "oldbad" });
      if (np === oldp) return sendJson(res, 400, { error: "same" });
      const salt = crypto.randomBytes(16).toString("hex");
      s.user.salt = salt;
      s.user.hash = (await scrypt(np, salt)).toString("hex");
      delete s.user.mustChange;
      const cur = sha(parseCookies(req)[COOKIE] || "");
      for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === s.key && k !== cur) delete db.sessions[k];
      if (s.user.isAdmin) { try { fs.unlinkSync(path.join(DATA, "admin-initial-password.txt")); } catch (e) { /* ignore */ } }
      persist();
      return sendJson(res, 200, { ok: true });
    }

    if (p === "/api/family" || p.startsWith("/api/family/")) {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      if ((s.user.role || "adult") !== "adult") return sendJson(res, 403, { error: "role" });
      const kids = () => Object.keys(db.users).filter((k) => db.users[k].parent === s.key);
      if (p === "/api/family" && req.method === "GET") {
        return sendJson(res, 200, { children: kids().map((k) => { const u = db.users[k]; return { name: u.name, created: u.created, xp: Number((u.state || {}).xp) || 0 }; }) });
      }
      if (p === "/api/family/child" && req.method === "POST") {
        if (limited("fam:" + s.key, 20, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        const name = String(b.username || "").trim(), pw = String(b.password || "");
        if (!USER_RE.test(name)) return sendJson(res, 400, { error: "user" });
        if (pw.length < 8 || pw.length > 100) return sendJson(res, 400, { error: "pass" });
        const key = name.toLowerCase();
        if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
        if (kids().length >= 10) return sendJson(res, 400, { error: "limit" });
        if (Object.keys(db.users).length >= MAX_USERS) return sendJson(res, 403, { error: "closed" });
        const salt = crypto.randomBytes(16).toString("hex");
        const hash = (await scrypt(pw, salt)).toString("hex");
        if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
        db.users[key] = { name, salt, hash, state: {}, created: new Date().toISOString(), role: "child", parent: s.key };
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if ((p === "/api/family/password" || p === "/api/family/delete") && req.method === "POST") {
        const b = await readBody(req);
        const key = String(b.username || "").trim().toLowerCase();
        if (!has(db.users, key) || db.users[key].parent !== s.key) return sendJson(res, 404, { error: "unknown" });
        if (p === "/api/family/delete") { deleteUser(key); persist(); return sendJson(res, 200, { ok: true }); }
        const pw = String(b.password || "");
        if (pw.length < 8 || pw.length > 100) return sendJson(res, 400, { error: "pass" });
        const salt = crypto.randomBytes(16).toString("hex");
        db.users[key].salt = salt;
        db.users[key].hash = (await scrypt(pw, salt)).toString("hex");
        for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === key) delete db.sessions[k];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 404, { error: "not_found" });
    }

    if (p.startsWith("/api/admin/")) {
      const s = sessionUser(req);
      if (!s || !s.user.isAdmin) return sendJson(res, 403, { error: "admin" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      if (p === "/api/admin/users" && req.method === "GET") {
        const users = Object.keys(db.users).map((k) => {
          const u = db.users[k], st = u.state || {};
          return { name: u.name, created: u.created, xp: Number(st.xp) || 0, items: Array.isArray(st.items) ? st.items.length : 0, admin: !!u.isAdmin, role: u.role || "adult" };
        });
        return sendJson(res, 200, { users, allowReg: allowReg() });
      }
      if (p === "/api/admin/registration" && req.method === "POST") {
        const b = await readBody(req);
        db.settings.allowReg = !!b.allow;
        persist();
        return sendJson(res, 200, { ok: true, allowReg: allowReg() });
      }
      if (p === "/api/admin/delete" && req.method === "POST") {
        const b = await readBody(req);
        const key = String(b.username || "").trim().toLowerCase();
        if (!has(db.users, key)) return sendJson(res, 404, { error: "unknown" });
        if (db.users[key].isAdmin) return sendJson(res, 400, { error: "admin" });
        deleteUser(key);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/admin/password" && req.method === "POST") {
        const b = await readBody(req);
        const key = String(b.username || "").trim().toLowerCase(), pw = String(b.password || "");
        if (!has(db.users, key)) return sendJson(res, 404, { error: "unknown" });
        if (pw.length < 8 || pw.length > 100) return sendJson(res, 400, { error: "pass" });
        const salt = crypto.randomBytes(16).toString("hex");
        db.users[key].salt = salt;
        db.users[key].hash = (await scrypt(pw, salt)).toString("hex");
        if (key !== s.key) for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === key) delete db.sessions[k];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 404, { error: "not_found" });
    }

    return sendJson(res, 404, { error: "not_found" });
  } catch (e) {
    if (e && e.message === "too_big") return sendJson(res, 413, { error: "too_big" });
    if (e && e.message === "bad_json") return sendJson(res, 400, { error: "json" });
    console.error(e);
    try { sendJson(res, 500, { error: "server" }); } catch (x) { /* ignore */ }
  }
});

ensureAdmin().catch((e) => console.error("Admin setup failed:", e.message)).then(() => {
  adminHint();
  server.listen(PORT, HOST, () => {
    console.log(`QuestBoss listening on ${HOST}:${PORT} (registration: ${allowReg() ? "open" : "closed"})`);
  });
});
function shutdown() { clearTimeout(timer); flushSync(); process.exit(0); }
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
