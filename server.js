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
db.suggestions = Array.isArray(db.suggestions) ? db.suggestions : [];
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

/* ---- Families ---- */
db.families = db.families || {};
const DEF_REW = () => [{ id: "r1", k: "rw1", c: 150 }, { id: "r2", k: "rw2", c: 100 }, { id: "r3", k: "rw3", c: 250 }];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const asDate = (v) => (typeof v === "string" && DATE_RE.test(v) ? v : null);
const asArr = (v) => (Array.isArray(v) ? v : []);
const famOf = (u) => (u && typeof u.family === "string" && has(db.families, u.family) ? db.families[u.family] : null);
const isManaged = (u) => !!u && u.role === "child" && typeof u.parent === "string" && has(db.users, u.parent);
const isAdultU = (u) => (u.role || "adult") === "adult";
const FAM_MAX = 20;
function ensureFamily(key) {
  const u = db.users[key];
  let f = famOf(u);
  if (f) return f;
  const own = (u.state && Array.isArray(u.state.rewards) ? u.state.rewards.map((r) => Object.assign({}, r)) : DEF_REW()).map((r) => Object.assign(r, { owner: key, to: [key] }));
  f = { id: "f" + crypto.randomBytes(6).toString("hex"), members: [key], rewards: own, created: new Date().toISOString() };
  db.families[f.id] = f;
  u.family = f.id;
  return f;
}
const keyOfU = (u) => Object.keys(db.users).find((k) => db.users[k] === u) || "";
const rewFor = (f, key) => f.rewards.filter((r) => !Array.isArray(r.to) || r.to.includes(key)).map((r) => { const o = Object.assign({}, r); delete o.to; delete o.owner; return o; });
const canRew = (r, key, adult) => (r.owner ? r.owner === key : adult);
function joinFamily(f, key) {
  if (!f.members.includes(key)) f.members.push(key);
  db.users[key].family = f.id;
}
function purgeAssigned(key) {
  for (const k of Object.keys(db.users)) {
    const u = db.users[k];
    const gone = asArr(u.assigned).filter((a) => k === key || a.byKey === key).map((a) => a.id);
    if (!gone.length) continue;
    u.assigned = asArr(u.assigned).filter((a) => !gone.includes(a.id));
    if (u.state) u.state.items = asArr(u.state.items).filter((i) => !(i && gone.includes(i.id)));
    u.grants = asArr(u.grants).filter((g) => !gone.includes(g.id));
  }
}
function leaveFamily(key) {
  const u = db.users[key], f = famOf(u);
  if (!u) return;
  purgeAssigned(key);
  if (f) {
    for (const rk of Object.keys(f.res || {})) if (rk.startsWith(key + "|") || f.res[rk] === key) delete f.res[rk];
    for (const dk of Object.keys(f.disp || {})) if (dk === key || f.disp[dk] === key) delete f.disp[dk];
    f.members = f.members.filter((m) => m !== key);
    f.rewards = f.rewards.filter((r) => r.owner !== key);
    for (const r of f.rewards) if (Array.isArray(r.to)) r.to = r.to.filter((m) => m !== key);
    f.plans = asArr(f.plans).filter((p) => p.owner !== key);
    if (!f.members.length) delete db.families[f.id];
    else syncPlans(f);
  }
  delete u.family;
}
function weekDone(st) {
  const act = st && st.act && typeof st.act === "object" ? st.act : {};
  let n = 0;
  for (let i = 0; i < 7; i++) {
    const d = new Date(Date.now() - i * 864e5).toISOString().slice(0, 10);
    if (has(act, d)) n += Math.max(0, Math.min(1000, Number(act[d]) || 0));
  }
  return n;
}
/* ---- Rotating plans ---- */
const ymdOf = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const dnum = (y) => { const a = y.split("-").map(Number); return Math.floor(Date.UTC(a[0], a[1] - 1, a[2]) / 864e5); };
const SIZE_XP = { easy: 10, mid: 20, boss: 40 };
function planIdx(p, y) { const a = dnum(y), b = dnum(p.start); return p.period === "daily" ? a - b : Math.floor((a + 3) / 7) - Math.floor((b + 3) / 7); }
function planWho(p, ci, y) { const n = p.members.length; return n ? p.members[(((planIdx(p, y) + ci) % n) + n) % n] : null; }
function syncPlans(f) {
  if (!f) return;
  const today = ymdOf(new Date());
  f.plans = asArr(f.plans).filter((p) => p && has(db.users, p.owner) && f.members.includes(p.owner));
  for (const p of f.plans) p.members = asArr(p.members).filter((m) => f.members.includes(m) && has(db.users, m));
  f.plans = f.plans.filter((p) => p.members.length);
  const want = {};
  for (const p of f.plans) {
    asArr(p.chores).forEach((c, ci) => {
      const who = planWho(p, ci, today);
      if (!who) return;
      (want[who] = want[who] || []).push({ id: "p" + p.id + "_" + c.id, t: c.t, kind: "task", rec: p.rec, date: p.start, days: p.rec === "weekly" ? p.days : [], dom: Number(p.start.slice(8, 10)), time: "", xp: SIZE_XP[p.size] || 20, ap: !!p.ap, by: p.name, byKey: p.owner, plan: p.id });
    });
  }
  for (const m of f.members) {
    const u = db.users[m];
    if (!u) continue;
    const w = want[m] || [], wid = new Set(w.map((x) => x.id));
    const drop = asArr(u.assigned).filter((a) => a.plan && !wid.has(a.id)).map((a) => a.id);
    if (drop.length) {
      u.assigned = asArr(u.assigned).filter((a) => !drop.includes(a.id));
      if (u.state) u.state.items = asArr(u.state.items).filter((i) => !(i && drop.includes(i.id)));
      u.grants = asArr(u.grants).filter((g) => !drop.includes(g.id));
    }
    for (const it of w) {
      const pub = Object.assign({}, it);
      delete pub.byKey;
      const ex = asArr(u.assigned).find((a) => a.id === it.id);
      u.state = u.state && typeof u.state === "object" ? u.state : {};
      if (!ex) {
        u.assigned = asArr(u.assigned).concat([it]);
        u.state.items = asArr(u.state.items).concat([pub]);
      } else if (JSON.stringify(ex) !== JSON.stringify(it)) {
        Object.assign(ex, it);
        const si = asArr(u.state.items).find((i) => i && i.id === it.id);
        if (si) Object.assign(si, pub);
      }
    }
  }
}
function enforceState(u, st) {
  const old = u.state && typeof u.state === "object" ? u.state : {};
  const f = famOf(u), managed = isManaged(u);
  if (f) st.rewards = rewFor(f, keyOfU(u));
  if (managed) st.pin = "";
  const clean = (list, n) => asArr(list).slice(0, n).filter((w) => w && typeof w === "object").map((w) => ({ id: String(w.id || "").slice(0, 24), t: String(w.t || "").slice(0, 60), p: String(w.p || "").slice(0, 20), done: !!w.done })).filter((w) => w.id && w.t);
  st.wishes = clean(st.wishes, 50);
  st.shop = f ? [] : clean(st.shop, 200);
  const asg = asArr(u.assigned);
  const grantKeys = new Set(asArr(u.grants).filter((g) => g.type === "ok").map((g) => g.id + "|" + g.d));
  const given = asArr(st.items).filter((i) => i && typeof i === "object");
  const cur = new Map(given.filter((i) => typeof i.id === "string").map((i) => [i.id, i]));
  const prev = new Map(asArr(old.items).filter((i) => i && typeof i.id === "string").map((i) => [i.id, i]));
  const mine = given.filter((i) => !has(i, "by") && !has(i, "byKey")).slice(0, 500);
  if (managed) mine.forEach((i) => { i.ap = false; });
  const out = asg.map((a) => {
    const c = cur.get(a.id) || {}, p = prev.get(a.id) || {};
    const it = Object.assign({}, a);
    delete it.byKey;
    let pendOn = asDate(c.pendOn), doneOn = asDate(c.doneOn);
    if (a.rec === "once" && a.ap) {
      if (p.doneOn) doneOn = asDate(p.doneOn);
      else if (doneOn && !grantKeys.has(a.id + "|" + doneOn)) doneOn = null;
    }
    if (pendOn) it.pendOn = pendOn;
    if (doneOn) it.doneOn = doneOn;
    return it;
  });
  st.items = mine.concat(out);
  const apRec = asg.filter((a) => a.ap && a.rec !== "once");
  if (apRec.length) {
    if (!st.done || typeof st.done !== "object" || Array.isArray(st.done)) st.done = {};
    const od = old.done && typeof old.done === "object" ? old.done : {};
    for (const a of apRec) {
      for (const d of Object.keys(st.done)) {
        if (d === "__proto__" || !Array.isArray(st.done[d])) continue;
        const was = has(od, d) && Array.isArray(od[d]) && od[d].includes(a.id);
        if (st.done[d].includes(a.id) && !was && !grantKeys.has(a.id + "|" + d)) st.done[d] = st.done[d].filter((x) => x !== a.id);
      }
      for (const d of Object.keys(od)) {
        if (d === "__proto__" || !Array.isArray(od[d]) || !od[d].includes(a.id)) continue;
        if (!Array.isArray(st.done[d])) st.done[d] = [];
        if (!st.done[d].includes(a.id)) st.done[d].push(a.id);
      }
    }
  }
  capRewards(u, f, st, old, out, asg);
}
function capRewards(u, f, st, old, out, asg) {
  if (!f || (u.role || "adult") !== "child") return;
  let gain = 0;
  const prevItems = new Map(asArr(old.items).filter((i) => i && typeof i.id === "string").map((i) => [i.id, i]));
  const od = old.done && typeof old.done === "object" ? old.done : {};
  for (const a of asg) {
    if (a.rec === "once") {
      const c = out.find((i) => i.id === a.id), p = prevItems.get(a.id) || {};
      if (c && c.doneOn && !p.doneOn) gain += Number(a.xp) || 0;
    } else if (st.done && typeof st.done === "object") {
      for (const d of Object.keys(st.done)) {
        if (d === "__proto__" || !Array.isArray(st.done[d]) || !st.done[d].includes(a.id)) continue;
        if (!(has(od, d) && Array.isArray(od[d]) && od[d].includes(a.id))) gain += Number(a.xp) || 0;
      }
    }
  }
  const ox = Math.max(0, Number(old.xp) || 0), oc = Math.max(0, Number(old.coins) || 0);
  st.xp = Math.max(0, Math.min(Number(st.xp) || 0, ox + gain));
  st.coins = Math.max(0, Math.min(Number(st.coins) || 0, oc + gain));
}
function pendingFor(u, approverKey) {
  const st = u.state || {}, out = [];
  const grants = new Set(asArr(u.grants).map((g) => g.id + "|" + g.d));
  for (const a of asArr(u.assigned)) {
    if (!a.ap || a.byKey !== approverKey) continue;
    if (a.rec === "once") {
      const it = asArr(st.items).find((i) => i && i.id === a.id);
      if (it && it.pendOn && !it.doneOn && !grants.has(a.id + "|" + it.pendOn)) out.push({ id: a.id, t: a.t, d: it.pendOn, xp: a.xp });
    } else if (st.pend && typeof st.pend === "object") {
      for (const d of Object.keys(st.pend)) {
        if (d === "__proto__" || !Array.isArray(st.pend[d]) || !st.pend[d].includes(a.id)) continue;
        if (!grants.has(a.id + "|" + d)) out.push({ id: a.id, t: a.t, d, xp: a.xp });
      }
    }
  }
  return out.sort((x, y) => x.d.localeCompare(y.d)).slice(0, 100);
}
function meInfo(u) {
  const f = famOf(u);
  syncPlans(f);
  const st = u.state && typeof u.state === "object" ? u.state : (u.state = {});
  if (f) st.rewards = rewFor(f, keyOfU(u));
  if (isManaged(u)) st.pin = "";
  const now = Date.now();
  u.invites = asArr(u.invites).filter((i) => now - i.ts < 14 * 864e5 && has(db.users, i.fromKey));
  return { user: u.name, role: u.role || "adult", admin: !!u.isAdmin, mustChange: !!u.mustChange, managed: isManaged(u), inFamily: !!f, grants: asArr(u.grants), invites: u.invites.map((i) => ({ id: i.id, from: i.from })), state: st };
}
/* migrate 1.1.0 data: children created by an adult share that adult's family */
for (const k of Object.keys(db.users)) {
  const u = db.users[k];
  if (u.parent && has(db.users, u.parent) && !famOf(u)) joinFamily(ensureFamily(u.parent), k);
}

function deleteUser(key) {
  const kids = Object.keys(db.users).filter((k) => db.users[k].parent === key);
  [key].concat(kids).forEach((k) => {
    leaveFamily(k);
    delete db.users[k];
    for (const t of Object.keys(db.sessions)) if (db.sessions[t].u === k) delete db.sessions[t];
    for (const o of Object.keys(db.users)) db.users[o].invites = asArr(db.users[o].invites).filter((i) => i.fromKey !== k);
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
  const rec = { salt, hash, isAdmin: true, role: "adult" };
  if (!envOk) rec.mustChange = true;
  if (u) {
    Object.assign(u, rec);
    if (envOk) delete u.mustChange;
    for (const k of Object.keys(db.sessions)) if (db.sessions[k].u === key) delete db.sessions[k];
  } else db.users[key] = Object.assign({ name: ADMIN_USER, state: {}, created: new Date().toISOString() }, rec);
  if (envOk) db.settings.adminEnv = { salt, hash };
  flushSync();
  adminLogged = true;
  if (generated) {
    try { fs.writeFileSync(path.join(DATA, "admin-initial-password.txt"), `User: ${ADMIN_USER}\nPassword: ${pw}\n(The password must be changed on first login; this file is then deleted.)\n`, { mode: 0o600 }); } catch (e) { /* ignore */ }
    console.log(`Admin account created. User: ${ADMIN_USER}  Password: ${pw}  (also in data/admin-initial-password.txt). The password must be changed on first login.`);
  } else console.log(`Admin account '${ADMIN_USER}' ready (password from ADMIN_PASSWORD, no forced change).`);
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
      return sendJson(res, 200, meInfo(s.user));
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
      return sendJson(res, 200, meInfo(u), { "Set-Cookie": cookie });
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
      syncPlans(famOf(s.user));
      enforceState(s.user, b);
      s.user.state = b;
      persist();
      return sendJson(res, 200, { ok: true });
    }

    if (p === "/api/ack" && req.method === "POST") {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      const b = await readBody(req);
      const ids = new Set(asArr(b.ids).map(String));
      s.user.grants = asArr(s.user.grants).filter((g) => !ids.has(g.n));
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

    if (p === "/api/suggest" && req.method === "POST") {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      if (limited("sug:" + s.key, 10, 24 * 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
      const b = await readBody(req);
      const text = String(b.text || "").trim().slice(0, 500);
      if (text.length < 3) return sendJson(res, 400, { error: "text" });
      if (db.suggestions.length >= 500) return sendJson(res, 400, { error: "limit" });
      db.suggestions.push({ id: "g" + crypto.randomBytes(5).toString("hex"), user: s.user.name, text, ts: new Date().toISOString(), done: false });
      persist();
      return sendJson(res, 200, { ok: true });
    }

    if (p === "/api/family" || p.startsWith("/api/family/")) {
      const s = sessionUser(req);
      if (!s) return sendJson(res, 401, { error: "auth" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      const me = s.user, adult = isAdultU(me);
      const mine = () => famOf(me);
      const memberOf = (name) => {
        const key = String(name || "").trim().toLowerCase(), f = mine();
        if (!f || key === s.key || !has(db.users, key) || !f.members.includes(key)) return null;
        return { key, u: db.users[key] };
      };
      const nmK = (k) => (k && has(db.users, k) ? db.users[k].name : "");
      const rewList = (f) => f.rewards.filter((r) => !Array.isArray(r.to) || r.to.includes(s.key) || r.owner === s.key).map((r) => ({
        id: r.id, k: r.k || "", n: r.n || "", c: r.c, mine: canRew(r, s.key, adult), forMe: !Array.isArray(r.to) || r.to.includes(s.key),
        from: r.owner && r.owner !== s.key ? nmK(r.owner) : "",
        to: Array.isArray(r.to) ? r.to.map(nmK).filter(Boolean) : f.members.map(nmK)
      }));
      if (p === "/api/family" && req.method === "GET") {
        const f = mine();
        if (!f) return sendJson(res, 200, { inFamily: false, members: [], rewards: [], shop: [], plans: [] });
        syncPlans(f);
        const members = f.members.filter((m) => has(db.users, m)).map((m) => {
          const u = db.users[m], st = u.state || {}, self = m === s.key;
          return {
            name: u.name, role: u.role || "adult", me: self, managed: isManaged(u), mine: u.parent === s.key,
            xp: Number(st.xp) || 0, created: u.created, week: weekDone(st),
            dispute: (f.disp && has(f.disp, m) && has(db.users, f.disp[m])) ? { by: db.users[f.disp[m]].name } : null,
            wishes: self ? [] : asArr(st.wishes).map((w) => { const rk = m + "|" + w.id, who = (f.res || {})[rk]; return { id: w.id, t: w.t, p: w.p, res: who && has(db.users, who) ? db.users[who].name : "", mineRes: who === s.key }; }),
            pending: self ? [] : pendingFor(u, s.key),
            tasks: self ? [] : asArr(u.assigned).filter((a) => a.byKey === s.key && !a.plan).map((a) => ({ id: a.id, t: a.t, kind: a.kind, rec: a.rec, date: a.date, time: a.time, xp: a.xp, ap: !!a.ap }))
          };
        });
        const nm = (k) => (k && has(db.users, k) ? db.users[k].name : "");
        const tomorrow = ymdOf(new Date(Date.now() + 864e5)), nextWeek = ymdOf(new Date(Date.now() + 7 * 864e5));
        const plansOut = asArr(f.plans).map((pl) => ({
          id: pl.id, name: pl.name, period: pl.period, rec: pl.rec, days: pl.days, size: pl.size, ap: !!pl.ap, owner: nm(pl.owner),
          members: pl.members.map(nm),
          chores: asArr(pl.chores).map((c, ci) => ({ id: c.id, t: c.t, now: nm(planWho(pl, ci, ymdOf(new Date()))), next: nm(planWho(pl, ci, pl.period === "daily" ? tomorrow : nextWeek)) }))
        }));
        return sendJson(res, 200, { inFamily: true, members, rewards: rewList(f), shop: asArr(f.shop), plans: plansOut });
      }
      if (p === "/api/family/task" && req.method === "POST") {
        if (limited("ftask:" + s.key, 120, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        const names = asArr(b.usernames).concat(b.username ? [b.username] : []).slice(0, 12);
        const targets = [];
        for (const n of names) { const m = memberOf(n); if (m && !targets.some((x) => x.key === m.key)) targets.push(m); }
        if (!targets.length) return sendJson(res, 404, { error: "unknown" });
        const title = String(b.title || "").trim().slice(0, 80);
        if (!title) return sendJson(res, 400, { error: "title" });
        const kind = b.kind === "event" ? "event" : "task";
        const rec = ["once", "daily", "weekly", "monthly"].includes(b.rec) ? b.rec : "once";
        const date = asDate(b.date);
        if (!date) return sendJson(res, 400, { error: "date" });
        let days = asArr(b.days).map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6);
        days = [...new Set(days)].sort();
        const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.time || "")) ? String(b.time) : "";
        const xp = kind === "event" ? 10 : ({ easy: 10, mid: 20, boss: 40 })[b.size] || 20;
        if (targets.some((m) => asArr(m.u.assigned).length >= 200)) return sendJson(res, 400, { error: "limit" });
        const dom = Number(date.slice(8, 10));
        const dow = new Date(date + "T12:00:00Z").getUTCDay();
        for (const m of targets) {
          const u = m.u;
          const it = { id: "a" + crypto.randomBytes(6).toString("hex"), t: title, kind, rec, date, days: rec === "weekly" ? (days.length ? days : [dow]) : [], dom, time, xp, ap: !!b.ap, by: me.name, byKey: s.key };
          u.assigned = asArr(u.assigned).concat([it]);
          u.state = u.state && typeof u.state === "object" ? u.state : {};
          const pub = Object.assign({}, it); delete pub.byKey;
          u.state.items = asArr(u.state.items).concat([pub]);
        }
        persist();
        return sendJson(res, 200, { ok: true, count: targets.length });
      }
      if (p === "/api/family/taskdel" && req.method === "POST") {
        const b = await readBody(req);
        const m = memberOf(b.username);
        if (!m) return sendJson(res, 404, { error: "unknown" });
        const id = String(b.id || ""), u = m.u;
        if (!asArr(u.assigned).some((a) => a.id === id && a.byKey === s.key && !a.plan)) return sendJson(res, 404, { error: "unknown" });
        u.assigned = asArr(u.assigned).filter((a) => a.id !== id);
        if (u.state) u.state.items = asArr(u.state.items).filter((i) => !(i && i.id === id));
        u.grants = asArr(u.grants).filter((g) => g.id !== id);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if ((p === "/api/family/confirm" || p === "/api/family/reject") && req.method === "POST") {
        const b = await readBody(req);
        const m = memberOf(b.username);
        if (!m) return sendJson(res, 404, { error: "unknown" });
        const id = String(b.id || ""), d = asDate(b.d), u = m.u;
        if (!d || !pendingFor(u, s.key).some((x) => x.id === id && x.d === d)) return sendJson(res, 404, { error: "unknown" });
        if (asArr(u.grants).length >= 200) return sendJson(res, 400, { error: "limit" });
        u.grants = asArr(u.grants).concat([{ n: crypto.randomBytes(6).toString("hex"), type: p.endsWith("confirm") ? "ok" : "no", id, d }]);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/reward" && req.method === "POST") {
        const f = mine();
        if (!f) return sendJson(res, 403, { error: "role" });
        const b = await readBody(req);
        const n = String(b.name || "").trim().slice(0, 40), c = Math.floor(Number(b.cost));
        if (!n || !(c > 0) || c > 100000) return sendJson(res, 400, { error: "reward" });
        if (f.rewards.length >= 100) return sendJson(res, 400, { error: "limit" });
        let to = [];
        for (const nm of asArr(b.to).slice(0, 30)) {
          const k = String(nm || "").trim().toLowerCase();
          if (has(db.users, k) && f.members.includes(k) && !to.includes(k)) to.push(k);
        }
        if (!adult) to = to.filter((k) => k !== s.key);
        if (!to.length) { if (adult) to = [s.key]; else return sendJson(res, 400, { error: "to" }); }
        f.rewards.push({ id: "r" + crypto.randomBytes(5).toString("hex"), n, c, owner: s.key, to });
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/rewardto" && req.method === "POST") {
        const f = mine();
        if (!f) return sendJson(res, 403, { error: "role" });
        const b = await readBody(req);
        const r = f.rewards.find((x) => x.id === String(b.id || ""));
        const k = String(b.username || "").trim().toLowerCase();
        if (!r || !canRew(r, s.key, adult) || !has(db.users, k) || !f.members.includes(k)) return sendJson(res, 403, { error: "role" });
        if (!adult && k === s.key) return sendJson(res, 403, { error: "role" });
        if (!Array.isArray(r.to)) r.to = f.members.slice();
        if (b.on) { if (!r.to.includes(k)) r.to.push(k); } else r.to = r.to.filter((m) => m !== k);
        if (!r.to.length) f.rewards = f.rewards.filter((x) => x !== r);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/rewarddel" && req.method === "POST") {
        const f = mine();
        if (!f) return sendJson(res, 403, { error: "role" });
        const b = await readBody(req);
        const r = f.rewards.find((x) => x.id === String(b.id || ""));
        if (!r || !canRew(r, s.key, adult)) return sendJson(res, 403, { error: "role" });
        f.rewards = f.rewards.filter((x) => x !== r);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/child" && req.method === "POST") {
        if (!adult) return sendJson(res, 403, { error: "role" });
        if (limited("fam:" + s.key, 20, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        const name = String(b.username || "").trim(), pw = String(b.password || "");
        if (!USER_RE.test(name)) return sendJson(res, 400, { error: "user" });
        if (pw.length < 8 || pw.length > 100) return sendJson(res, 400, { error: "pass" });
        const key = name.toLowerCase();
        if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
        if (Object.keys(db.users).filter((k) => db.users[k].parent === s.key).length >= 10) return sendJson(res, 400, { error: "limit" });
        if (Object.keys(db.users).length >= MAX_USERS) return sendJson(res, 403, { error: "closed" });
        const f0 = ensureFamily(s.key);
        if (f0.members.length >= FAM_MAX) return sendJson(res, 400, { error: "limit" });
        const salt = crypto.randomBytes(16).toString("hex");
        const hash = (await scrypt(pw, salt)).toString("hex");
        if (has(db.users, key)) return sendJson(res, 409, { error: "taken" });
        db.users[key] = { name, salt, hash, state: {}, created: new Date().toISOString(), role: "child", parent: s.key };
        joinFamily(ensureFamily(s.key), key);
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
      if (p === "/api/family/dispute" && req.method === "POST") {
        const f = mine();
        if (!f || !adult) return sendJson(res, 403, { error: "role" });
        const b = await readBody(req);
        const m = memberOf(b.username);
        if (!m) return sendJson(res, 404, { error: "unknown" });
        if ((m.u.role || "adult") !== "child") return sendJson(res, 400, { error: "adult" });
        f.disp = f.disp && typeof f.disp === "object" ? f.disp : {};
        if (b.on) f.disp[m.key] = s.key; else delete f.disp[m.key];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/plan" && req.method === "POST") {
        const f = mine();
        if (!f || !adult) return sendJson(res, 403, { error: "role" });
        if (limited("plan:" + s.key, 60, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        if (b.op === "del") {
          f.plans = asArr(f.plans).filter((x) => x.id !== String(b.id || ""));
          syncPlans(f);
          persist();
          return sendJson(res, 200, { ok: true });
        }
        const name = String(b.name || "").trim().slice(0, 40);
        const period = b.period === "daily" ? "daily" : "weekly";
        const rec = b.rec === "weekly" ? "weekly" : "daily";
        const today = ymdOf(new Date());
        let days = asArr(b.days).map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n <= 6);
        days = [...new Set(days)].sort();
        if (rec === "weekly" && !days.length) days = [new Date().getDay()];
        const size = ["easy", "mid", "boss"].includes(b.size) ? b.size : "mid";
        const keys = [];
        for (const n of asArr(b.members)) {
          const k = String(n || "").trim().toLowerCase();
          if (has(db.users, k) && f.members.includes(k) && !keys.includes(k)) keys.push(k);
        }
        const chores = asArr(b.chores).map((x) => String(x || "").trim().slice(0, 60)).filter(Boolean).slice(0, 20);
        if (!name || !keys.length || keys.length > 12 || !chores.length) return sendJson(res, 400, { error: "plan" });
        if (asArr(f.plans).length >= 20) return sendJson(res, 400, { error: "limit" });
        f.plans = asArr(f.plans).concat([{ id: crypto.randomBytes(4).toString("hex"), name, period, rec, days: rec === "weekly" ? days : [], size, ap: !!b.ap, members: keys, chores: chores.map((t) => ({ id: crypto.randomBytes(3).toString("hex"), t })), owner: s.key, start: today }]);
        syncPlans(f);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/shop" && req.method === "POST") {
        const f = mine();
        if (!f) return sendJson(res, 403, { error: "nofamily" });
        if (limited("shop:" + s.key, 300, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        f.shop = asArr(f.shop);
        const id = String(b.id || "");
        if (b.op === "add") {
          const t = String(b.t || "").trim().slice(0, 60);
          if (!t) return sendJson(res, 400, { error: "title" });
          if (f.shop.length >= 200) return sendJson(res, 400, { error: "limit" });
          f.shop.push({ id: "s" + crypto.randomBytes(5).toString("hex"), t, done: false, by: me.name });
        } else if (b.op === "toggle") {
          const it = f.shop.find((x) => x.id === id);
          if (it) it.done = !it.done;
        } else if (b.op === "del") {
          f.shop = f.shop.filter((x) => x.id !== id);
        } else if (b.op === "clear") {
          f.shop = f.shop.filter((x) => !x.done);
        } else return sendJson(res, 400, { error: "op" });
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/wishres" && req.method === "POST") {
        const f = mine();
        const b = await readBody(req);
        const m = memberOf(b.username);
        if (!f || !m) return sendJson(res, 404, { error: "unknown" });
        const id = String(b.id || ""), rk = m.key + "|" + id;
        if (!asArr(m.u.state && m.u.state.wishes).some((w) => w && w.id === id)) return sendJson(res, 404, { error: "unknown" });
        f.res = f.res && typeof f.res === "object" ? f.res : {};
        if (b.on) { if (!has(f.res, rk)) f.res[rk] = s.key; else if (f.res[rk] !== s.key) return sendJson(res, 409, { error: "taken" }); }
        else if (has(f.res, rk) && f.res[rk] === s.key) delete f.res[rk];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/invite" && req.method === "POST") {
        if (!adult) return sendJson(res, 403, { error: "role" });
        if (limited("finv:" + s.key, 20, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        const key = String(b.username || "").trim().toLowerCase();
        if (!has(db.users, key) || key === s.key) return sendJson(res, 404, { error: "unknown" });
        const tu = db.users[key];
        if (famOf(tu)) return sendJson(res, 409, { error: "infamily" });
        const f = ensureFamily(s.key);
        if (f.members.length >= FAM_MAX) return sendJson(res, 400, { error: "limit" });
        tu.invites = asArr(tu.invites).filter((i) => i.fromKey !== s.key);
        if (tu.invites.length >= 10) return sendJson(res, 400, { error: "limit" });
        tu.invites.push({ id: crypto.randomBytes(5).toString("hex"), fid: f.id, from: me.name, fromKey: s.key, ts: Date.now() });
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if ((p === "/api/family/accept" || p === "/api/family/decline") && req.method === "POST") {
        const b = await readBody(req);
        const inv = asArr(me.invites).find((i) => i.id === String(b.id || ""));
        if (!inv) return sendJson(res, 404, { error: "unknown" });
        if (p.endsWith("decline")) {
          me.invites = me.invites.filter((i) => i !== inv);
          persist();
          return sendJson(res, 200, { ok: true });
        }
        const f = has(db.families, inv.fid) ? db.families[inv.fid] : null;
        if (famOf(me) || !f || f.members.length >= FAM_MAX || !f.members.includes(inv.fromKey)) return sendJson(res, 409, { error: "gone" });
        joinFamily(f, s.key);
        me.invites = [];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      const byLink = (tok) => {
        const h = sha(String(tok || ""));
        for (const fid of Object.keys(db.families)) {
          const f = db.families[fid], l = f.link;
          if (l && l.h === h && l.exp > Date.now() && f.members.includes(l.by) && has(db.users, l.by)) return f;
        }
        return null;
      };
      if (p === "/api/family/link" && req.method === "POST") {
        const f = mine();
        if (!f || !adult) return sendJson(res, 403, { error: "role" });
        if (limited("link:" + s.key, 30, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const tok = crypto.randomBytes(18).toString("base64url");
        f.link = { h: sha(tok), by: s.key, exp: Date.now() + 7 * 864e5 };
        persist();
        return sendJson(res, 200, { token: tok });
      }
      if ((p === "/api/family/joininfo" || p === "/api/family/join") && req.method === "POST") {
        if (limited("join:" + s.key, 30, 60 * 60 * 1000)) return sendJson(res, 429, { error: "rate" });
        const b = await readBody(req);
        if (famOf(me)) return sendJson(res, 409, { error: "have" });
        const f = byLink(b.token);
        if (!f || f.members.length >= FAM_MAX) return sendJson(res, 404, { error: "gone" });
        if (p.endsWith("joininfo")) return sendJson(res, 200, { from: db.users[f.link.by].name });
        joinFamily(f, s.key);
        me.invites = [];
        persist();
        return sendJson(res, 200, { ok: true });
      }
      if (p === "/api/family/leave" && req.method === "POST") {
        if (!mine()) return sendJson(res, 404, { error: "unknown" });
        if (isManaged(me)) return sendJson(res, 403, { error: "managed" });
        if (Object.keys(db.users).some((k) => db.users[k].parent === s.key)) return sendJson(res, 400, { error: "kids" });
        leaveFamily(s.key);
        persist();
        return sendJson(res, 200, { ok: true });
      }
      return sendJson(res, 404, { error: "not_found" });
    }

    if (p.startsWith("/api/admin/")) {
      const s = sessionUser(req);
      if (!s || !s.user.isAdmin) return sendJson(res, 403, { error: "admin" });
      if (s.user.mustChange) return sendJson(res, 403, { error: "change" });
      if (p === "/api/admin/suggestions" && req.method === "GET") {
        return sendJson(res, 200, { suggestions: db.suggestions.slice().reverse() });
      }
      if (p === "/api/admin/suggestion" && req.method === "POST") {
        const b = await readBody(req);
        const id = String(b.id || "");
        if (b.op === "del") db.suggestions = db.suggestions.filter((x) => x.id !== id);
        else { const x = db.suggestions.find((y) => y.id === id); if (x) x.done = !x.done; }
        persist();
        return sendJson(res, 200, { ok: true });
      }
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
