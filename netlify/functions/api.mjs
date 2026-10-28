import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual, createHmac } from "node:crypto";

const AUTH = () => getStore("auth"), DATA = () => getStore("inventory");
const J = (o, s = 200) => Response.json(o, { status: s });
const mk = (s, salt = randomBytes(16).toString("hex")) => ({ salt, hash: scryptSync(s, salt, 32).toString("hex") });
const chk = (s, salt, h) => { const a = Buffer.from(scryptSync(s, salt, 32).toString("hex")), b = Buffer.from(h || ""); return a.length === b.length && timingSafeEqual(a, b); };
const newKey = () => Array.from({ length: 4 }, () => randomBytes(2).toString("hex").toUpperCase()).join("-");
const normKey = (k) => String(k || "").trim().toUpperCase();
const users = async () => (await AUTH().get("users", { type: "json" })) || {};
const saveUsers = (u) => AUTH().setJSON("users", u);

async function secret() {
  let s = await AUTH().get("secret");
  if (!s) { s = randomBytes(32).toString("hex"); await AUTH().set("secret", s); }
  return s;
}
async function sign(u) {
  const p = Buffer.from(JSON.stringify({ u, e: Date.now() + 7 * 864e5 })).toString("base64url");
  return p + "." + createHmac("sha256", await secret()).update(p).digest("base64url");
}
async function who(req, us) {
  const [p, g] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!p || !g || createHmac("sha256", await secret()).update(p).digest("base64url") !== g) return null;
  const x = JSON.parse(Buffer.from(p, "base64url"));
  const u = us[x.u];
  return x.e > Date.now() && u && u.active ? { username: x.u, role: u.role } : null;
}
function addUser(us, username, password, role) {
  username = String(username || "").trim().toLowerCase();
  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) return "Username 3-30 character, shudhu a-z 0-9 _ . - hobe";
  if (String(password || "").length < 6) return "Password kom-e kom 6 character dite hobe";
  if (us[username]) return "Ei username age theke ache";
  const key = newKey(), p = mk(password), r = mk(key);
  us[username] = { role, active: true, salt: p.salt, hash: p.hash, rsalt: r.salt, rhash: r.hash, created: Date.now() };
  return { username, key };
}

export default async (req) => {
  const path = new URL(req.url).pathname.replace(/^\/api\//, "").split("/"), m = req.method;
  const b = m === "GET" ? {} : await req.json().catch(() => ({}));
  const us = await users();

  if (path[0] === "status") return J({ setup: !Object.keys(us).length });

  if (path[0] === "setup") {
    if (Object.keys(us).length) return J({ error: "Setup age-i hoye gese" }, 400);
    const pw = Netlify.env.get("APP_PASSWORD");
    if (!pw) return J({ error: "Netlify-te APP_PASSWORD environment variable set korun" }, 500);
    if (b.code !== pw) return J({ error: "Setup code vul" }, 401);
    const r = addUser(us, b.username, b.password, "admin");
    if (typeof r === "string") return J({ error: r }, 400);
    await saveUsers(us);
    return J({ token: await sign(r.username), user: { username: r.username, role: "admin" }, recoveryKey: r.key });
  }

  if (path[0] === "login") {
    const name = String(b.username || "").trim().toLowerCase(), u = us[name];
    if (!u || !chk(String(b.password || ""), u.salt, u.hash)) return J({ error: "Username ba password vul" }, 401);
    if (!u.active) return J({ error: "Ei account deactivate kora. Admin-er sathe jogajog korun" }, 403);
    return J({ token: await sign(name), user: { username: name, role: u.role } });
  }

  if (path[0] === "recover") {
    const name = String(b.username || "").trim().toLowerCase(), u = us[name];
    if (!u || !chk(normKey(b.key), u.rsalt, u.rhash)) return J({ error: "Username ba recovery key vul" }, 401);
    if (!u.active) return J({ error: "Ei account deactivate kora" }, 403);
    if (String(b.password || "").length < 6) return J({ error: "Password kom-e kom 6 character" }, 400);
    const key = newKey(), p = mk(b.password), r = mk(key);
    Object.assign(u, { salt: p.salt, hash: p.hash, rsalt: r.salt, rhash: r.hash });
    await saveUsers(us);
    return J({ ok: true, recoveryKey: key });
  }

  const me = await who(req, us);
  if (!me) return J({ error: "Login korun" }, 401);

  if (path[0] === "me") return J({ user: me });

  if (path[0] === "data") {
    if (m === "GET") return J((await DATA().get("entries", { type: "json" })) || { entries: [] });
    if (m === "PUT") {
      if (!Array.isArray(b.entries)) return J({ error: "Bad request" }, 400);
      await DATA().setJSON("entries", { entries: b.entries, updated: Date.now(), by: me.username });
      return J({ ok: true });
    }
  }

  if (["usdt", "receivable", "payable"].includes(path[0])) {
    if (m === "GET") return J((await DATA().get(path[0], { type: "json" })) || { items: [] });
    if (m === "PUT") {
      if (!Array.isArray(b.items)) return J({ error: "Bad request" }, 400);
      const items = b.items.filter((x) => x && typeof x.date === "string").map((x) => ({ id: String(x.id), date: x.date, amount: Number(x.amount) || 0, note: String(x.note || ""), ts: Number(x.ts) || 0 }));
      await DATA().setJSON(path[0], { items, updated: Date.now(), by: me.username });
      return J({ ok: true });
    }
  }

  if (path[0] === "password" && m === "POST") {
    const u = us[me.username];
    if (!chk(String(b.old || ""), u.salt, u.hash)) return J({ error: "Purono password vul" }, 401);
    if (String(b.password || "").length < 6) return J({ error: "Notun password kom-e kom 6 character" }, 400);
    Object.assign(u, mk(b.password));
    await saveUsers(us);
    return J({ ok: true });
  }

  if (path[0] === "users") {
    if (me.role !== "admin") return J({ error: "Shudhu admin pare" }, 403);
    if (m === "GET" && !path[1])
      return J({ users: Object.entries(us).map(([username, u]) => ({ username, role: u.role, active: u.active, created: u.created })) });
    if (m === "POST" && !path[1]) {
      const r = addUser(us, b.username, b.password, "manager");
      if (typeof r === "string") return J({ error: r }, 400);
      await saveUsers(us);
      return J({ ok: true, username: r.username, recoveryKey: r.key });
    }
    const t = us[path[1]];
    if (!t) return J({ error: "User paoa jayni" }, 404);
    if (path[2] === "reset" && m === "POST") {
      if (String(b.password || "").length < 6) return J({ error: "Password kom-e kom 6 character" }, 400);
      const key = newKey(), r = mk(key);
      Object.assign(t, mk(b.password), { rsalt: r.salt, rhash: r.hash });
      await saveUsers(us);
      return J({ ok: true, recoveryKey: key });
    }
    if (path[2] === "toggle" && m === "POST") {
      if (path[1] === me.username) return J({ error: "Nijer account deactivate kora jabe na" }, 400);
      t.active = !t.active;
      await saveUsers(us);
      return J({ ok: true, active: t.active });
    }
  }
  return J({ error: "Not found" }, 404);
};

export const config = { path: "/api/*" };
