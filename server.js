// Jot — notes app. Zero dependencies: node:http + node:sqlite + node:crypto.
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(process.env.DB || 'data.db');
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    avatar BLOB,
    avatar_type TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 500),
    shared INTEGER NOT NULL DEFAULT 0,
    token TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS notes_user ON notes(user_id);
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// ---------- security helpers ----------
const hashPassword = (pw) => {
  const salt = randomBytes(16);
  return `${salt.toString('hex')}:${scryptSync(pw, salt, 64).toString('hex')}`;
};
const checkPassword = (pw, stored) => {
  const [salt, hash] = stored.split(':');
  return timingSafeEqual(scryptSync(pw, Buffer.from(salt, 'hex'), 64), Buffer.from(hash, 'hex'));
};
const token = () => randomBytes(18).toString('base64url');

// Sniff the real type from magic bytes; never trust the client's content-type. No SVG (can carry scripts).
const imageType = (b) =>
  b[0] === 0x89 && b.subarray(1, 4).toString() === 'PNG' ? 'image/png'
  : b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff ? 'image/jpeg'
  : b.subarray(0, 4).toString() === 'GIF8' ? 'image/gif'
  : b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP' ? 'image/webp'
  : null;

const httpError = (status, message) => Object.assign(new Error(message), { status });

// Parses urlencoded and multipart bodies via the built-in Fetch Response, with a hard size cap.
async function readForm(req, limit = 3_000_000) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    if ((size += c.length) > limit) throw httpError(413, 'That upload is too large.');
    chunks.push(c);
  }
  try {
    return await new Response(Buffer.concat(chunks), { headers: { 'content-type': req.headers['content-type'] || '' } }).formData();
  } catch {
    throw httpError(400, 'Bad form submission.');
  }
}

// ---------- HTML templating (auto-escapes every interpolated value) ----------
class Safe { constructor(s) { this.s = s; } }
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const raw = (v) => v instanceof Safe ? v.s : Array.isArray(v) ? v.map(raw).join('') : v == null || v === false ? '' : esc(v);
const html = (strings, ...vals) => new Safe(strings.reduce((out, s, i) => out + raw(vals[i - 1]) + s));

const fmt = (sqlDate) => new Date(sqlDate.replace(' ', 'T') + 'Z').toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });

const avatar = (u, size = 40) => u.avatar_type
  ? html`<img class="avatar" src="/avatar/${u.id}" width="${size}" height="${size}" alt="">`
  : html`<span class="avatar" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.42)}px">${u.username[0].toUpperCase()}</span>`;

const CSS = `
:root{--bg:#f5f6fb;--card:#fff;--text:#0f172a;--muted:#64748b;--border:#e5e7ef;--accent:#6366f1;--accent2:#a855f7;--danger:#e11d48;--ring:rgb(99 102 241/.25)}
@media (prefers-color-scheme:dark){:root{--bg:#0a0d16;--card:#121725;--text:#e5e7eb;--muted:#94a3b8;--border:#232a3b}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--text);background:radial-gradient(1200px 500px at 10% -10%,rgb(99 102 241/.14),transparent),radial-gradient(900px 400px at 100% 0,rgb(168 85 247/.12),transparent),var(--bg);background-attachment:fixed}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:1.6rem;letter-spacing:-.02em;margin:0 0 .25rem}h2{font-size:1.05rem;margin:0 0 .75rem}
.nav{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;padding:14px 24px;backdrop-filter:blur(12px);background:color-mix(in srgb,var(--bg) 75%,transparent);border-bottom:1px solid var(--border)}
.nav nav{display:flex;align-items:center;gap:18px}.nav nav a{color:var(--text);font-weight:500}.nav form{margin:0}
.brand{font-weight:800;font-size:1.2rem;letter-spacing:-.03em;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent!important}
.me{display:flex;align-items:center;gap:8px}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px 80px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:0 1px 2px rgb(0 0 0/.04),0 12px 32px -16px rgb(15 23 42/.18);margin-bottom:16px}
.btn,button{font:inherit;cursor:pointer;border:0;border-radius:10px;padding:10px 18px;font-weight:600;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 6px 16px -6px rgb(99 102 241/.6);transition:transform .1s,filter .15s;display:inline-block}
.btn:hover,button:hover{filter:brightness(1.08);text-decoration:none}.btn:active,button:active{transform:translateY(1px)}
.sm{padding:6px 12px;font-size:.85rem}.block{width:100%}
.ghost{background:transparent;color:var(--muted);box-shadow:none;border:1px solid var(--border)}.ghost:hover{color:var(--text);border-color:var(--muted)}
.ghost.danger:hover{color:var(--danger);border-color:var(--danger)}
.link{background:none;box-shadow:none;color:var(--muted);padding:0;font-weight:500}.link:hover{color:var(--text)}
input,textarea{font:inherit;color:inherit;width:100%;padding:11px 13px;border:1px solid var(--border);border-radius:10px;background:var(--bg);outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
textarea{resize:vertical;min-height:90px;border:0;background:transparent;padding:4px;font-size:1.05rem}textarea:focus{box-shadow:none}
label{display:block;font-weight:600;font-size:.9rem;margin-bottom:14px}label input{margin-top:6px;font-weight:400}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;border-top:1px solid var(--border);padding-top:12px;margin-top:8px}
.toggle{display:flex;align-items:center;gap:10px;margin:0;font-weight:500;color:var(--muted);cursor:pointer}
.toggle input{appearance:none;width:38px;height:22px;margin:0;padding:0;border-radius:99px;background:var(--border);position:relative;cursor:pointer;border:0;transition:background .2s}
.toggle input::after{content:"";position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .2s;box-shadow:0 1px 3px rgb(0 0 0/.3)}
.toggle input:checked{background:var(--accent)}.toggle input:checked::after{transform:translateX(16px)}
.section{display:flex;align-items:center;gap:8px;margin:32px 0 12px;color:var(--muted);font-size:.85rem;text-transform:uppercase;letter-spacing:.08em}
.count{background:var(--border);color:var(--text);border-radius:99px;padding:0 8px;font-size:.75rem}
.note .body{white-space:pre-wrap;word-break:break-word;margin:0 0 14px;font-size:1.02rem}.note .big{font-size:1.25rem;margin-top:16px}
.meta{display:flex;align-items:center;flex-wrap:wrap;gap:8px;color:var(--muted);font-size:.85rem}.meta form{margin:0}.spacer{flex:1}
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 10px;border-radius:99px;font-size:.78rem;font-weight:600;background:var(--border);color:var(--muted)}
.badge.on{background:rgb(99 102 241/.14);color:var(--accent)}
.avatar{display:inline-grid;place-items:center;border-radius:50%;object-fit:cover;flex:none;font-weight:700;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2))}
.user{display:flex;align-items:center;gap:12px}
.muted{color:var(--muted)}.small{font-size:.85rem}.center{text-align:center}
.empty{text-align:center;color:var(--muted);padding:40px 0}
.error{background:rgb(225 29 72/.1);color:var(--danger);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-weight:500}
.auth{max-width:400px;margin:40px auto;padding:32px}
.hero{text-align:center;padding:72px 0 40px}.hero h1{font-size:clamp(2.4rem,6vw,3.6rem);line-height:1.1;letter-spacing:-.04em}
.hero p{font-size:1.15rem;color:var(--muted);max-width:480px;margin:16px auto 28px}.hero .actions{display:flex;gap:12px;justify-content:center}
.grad{background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;color:transparent}
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}.features .card{margin:0}.features b{display:block;margin-bottom:4px}
.profile{display:flex;align-items:center;gap:20px}
.upload{display:flex;gap:10px;align-items:center}.upload input{flex:1}
input[type=file]{padding:8px}input[type=file]::file-selector-button{font:inherit;border:0;border-radius:8px;padding:6px 12px;margin-right:12px;background:var(--border);color:var(--text);cursor:pointer}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:20px 0}.stats .card{margin:0}.stat b{display:block;font-size:1.8rem;letter-spacing:-.03em}.stat span{color:var(--muted);font-size:.85rem}
.table{padding:0;overflow-x:auto}table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px 20px;border-bottom:1px solid var(--border)}tr:last-child td{border-bottom:0}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600}
`;

const SCRIPT = `<script>document.addEventListener('click',e=>{const b=e.target.closest('[data-copy]');if(!b)return;navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copied ✓';setTimeout(()=>b.textContent='Copy link',1500)})</script>`;

const layout = (user, title, content) => '<!doctype html>' + html`<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · Jot</title><style>${new Safe(CSS)}</style></head><body>
<header class="nav"><a class="brand" href="/">✎ Jot</a><nav>${user
  ? html`<a href="/">Notes</a>${user.is_admin ? html`<a href="/admin">Admin</a>` : ''}
    <a class="me" href="/profile">${avatar(user, 30)}<span>${user.username}</span></a>
    <form method="post" action="/logout"><button class="link">Log out</button></form>`
  : html`<a href="/login">Log in</a><a class="btn sm" href="/signup">Sign up</a>`}</nav></header>
<main class="wrap">${content}</main>${new Safe(SCRIPT)}</body></html>`.s;

const errorPage = (user, status, message) => layout(user, 'Oops', html`<div class="empty"><h1>${status}</h1><p>${message}</p><a class="btn" href="/">Go home</a></div>`);

const authPage = (mode, error = '', username = '') => {
  const login = mode === 'login';
  return layout(null, login ? 'Log in' : 'Sign up', html`<div class="card auth">
    <h1>${login ? 'Welcome back' : 'Create your account'}</h1>
    <p class="muted">${login ? 'Log in to see your notes.' : 'Start jotting in seconds.'}</p>
    ${error ? html`<div class="error" role="alert">${error}</div>` : ''}
    <form method="post" action="/${mode}">
      <label>Username<input name="username" value="${username}" required autofocus autocomplete="username"
        ${login ? '' : html`pattern="[A-Za-z0-9_]{3,20}" title="3–20 letters, numbers or underscores"`}></label>
      <label>Password<input type="password" name="password" required ${login ? html`autocomplete="current-password"` : html`minlength="8" autocomplete="new-password"`}></label>
      <button class="btn block">${login ? 'Log in' : 'Sign up'}</button>
    </form>
    <p class="muted small center">${login ? html`No account? <a href="/signup">Sign up</a>` : html`Already have an account? <a href="/login">Log in</a>`}</p>
  </div>`);
};

const noteCard = (n, host) => html`<article class="card note">
  <p class="body">${n.body}</p>
  <div class="meta">
    <span class="badge ${n.shared ? 'on' : ''}">${n.shared ? '🔗 Shared' : '🔒 Private'}</span>
    <time>${fmt(n.created_at)}</time><span class="spacer"></span>
    ${n.shared ? html`<a class="ghost btn sm" href="/n/${n.token}" target="_blank">Open</a><button class="ghost sm" data-copy="http://${host}/n/${n.token}">Copy link</button>` : ''}
    <form method="post" action="/notes/${n.id}/toggle"><button class="ghost sm">${n.shared ? 'Make private' : 'Share'}</button></form>
    <form method="post" action="/notes/${n.id}/delete" onsubmit="return confirm('Delete this note?')"><button class="ghost sm danger">Delete</button></form>
  </div>
</article>`;

const profilePage = (user, error = '') => layout(user, 'Profile', html`
  <div class="card profile">${avatar(user, 96)}<div><h1>${user.username}</h1>
    <p class="muted">${user.is_admin ? 'Admin · ' : ''}Joined ${fmt(user.created_at)}</p></div></div>
  <div class="card"><h2>Profile picture</h2>
    ${error ? html`<div class="error" role="alert">${error}</div>` : ''}
    <form class="upload" method="post" action="/profile" enctype="multipart/form-data">
      <input type="file" name="avatar" accept="image/png,image/jpeg,image/gif,image/webp" required aria-label="Profile picture">
      <button class="btn">Upload</button>
    </form>
    <p class="muted small">PNG, JPEG, GIF or WebP, up to 2 MB.</p>
  </div>`);

// ---------- sessions ----------
const SESSION_DAYS = 30;
const currentUser = (req) => {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
  return sid ? db.prepare(`SELECT u.id, u.username, u.is_admin, u.avatar_type, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.created_at > datetime('now', '-${SESSION_DAYS} days')`).get(sid) : undefined;
};
const startSession = (res, userId) => {
  const sid = token();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(sid, userId);
  redirect(res, '/', { 'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}` });
};

const send = (res, body, status = 200) => { res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(body); };
const redirect = (res, to, headers = {}) => { res.writeHead(303, { Location: to, ...headers }); res.end(); };
const field = (f, name) => String(f.get(name) ?? '').trim();

// ---------- routes ----------
const loggedIn = (fn) => (ctx) => ctx.user ? fn(ctx) : redirect(ctx.res, '/login');

const routes = [
  ['GET', /^\/$/, ({ res, req, user }) => {
    if (!user) return send(res, layout(null, 'Welcome', html`
      <section class="hero"><h1>Thoughts, <span class="grad">jotted.</span></h1>
        <p>Short notes that stay private — or share any one of them with a single link.</p>
        <div class="actions"><a class="btn" href="/signup">Get started</a><a class="btn ghost" href="/login">Log in</a></div></section>
      <div class="features">
        <div class="card"><b>🔒 Private by default</b><span class="muted small">Only you can see your notes.</span></div>
        <div class="card"><b>🔗 Share with a link</b><span class="muted small">Flip a switch to share any note.</span></div>
        <div class="card"><b>🙂 Make it yours</b><span class="muted small">Upload a profile picture.</span></div>
      </div>`));
    const notes = db.prepare('SELECT * FROM notes WHERE user_id = ? ORDER BY id DESC').all(user.id);
    send(res, layout(user, 'Notes', html`
      <form class="card" method="post" action="/notes">
        <textarea name="body" maxlength="500" required placeholder="What's on your mind?" aria-label="New note"></textarea>
        <div class="row"><label class="toggle"><input type="checkbox" name="shared"> Share with link</label><button class="btn">Post note</button></div>
      </form>
      <h2 class="section">Your notes <span class="count">${notes.length}</span></h2>
      ${notes.length ? notes.map((n) => noteCard(n, req.headers.host)) : html`<p class="empty">No notes yet — write your first one above.</p>`}`));
  }],

  ['GET', /^\/(login|signup)$/, ({ res, user, params: [mode] }) => user ? redirect(res, '/') : send(res, authPage(mode))],

  ['POST', /^\/signup$/, async ({ req, res }) => {
    const f = await readForm(req);
    const username = field(f, 'username'), password = String(f.get('password') ?? '');
    const error = !/^[A-Za-z0-9_]{3,20}$/.test(username) ? 'Username must be 3–20 letters, numbers or underscores.'
      : password.length < 8 || password.length > 200 ? 'Password must be 8–200 characters.'
      : db.prepare('SELECT 1 FROM users WHERE username = ?').get(username) ? 'That username is taken.'
      : null;
    if (error) return send(res, authPage('signup', error, username), 400);
    // The very first account becomes the admin.
    const { lastInsertRowid } = db.prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, (SELECT COUNT(*) = 0 FROM users))')
      .run(username, hashPassword(password));
    startSession(res, lastInsertRowid);
  }],

  ['POST', /^\/login$/, async ({ req, res }) => {
    const f = await readForm(req);
    const username = field(f, 'username'), password = String(f.get('password') ?? '');
    const u = db.prepare('SELECT id, password FROM users WHERE username = ?').get(username);
    if (!u || !checkPassword(password, u.password)) return send(res, authPage('login', 'Wrong username or password.', username), 401);
    startSession(res, u.id);
  }],

  ['POST', /^\/logout$/, ({ req, res }) => {
    const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
    if (sid) db.prepare('DELETE FROM sessions WHERE token = ?').run(sid);
    redirect(res, '/', { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }],

  ['POST', /^\/notes$/, loggedIn(async ({ req, res, user }) => {
    const f = await readForm(req);
    const body = field(f, 'body');
    if (!body || body.length > 500) throw httpError(400, 'Notes must be 1–500 characters.');
    db.prepare('INSERT INTO notes (user_id, body, shared, token) VALUES (?, ?, ?, ?)').run(user.id, body, f.get('shared') ? 1 : 0, token());
    redirect(res, '/');
  })],

  // Ownership is enforced in SQL: you can only touch rows where user_id is you.
  ['POST', /^\/notes\/(\d+)\/toggle$/, loggedIn(({ res, user, params: [id] }) => {
    db.prepare('UPDATE notes SET shared = 1 - shared WHERE id = ? AND user_id = ?').run(id, user.id);
    redirect(res, '/');
  })],

  ['POST', /^\/notes\/(\d+)\/delete$/, loggedIn(({ res, user, params: [id] }) => {
    db.prepare('DELETE FROM notes WHERE id = ? AND user_id = ?').run(id, user.id);
    redirect(res, '/');
  })],

  ['GET', /^\/n\/([\w-]+)$/, ({ res, user, params: [t] }) => {
    const n = db.prepare(`SELECT n.body, n.created_at, u.id, u.username, u.avatar_type FROM notes n JOIN users u ON u.id = n.user_id
      WHERE n.token = ? AND n.shared = 1`).get(t);
    if (!n) throw httpError(404, 'This note doesn’t exist or isn’t shared.');
    send(res, layout(user, `Note by ${n.username}`, html`
      <article class="card note" style="padding:28px">
        <div class="user">${avatar(n, 44)}<div><b>${n.username}</b><div class="muted small">${fmt(n.created_at)}</div></div></div>
        <p class="body big">${n.body}</p>
      </article>
      ${user ? '' : html`<p class="center muted">Want your own notes? <a href="/signup">Sign up for Jot</a></p>`}`));
  }],

  ['GET', /^\/profile$/, loggedIn(({ res, user }) => send(res, profilePage(user)))],

  ['POST', /^\/profile$/, loggedIn(async ({ req, res, user }) => {
    const file = (await readForm(req)).get('avatar');
    const buf = file instanceof File ? Buffer.from(await file.arrayBuffer()) : Buffer.alloc(0);
    const type = imageType(buf);
    const error = !buf.length ? 'Choose an image to upload.' : buf.length > 2_000_000 ? 'Images must be 2 MB or smaller.'
      : !type ? 'Only PNG, JPEG, GIF or WebP images are allowed.' : null;
    if (error) return send(res, profilePage(user, error), 400);
    db.prepare('UPDATE users SET avatar = ?, avatar_type = ? WHERE id = ?').run(buf, type, user.id);
    redirect(res, '/profile');
  })],

  ['GET', /^\/avatar\/(\d+)$/, ({ res, params: [id] }) => {
    const a = db.prepare('SELECT avatar, avatar_type FROM users WHERE id = ? AND avatar IS NOT NULL').get(id);
    if (!a) throw httpError(404, 'No avatar.');
    res.writeHead(200, { 'Content-Type': a.avatar_type, 'Cache-Control': 'no-cache' });
    res.end(a.avatar);
  }],

  ['GET', /^\/admin$/, loggedIn(({ res, user }) => {
    if (!user.is_admin) throw httpError(403, 'Admins only.');
    const users = db.prepare(`SELECT u.id, u.username, u.is_admin, u.avatar_type, u.created_at,
        COUNT(n.id) AS notes, COALESCE(SUM(n.shared), 0) AS shared
      FROM users u LEFT JOIN notes n ON n.user_id = u.id GROUP BY u.id ORDER BY u.id`).all();
    const total = (k) => users.reduce((s, u) => s + u[k], 0);
    send(res, layout(user, 'Admin', html`
      <h1>Admin</h1><p class="muted">Everyone who has signed up.</p>
      <div class="stats">
        <div class="card stat"><b>${users.length}</b><span>Users</span></div>
        <div class="card stat"><b>${total('notes')}</b><span>Notes</span></div>
        <div class="card stat"><b>${total('shared')}</b><span>Shared notes</span></div>
      </div>
      <div class="card table"><table>
        <thead><tr><th>User</th><th>Role</th><th>Notes</th><th>Shared</th><th>Joined</th></tr></thead>
        <tbody>${users.map((u) => html`<tr>
          <td><div class="user">${avatar(u, 32)}<b>${u.username}</b></div></td>
          <td>${u.is_admin ? html`<span class="badge on">Admin</span>` : html`<span class="badge">Member</span>`}</td>
          <td>${u.notes}</td><td>${u.shared}</td><td class="muted">${fmt(u.created_at)}</td></tr>`)}</tbody>
      </table></div>`));
  })],
];

http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer'); // keeps share tokens out of Referer headers
  let user;
  try {
    const pathname = URL.parse(req.url, 'http://localhost')?.pathname;
    if (!pathname) throw httpError(400, 'Bad request.');
    user = currentUser(req);
    for (const [method, re, handler] of routes) {
      const m = req.method === method && pathname.match(re);
      if (m) return await handler({ req, res, user, params: m.slice(1) });
    }
    throw httpError(404, 'Page not found.');
  } catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) send(res, errorPage(user, e.status || 500, e.status ? e.message : 'Something went wrong.'), e.status || 500);
    else res.end();
  }
}).listen(PORT, () => console.log(`Jot running at http://localhost:${PORT}`));
