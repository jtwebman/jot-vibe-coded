// End-to-end checks of the security-relevant paths. Run: npm test
// Each test boots its own server on a fresh database, so state (sessions, login limits) never leaks between tests.
import { test } from 'node:test';
import http from 'node:http';
import net from 'node:net';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => r(port)); }); });
const boot = async (t, env = {}, DB = join(mkdtempSync(join(tmpdir(), 'jot-')), 'test.db')) => {
  const PORT = await freePort(), base = `http://127.0.0.1:${PORT}`;
  const server = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', 'server.js'], { env: { ...process.env, PORT, DB, ...env }, stdio: ['ignore', 'pipe', 'inherit'] });
  t.after(() => server.kill());
  await new Promise((r) => server.stdout.once('data', r));
  const req = (path, cookie, body, headers = {}) =>
    fetch(base + path, { method: body ? 'POST' : 'GET', headers: { ...headers, ...(cookie ? { cookie } : {}) }, body, redirect: 'manual' });
  const signup = async (username) => {
    const r = await req('/signup', null, new URLSearchParams({ username, password: 'password123' }));
    assert.equal(r.status, 303);
    return r.headers.get('set-cookie').split(';')[0];
  };
  const login = (username, password) => req('/login', null, new URLSearchParams({ username, password }));
  return { PORT, DB, base, req, signup, login, kill: () => server.kill() };
};

test('auth, note privacy, sharing, uploads, admin', async (t) => {
  const { DB, req, signup, login } = await boot(t);
  const alice = await signup('alice'), bob = await signup('bob');
  assert.equal((await req('/signup', null, new URLSearchParams({ username: 'BOB', password: 'password123' }))).status, 400, 'usernames are case-insensitive unique');
  assert.equal((await login('bob', 'wrong-pass')).status, 401);
  assert.equal((await login('bob', 'password123')).status, 303);

  // nobody is admin unless the operator names them (see #2)
  assert.equal((await req('/admin', alice)).status, 403);
  assert.equal((await req('/admin', bob)).status, 403);
  assert.equal((await req('/admin')).status, 303);

  // private note is not reachable by link; others can't toggle it; output is escaped
  await req('/notes', bob, new URLSearchParams({ body: '<script>x</script>' }));
  const note = new DatabaseSync(DB).prepare('SELECT id, token FROM notes').get();
  assert.equal((await req(`/n/${note.token}`)).status, 404);
  await req(`/notes/${note.id}/toggle`, alice, new URLSearchParams());
  assert.equal((await req(`/n/${note.token}`)).status, 404, 'non-owner cannot share');
  await req(`/notes/${note.id}/toggle`, bob, new URLSearchParams());
  const shared = await req(`/n/${note.token}`);
  assert.equal(shared.status, 200);
  const page = await shared.text();
  assert.ok(page.includes('&#60;script&#62;x') && !page.includes('<script>x'));

  // uploads: magic bytes decide, not the filename/content-type
  const upload = (bytes, name) => { const f = new FormData(); f.append('avatar', new Blob([bytes], { type: 'image/png' }), name); return req('/profile', bob, f); };
  assert.equal((await upload(Buffer.from('<svg onload=alert(1)>'), 'x.png')).status, 400);
  assert.equal((await upload(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]), 'a.png')).status, 303);
  assert.equal((await req('/avatar/2')).headers.get('content-type'), 'image/png');

  // logout kills the session
  await req('/logout', bob, new URLSearchParams());
  assert.equal((await req('/profile', bob)).status, 303);
});

test('#1 a malformed request path gets a 400 and the server keeps running', async (t) => {
  const { PORT, req } = await boot(t);
  // fetch normalizes URLs, so send the raw request line the audit used: GET //[
  const status = await new Promise((resolve, reject) =>
    http.get({ host: '127.0.0.1', port: PORT, path: '//[' }, (r) => { r.resume(); resolve(r.statusCode); }).on('error', reject));
  assert.equal(status, 400);
  assert.equal((await req('/')).status, 200);
});

test('#2 signing up first does not make you admin; only ADMIN=<username> does', async (t) => {
  const fresh = await boot(t);
  const mallory = await fresh.signup('mallory'), owner = await fresh.signup('owner');
  assert.equal((await fresh.req('/admin', mallory)).status, 403, 'first signup must not be admin');
  fresh.kill();
  const restarted = await boot(t, { ADMIN: 'owner' }, fresh.DB);
  assert.equal((await restarted.req('/admin', owner)).status, 200);
  assert.equal((await restarted.req('/admin', mallory)).status, 403);
});

test('#3 after 10 failed logins, even the right password is refused', async (t) => {
  const { signup, login } = await boot(t);
  await signup('bob');
  for (let i = 0; i < 10; i++) assert.equal((await login('bob', `guess${i}`)).status, 401);
  assert.equal((await login('bob', 'password123')).status, 429);
});

test('#3 password hashing does not stall other requests', async (t) => {
  const { req } = await boot(t);
  let done = 0;
  const signups = Array.from({ length: 40 }, (_, i) =>
    req('/signup', null, new URLSearchParams({ username: `user${i}`, password: 'password123' })).then(() => done++));
  await new Promise((r) => setTimeout(r, 20));
  const page = await req('/login');
  const doneBeforePage = done;
  await Promise.all(signups);
  assert.equal(page.status, 200);
  assert.ok(doneBeforePage < 20, `GET /login waited behind ${doneBeforePage} of 40 password hashes`);
});
