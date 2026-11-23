# Audit of "Jot" (vibe-coded from one prompt, every change auto-accepted)

Audited 2026-11-23 by a separate AI (fresh context, never saw the build). Every finding was proven against the running, unmodified app on 127.0.0.1:4123 (fresh DB per run).
Proof commands are summarised below.
Build: 12 turns, ~4 min, $0.99, 353-line server.js, zero npm deps, node:sqlite; its own test passes.

## Summary
Mostly solid: safe password storage (salted scrypt, timing-safe compare), parameterized SQL, no cross-user note access, everything escaped,
strict uploads, unguessable session and share tokens. But ONE unauthenticated request (`GET //[`) crashes the whole server, and a page on
another local port can do it with one <img> tag. Design gaps: the first person to sign up becomes admin forever; no login rate limit and
password hashing blocks the server; no CSRF token beyond SameSite=Lax; re-sharing a note resurrects its old leaked link.

## Findings (all proven)
1. HIGH · One request crashes the server · server.js:339 `new URL(req.url, ...)` runs before the try at :341; Node exits, nothing restarts it.
   Proof: `curl -sg --path-as-is "http://127.0.0.1:4123//["` → before 200, after: nothing listening, `TypeError: Invalid URL at server.js:339`.
   Real Chrome: an <img src="http://127.0.0.1:4123//["> on a page served from 127.0.0.1:4124 killed it (a public/opaque origin was blocked by Chrome).
   Fix: move the URL parse inside the try (and run under a restarter).
2. MEDIUM · First person to sign up becomes admin · server.js:241-242 `is_admin = (SELECT COUNT(*) = 0 FROM users)`; no way to change it.
   Proof: fresh DB, signup mallory then owner → mallory /admin 200, owner /admin 403 (screens/7-admin.png). Fix: ADMIN_USERNAME env or a setup token.
3. MEDIUM · Unlimited password guessing; logins freeze the server · login :247-253 no throttle; scryptSync :43 on the main thread; 8-char minimum only.
   Proof: 300 wrong passwords in 7.4 s all 401, then the right one → 303 (no lockout); GET /login 0.3 ms idle vs 327 ms during 40 parallel logins.
   Fix: per-IP/per-user failure counter → 429; async crypto.scrypt.
4. LOW · No CSRF token · POST routes :255-303 rely on SameSite=Lax only. Same-site pages (another port, sibling subdomain) can post as the user.
   Proof: real Chrome, victim logged in; page on 127.0.0.1:4124 planted "CSRF: posted by a page on 127.0.0.1:4124"; cross-site data: page blocked.
   Fix: reject POSTs whose Origin / Sec-Fetch-Site isn't the app's own.
5. LOW · Making a note private doesn't kill its link · token made once (:265), toggle (:270-273) only flips `shared`.
   Proof: shared 200 → private 404 → re-shared, SAME old token 200. Fix: new token on every private→shared.
6. LOW · Username enumeration · "That username is taken." (:238); login only hashes for existing users (median 26.6 ms vs 0.4 ms).
7. LOW · Listens on all interfaces · `.listen(PORT)` (:353) → `node *:4123 (LISTEN)`; prompt said "run it locally". Fix: bind 127.0.0.1.
8. LOW · Upload check reads only the magic bytes (:48-53); a GIF89a+<script> polyglot is accepted but served as image/gif + nosniff (not XSS).
9. INFO · Session cookie has no Secure flag (:200). 10. INFO · Avatars public at sequential IDs (/avatar/3 → 200 anonymously).

## Done right (proven)
scrypt + salt + timingSafeEqual · parameterized SQL (`bob' --`, `' OR 1=1 --` → 401) · notes scoped by user_id (mallory can't toggle/delete bob's) ·
/admin 403 for users, mass-assignment `is_admin=1` ignored · private note links 404, 144-bit share tokens · output escaped (`<img onerror>` inert,
`<script>` usernames rejected) · SVG/HTML uploads 400, 3.1 MB → 413, stored in DB, served with nosniff · HttpOnly + SameSite=Lax 144-bit sessions,
server-side expiry, fixation-proof, logout deletes the session · cross-site CSRF blocked in a real browser · friendly errors, no stack traces ·
X-Frame-Options DENY, Referrer-Policy no-referrer · no secrets in code · every prompt feature present, one-command start, modern responsive UI with dark mode.

## Unproven
LAN reachability (scope was 127.0.0.1 only) · drive-by crash from public sites in Firefox/Safari · DNS rebinding (no Host check) · copy-link URL
hard-codes http:// · memory per request (3 MB buffered pre-auth) · expired sessions never purged, tokens stored in plaintext.
