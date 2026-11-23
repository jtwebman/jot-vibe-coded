# Jot: a vibe-coded app, attacked and fixed

The demo app from the Max Tokens episode **"I Built an App in 4 Minutes. One Request Killed It."**

**The first commit** is the app exactly as an AI coding agent wrote it from this one prompt, with every change auto-accepted and nobody reading the code:

> Build me a web app where people can sign up, log in, and post short notes. Each note can be private or shared with a link. Users can upload a profile picture. I also want an admin page where I can see all users. Use a real database. Make it look nice and modern. I want to run it locally with one command.

It took about 4 minutes. It has zero dependencies (Node 22+ with the built-in `node:sqlite`), and its own test passed.

**Then a separate AI attacked it**, and every finding was proven against the running app (see [AUDIT.md](AUDIT.md)). Most of it was solid. But one request with no login, `GET //[`, crashed the whole server. Also, whoever signed up first became admin, and the code's own comment and test documented that as intended.

**The rest of the history** is the fixes, made with [pstack](https://github.com/cursor/plugins/tree/main/pstack) by Lauren Tan (poteto). There is one commit per finding, and every fix has a test that **fails on the original code and passes on the new code**. Running the final `test.js` against the first commit's `server.js` gives 0 of 10 passing; against the fixed one it gives 10 of 10.

```sh
npm start                  # http://localhost:3000  (no install step)
ADMIN=<username> npm start # make an existing account the admin (fixed version)
npm test                   # 10 checks
git checkout $(git rev-list --max-parents=0 HEAD)   # the original, as vibe-coded
```

For learning only. It's a small demo, not a hardened product.
