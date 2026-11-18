// Real-browser passkey test: headless Chromium (DevTools protocol) with a virtual platform
// authenticator, against a THROWAWAY dashboard instance (consumes the one-time admin password).
// usage: node scripts/passkey-e2e.mjs http://localhost:PORT /path/initial-admin-password.txt /path/to/chrome
import { spawn } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { createHmac } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [base, pwFile, chromePath] = process.argv.slice(2);
const pw0 = readFileSync(pwFile, "utf8").split("\n").map((l) => l.trim()).find((l) => /^password:/i.test(l)).replace(/^password:\s*/i, "");
let checks = 0;
function ok(cond, what, extra) {
  checks++;
  if (!cond) { console.log("FAIL", what, extra === undefined ? "" : JSON.stringify(extra)); cleanup(1); }
  console.log("ok  ", what);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = createHmac("sha1", key).update(ctr).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}

// --- browser + CDP ---------------------------------------------------------------------------
const profile = mkdtempSync(join(tmpdir(), "novadb-pk-"));
const port = 9300 + Math.floor(Math.random() * 500);
const chrome = spawn(chromePath, [
  "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
  `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "about:blank",
], { stdio: "ignore" });
function cleanup(code) {
  try { chrome.kill("SIGKILL"); } catch {}
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
  process.exit(code);
}
let pageWs;
for (let i = 0; i < 100 && !pageWs; i++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    pageWs = list.find((t) => t.type === "page")?.webSocketDebuggerUrl;
  } catch {}
  if (!pageWs) await sleep(100);
}
if (!pageWs) { console.log("FAIL could not start chromium"); cleanup(1); }
const ws = new WebSocket(pageWs);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let nextId = 1;
const pending = new Map();
ws.onmessage = (m) => {
  const j = JSON.parse(m.data);
  if (j.id && pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); }
};
function cdp(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((res, rej) => pending.set(id, (j) => (j.error ? rej(new Error(method + ": " + j.error.message)) : res(j.result))));
}
async function js(expr) {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + " " + (r.exceptionDetails.exception?.description || ""));
  return r.result.value;
}
async function go(path) {
  await cdp("Page.navigate", { url: base + path });
  await waitFor(`document.readyState === "complete" && location.pathname === ${JSON.stringify(path.split("?")[0])}`);
}
async function waitFor(cond, ms = 15000) {
  const t0 = Date.now();
  for (;;) {
    try { if (await js(`(${cond})`)) return true; } catch {}
    if (Date.now() - t0 > ms) return false;
    await sleep(100);
  }
}
const path = () => js("location.pathname + location.search");
const text = () => js("document.body.innerText");
async function submitForm(sel, values) {
  await js(`(() => { const f = document.querySelector(${JSON.stringify(sel)}); const v = ${JSON.stringify(values)};
    for (const k in v) f.querySelector('[name="' + k + '"]').value = v[k]; f.submit(); })()`);
  await sleep(300);
  await waitFor(`document.readyState === "complete"`);
}

await cdp("Page.enable");
await cdp("Runtime.enable");

// --- first login: password change + TOTP enrolment -------------------------------------------
await go("/login");
ok(await js(`!!document.getElementById("pk-login")`), "login page offers 'Sign in with a passkey'");
await submitForm('form[action="/login"]', { username: "admin", password: pw0 });
await waitFor(`location.pathname === "/setup/password"`);
const newPw = "Passkey-test-password-123";
await submitForm('form[action="/setup/password"]', { new: newPw, again: newPw });
await waitFor(`location.pathname === "/setup/totp"`);
const secret = await js(`document.querySelector(".secret").textContent.replace(/\\s+/g, "")`);
const enrolCode = totp(secret);
await submitForm('form[action="/setup/totp"]', { code: enrolCode });
ok(await waitFor(`location.pathname === "/"`), "signed in with password + TOTP", await path());

// --- register a passkey ----------------------------------------------------------------------
await cdp("WebAuthn.enable", { enableUI: false });
const { authenticatorId } = await cdp("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});
await go("/account");
ok((await text()).includes("Passkeys"), "Account page has a Passkeys card");
// a stolen session alone must not be able to add a passkey: password + fresh code required
await js(`document.getElementById("pk-name").value = "Test laptop"; document.getElementById("pk-pw").value = "wrong-password-xyz"; document.getElementById("pk-code").value = ${JSON.stringify(enrolCode)}; document.getElementById("pk-add").click()`);
ok(await waitFor(`(document.getElementById("pk-msg")?.textContent || "").includes("wrong")`), "adding a passkey with a wrong password is refused", await js(`document.getElementById("pk-msg")?.textContent`));
ok((await cdp("WebAuthn.getCredentials", { authenticatorId })).credentials.length === 0, "nothing was created on the authenticator");
// the code used at enrolment cannot be replayed: wait for the next 30 s window
for (let i = 0; i < 70 && totp(secret) === enrolCode; i++) await sleep(500);
await js(`document.getElementById("pk-pw").value = ${JSON.stringify(newPw)}; document.getElementById("pk-code").value = ${JSON.stringify(totp(secret))}; document.getElementById("pk-add").click()`);
ok(await waitFor(`location.search.includes("passkey_added")`), "passkey registered through the browser", await js(`document.getElementById("pk-msg")?.textContent`));
ok((await text()).includes("Test laptop"), "passkey listed with its name");
const creds = (await cdp("WebAuthn.getCredentials", { authenticatorId })).credentials;
ok(creds.length === 1 && creds[0].isResidentCredential, "authenticator holds one discoverable credential");

// --- sign out, sign in with the passkey ------------------------------------------------------
const logout = async () => { await js(`document.querySelector('form[action="/logout"]').submit()`); await waitFor(`location.pathname === "/login"`); };
await logout();
await js(`document.getElementById("pk-login").click()`);
ok(await waitFor(`location.pathname === "/"`), "passkey login skips password and TOTP", await js(`document.getElementById("pk-msg")?.textContent`));
ok((await text()).toLowerCase().includes("admin"), "logged in as admin");

// --- the passkey must verify the user ----------------------------------------------------------
await logout();
await cdp("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: false });
await js(`document.getElementById("pk-login").click()`);
await sleep(2500);
ok((await path()).startsWith("/login"), "no login without user verification (PIN/biometrics)", await path());
await cdp("WebAuthn.setUserVerified", { authenticatorId, isUserVerified: true });

// --- audit + removal -------------------------------------------------------------------------
await js(`document.getElementById("pk-login").click()`);
ok(await waitFor(`location.pathname === "/"`), "passkey login works again");
await go("/audit");
const audit = await text();
ok(audit.includes("passkey.add") && audit.includes("login.passkey_ok"), "audit log records passkey.add and login.passkey_ok");
await go("/account");
await js(`document.querySelector('form[action="/account/passkeys/delete"]').submit()`);
await waitFor(`location.search.includes("passkey_removed")`);
// (the activity feed on the same page still mentions it, so check the Passkeys card itself)
ok(await js(`!document.querySelector('form[action="/account/passkeys/delete"]') && document.body.innerText.includes("No passkeys yet")`), "passkey removed", await js(`[...document.querySelectorAll(".card")].find(c => c.innerText.includes("Passkeys"))?.innerText`));
await logout();
await js(`document.getElementById("pk-login").click()`);
await sleep(2500);
ok((await path()).startsWith("/login"), "a removed passkey cannot sign in");
ok((await js(`document.getElementById("pk-msg").textContent`)).length > 0, "the login page explains why");

console.log(`ALL ${checks} PASSKEY CHECKS PASSED`);
cleanup(0);
