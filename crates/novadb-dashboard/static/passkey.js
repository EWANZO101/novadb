// NovaDB dashboard — passkeys (WebAuthn). The only script on the site; no inline code.
"use strict";
(function () {
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64 = (s) => {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
  };
  const say = (msg, bad) => {
    const el = document.getElementById("pk-msg");
    if (el) { el.textContent = msg; el.className = bad ? "hint err" : "hint"; }
  };
  const post = async (url, body, csrf) => {
    const h = { "content-type": "application/json" };
    if (csrf) h["x-csrf"] = csrf;
    const r = await fetch(url, { method: "POST", headers: h, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
    let j = {};
    try { j = await r.json(); } catch (e) { /* empty */ }
    if (!r.ok || j.ok === false) throw new Error(j.error || ("HTTP " + r.status));
    return j;
  };
  const supported = () => window.PublicKeyCredential && navigator.credentials && navigator.credentials.create;

  const add = document.getElementById("pk-add");
  if (add) {
    add.addEventListener("click", async () => {
      if (!supported()) return say("This browser does not support passkeys.", true);
      const csrf = add.dataset.csrf;
      add.disabled = true;
      try {
        say("Follow your browser's prompt…");
        const val = (id) => (document.getElementById(id) || {}).value || "";
        const o = await post("/account/passkeys/begin", { current: val("pk-pw"), code: val("pk-code") }, csrf);
        const pw = document.getElementById("pk-pw");
        if (pw) pw.value = "";
        o.challenge = unb64(o.challenge);
        o.user.id = unb64(o.user.id);
        o.excludeCredentials = (o.excludeCredentials || []).map((c) => ({ ...c, id: unb64(c.id) }));
        const cred = await navigator.credentials.create({ publicKey: o });
        const name = (document.getElementById("pk-name") || {}).value || "";
        await post("/account/passkeys/finish", {
          name,
          id: cred.id,
          response: {
            attestationObject: b64(cred.response.attestationObject),
            clientDataJSON: b64(cred.response.clientDataJSON),
          },
        }, csrf);
        location.href = "/account?ok=passkey_added";
      } catch (e) {
        say(e.name === "NotAllowedError" ? "Cancelled or timed out." : ("Could not add the passkey: " + e.message), true);
      } finally {
        add.disabled = false;
      }
    });
  }

  const login = document.getElementById("pk-login");
  if (login) {
    if (!supported()) { login.hidden = true; }
    login.addEventListener("click", async () => {
      login.disabled = true;
      try {
        say("Follow your browser's prompt…");
        const b = await post("/login/passkey/begin");
        const o = b.publicKey;
        o.challenge = unb64(o.challenge);
        o.allowCredentials = [];
        const a = await navigator.credentials.get({ publicKey: o });
        const r = await post("/login/passkey/finish", {
          flow: b.flow,
          id: a.id,
          response: {
            authenticatorData: b64(a.response.authenticatorData),
            clientDataJSON: b64(a.response.clientDataJSON),
            signature: b64(a.response.signature),
            userHandle: a.response.userHandle ? b64(a.response.userHandle) : null,
          },
        });
        location.href = r.redirect || "/";
      } catch (e) {
        say(e.name === "NotAllowedError" ? "Cancelled or timed out." : e.message, true);
      } finally {
        login.disabled = false;
      }
    });
  }
})();
