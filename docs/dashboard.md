# NovaDB control dashboard (Stage 9)

Crate: `crates/novadb-dashboard`. Server-rendered HTML, **no JavaScript**, one binary.

> Built ahead of Stages 3–8 at the owner's request (2026-11-18). There is no SQL server yet, so the
> dashboard currently manages its own identity system and shows engine/system-DB health. Database,
> cluster and backup screens are added as those stages land.

## What it does today
| Area | Details |
|---|---|
| Storage | Users, sessions, OAuth links, audit log live in NovaDB's own storage engine (`<data>/system`), opened with crash recovery. |
| First run | No default credentials (PLAN §4.1). Creates `admin` with a 24-char random password in `<data>/initial-admin-password.txt` (0600, `create_new`). Not printed to logs. File is deleted after the first password change. |
| Passwords | Argon2id (m=19 MiB, t=2, p=1), 12–128 chars, rejects username/common words; new ≠ old. Unknown users are verified against a dummy hash (no user enumeration by timing or message). |
| 2FA | TOTP (RFC 6238) **mandatory for every account**; enrolment shows QR (inline SVG) + key; codes single-use (last accepted step stored → replay rejected). Moving 2FA needs password + current code. |
| Sessions | 256-bit token in `__Host-novadb_session` (Secure, HttpOnly, SameSite=Lax); only SHA-256 of the token is stored. Idle 30 min, absolute 12 h, pruned every 5 min. Session id rotated at every privilege change (password ok → TOTP ok → setup done). Users can see and revoke their sessions; password change / disable / 2FA reset revoke sessions. |
| Brute force (§4.5) | Per-IP 10 logins / 5 min and per-user 20 / 5 min **before** hashing; max 2 concurrent Argon2 hashes; 10 wrong passwords → 15 min lock; 6 wrong TOTP codes / 5 min kill the half-authenticated session. nginx adds its own limits in front. |
| CSRF | Every POST carries a per-session token (constant-time compare) + Origin / Sec-Fetch-Site check. |
| Headers | CSP `default-src 'none'` (style from self only, no scripts), `frame-ancestors 'none'`, XFO DENY, nosniff, no-referrer, `Cache-Control: no-store`, COOP. |
| Roles | `viewer` (overview, account), `operator` (+ audit log, system), `admin` (+ users, sessions, checkpoint). Always at least one active admin; admins cannot act on themselves from the Users page. |
| Users | Create (one-time password shown once, must change + enrol 2FA), disable/enable, unlock, reset password, reset 2FA, change role, delete. |
| Recovery codes | 10 single-use codes (80 bit, base32 `XXXX-XXXX-XXXX-XXXX`), shown once; only SHA-256 stored. Creating them needs password + fresh TOTP. Usable at the 2FA step instead of a TOTP code (same attempt budget). Admin "Reset 2FA" clears them. |
| Audit search | Filter by text / event type / user, 50 per page, CSV export (formula-injection safe, the export itself is audited). |
| Sessions (admin) | Every session of every user with state and expiry; revoke one or "sign out everyone else". Users can sign out all their other devices from Account. |
| System (operator+) | Runtime (RSS, threads, fds), storage stats, integrity verify, crash-recovery report, system trees, effective security policy. Admins can force a checkpoint. |
| Overview | Warnings (no recovery codes, locked users, users without 2FA, failed sign-ins) + recent activity feed. |
| OAuth (§4.9) | Discord + GitHub, optional (env vars). `state` (single-use, 10 min) + PKCE S256 + browser-binding cookie + exact redirect URI. **Linking only while fully logged in**; login looks up the provider **user id** — no auto-create, no e-mail matching. OAuth skips the password, **never** the TOTP step. |
| Audit (§4.18) | Append-only, hash-chained (`sha256(prev ‖ fields)`), entry + head written in one transaction. Verified on every Overview/Audit load; tampering, deletion or truncation shows "chain broken". No passwords, codes, tokens or secrets are ever logged. |
| Proxy (§4.13) | `X-Real-IP` trusted only from `NOVADB_DASH_TRUSTED_PROXY` (default 127.0.0.1). Refuses to bind a non-loopback address without an https public URL. |

Not done yet: **passkeys/WebAuthn** (next), e-mail, per-database permissions
(needs Stage 3+), REST tokens (Stage 10).

## Configuration (environment)
| var | default |
|---|---|
| `NOVADB_DASH_DATA` | `./dashboard-data` (`/data` in the image) |
| `NOVADB_DASH_LISTEN` | `127.0.0.1:9620` |
| `NOVADB_DASH_PUBLIC_URL` | `http://<listen>`; set to the https URL behind nginx (used for Origin check + OAuth redirect URIs) |
| `NOVADB_DASH_TRUSTED_PROXY` | `127.0.0.1` (`none` to never trust X-Real-IP) |
| `NOVADB_DISCORD_CLIENT_ID` / `NOVADB_DISCORD_CLIENT_SECRET` | unset → Discord button hidden |
| `NOVADB_GITHUB_CLIENT_ID` / `NOVADB_GITHUB_CLIENT_SECRET` | unset → GitHub button hidden |

OAuth redirect URIs to register: `<public url>/oauth/discord/callback`, `<public url>/oauth/github/callback`.

## Build + run
    docker run --rm -v "$PWD":/src -w /src --entrypoint cargo novadb-builder build --release --locked -p novadb-dashboard
    cp target/release/novadb-dashboard docker/
    docker build -f docker/dashboard.Dockerfile -t novadb-dashboard docker/ && rm docker/novadb-dashboard
    docker run -d --name novadb-dashboard --restart unless-stopped --network host --read-only \
      --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges --memory 384m --cpus 0.5 \
      --pids-limit 128 -v novadb-dash-data:/data \
      -e NOVADB_DASH_PUBLIC_URL=https://novadb.example.com novadb-dashboard
    docker exec novadb-dashboard cat /data/initial-admin-password.txt   # once

## Tests
* `cargo test -p novadb-dashboard` — TOTP RFC 6238 vectors + replay, base32, PKCE RFC 7636 vector,
  Argon2id parameters, password policy, rate limiter, HTML escaping, audit-chain tamper/delete
  detection, persistence of users/sessions/links across reopen, OAuth state single-use.
* `scripts/dashboard-e2e.py` — 64 black-box checks (incl. browser-style Origin/Sec-Fetch-Site) against a **throwaway** instance (forced setup,
  CSRF/Origin, roles, TOTP replay, session revocation, logout, audit chain, no secrets in log,
  HTTP 429 on brute force).
