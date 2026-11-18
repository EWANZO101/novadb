# REST + WebSocket API (Stage 10)

`novadb-server … --rest 127.0.0.1:3380` serves a JSON API next to the MySQL port. It is plain
HTTP and refuses non-loopback addresses: put nginx (TLS, `X-Real-IP`) in front for remote use.

## Tokens
```sh
novadb-server token create --data-dir DIR --user app --scopes rows,query [--tables items,orders] [--days 90] [--name shop] [--rate 600]
novadb-server token list   --data-dir DIR
novadb-server token revoke --data-dir DIR <id>
```
* A token **acts as an SQL user**: the engine's `GRANT`s decide what it can read/write (create a
  dedicated user with only the privileges the API needs; `root` tokens get a warning).
* The secret (`nvdb_<id>_<64 hex>`) is printed once; only its SHA-256 is stored, in
  `<data>/rest-tokens.json` (0600). Changes apply without a restart.
* Scopes: **rows** (table CRUD), **query** (saved queries), **sql** (arbitrary single statements —
  explicit opt-in, still bound by GRANTs). `--tables` limits the rows scope to listed tables.
* Send `Authorization: Bearer <token>`.

## Saved queries (`query` scope)
```sh
novadb-server query add --data-dir DIR by_name 'SELECT * FROM items WHERE name = ?' --params name
novadb-server query list|remove …
```
Exactly one statement, `?` placeholders bound as values (never spliced into SQL).

## Endpoints
| Method + path | Scope | Notes |
|---|---|---|
| `GET /v1/health` | — | liveness |
| `GET /v1/tables` | rows | tables the user may access (∩ token allow-list) |
| `GET /v1/tables/{t}` | rows | DESCRIBE |
| `GET /v1/tables/{t}/rows` | rows | `where.col=v`, `where.col.gt|gte|lt|lte|ne|like=v`, `where.col.null=true|false`, `cols=a,b`, `order=a,-b`, `limit` (1–10000, default 1000), `offset`, `format=array` |
| `POST /v1/tables/{t}/rows` | rows | body: row object or `{"rows":[…]}` (≤ 10,000) → `affected`, `last_insert_id` |
| `PATCH /v1/tables/{t}/rows?where.…` | rows | body: `{col: value}`; a filter is required |
| `DELETE /v1/tables/{t}/rows?where.…` | rows | a filter is required |
| `POST /v1/query/{name}` | query | `{"params": {...} or [...]}` |
| `POST /v1/sql` | sql | `{"sql": "…", "params": [...]}` — one statement |
| `GET /v1/ws` | any | WebSocket, see below |

Results: `{"columns": [...], "rows": [{...}], "truncated": bool, "affected": n, "last_insert_id"?: n}`.
Values: integers as JSON numbers, DECIMAL/DATETIME/strings as strings, BLOB as base64, NULL as null.
Errors: `{"error": {"code": <MySQL errno>, "message": "…"}}` with 401 (token), 403 (scope/GRANT,
1142), 404 (unknown table/column/query), 409 (1062 duplicate, 1213 conflict, 1205 busy), 408
(timeout), 429 (rate limit), 400 (other).

## WebSocket `/v1/ws`
One session per socket (its own connection id): messages are JSON `{"id": n, "op": …}`, replies
`{"id": n, "ok": true, "result": …}` / `{"id": n, "ok": false, "error": {...}}`.
* `{"op":"ping"}`, `{"op":"query","name":…,"params":…}`, `{"op":"select","table":…,"where":{…},"limit":n}`
* `{"op":"sql","sql":…,"params":[…]}` — **transactions span messages** (`BEGIN` … `COMMIT`);
  closing the socket rolls back.
* `{"op":"subscribe","table":"t"}` (rows scope + SELECT grant) → after every COMMIT that touches
  `t`: `{"event":"change","table":"t","op":"put"|"delete","key":"<hex PK>","row":{…}}` (put only).
  Rolled-back work never produces events. Schema or GRANT changes re-check subscriptions
  (`{"event":"unsubscribed",…}` if access was lost); a slow client gets `{"event":"lagged"}`.
  Max 32 subscriptions per socket, 64 sockets per token.

## Limits & security (PLAN.md §4.8)
* Identifiers are quoted, values are bound parameters — `rows` and `query` can't inject SQL
  (tests try value, identifier and ORDER BY injection).
* 1 MiB bodies/messages, 10 s per SELECT, ≤ 10,000 rows per response.
* Per token: requests per minute (`--rate`, default 600). Per client IP: 30 failed token checks per
  minute, then 429 for the rest of the minute (even for valid tokens). `X-Real-IP` is honoured
  only from a loopback proxy.
* Tokens never appear in logs; revocation and expiry take effect immediately.

## SDKs (`sdk/`)
* **JavaScript** (`sdk/js/novadb.mjs`, no dependencies; Node 22+/Deno/Bun/browsers):
  `new NovaDB(url, token)`, `.table(t).select/get/insert/update/delete`, `.query`, `.sql`,
  `.live()` → `subscribe(table, fn)`, `sql` (transactions), `query`, `select`. Browsers can't set
  WebSocket headers — use it server-side or have the proxy add the header.
* **Python** (`sdk/python/novadb.py`, stdlib only): same REST surface; raises `NovaDBError`
  (`.status`, `.code`).

## Tests
`scripts/rest-test.mjs` (42 checks: auth, CRUD, filters, limits, injection attempts, GRANTs, scopes,
saved queries, WebSocket queries/transactions/change events) and `sdk/test-sdks.sh` (both SDKs)
against a live server; token store unit test in `tokens.rs`. Engine change hook: emitted only after
a durable commit, deferred to COMMIT for transactions with DDL.
