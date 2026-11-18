# NovaDB server — MySQL wire protocol (Stage 4)

Crates: `novadb-protocol` (pure encode/decode, no I/O, fuzzed) and `novadb-server`
(tokio + rustls listener). Clients that speak MySQL 8 connect with their normal drivers.

## Run
    novadb-server --data-dir /var/lib/novadb [--listen 127.0.0.1:3307] [--tls-cert cert.pem --tls-key key.pem]

First start:
* creates the database in `<data>/db`,
* creates user `root` with a random 24-character password in `<data>/initial-root-password.txt`
  (mode 0600) — there are **no default credentials**. Change it, then delete the file:
  `ALTER USER root IDENTIFIED BY '…';`
* without `--tls-cert/--tls-key`, generates a self-signed certificate for `localhost`/`127.0.0.1`
  in `<data>/tls/` (key 0600). Give clients that certificate as their CA.

Connect:
    mariadb -h127.0.0.1 -P3307 -uroot -p --ssl-ca=<data>/tls/server.crt novadb
    mysql   -h127.0.0.1 -P3307 -uroot -p --ssl-mode=VERIFY_CA --ssl-ca=<data>/tls/server.crt novadb
    # Node:   mysql.createConnection({host:'127.0.0.1', port:3307, user, password, ssl:{ca}})

There is one database, `novadb` (`USE novadb`, `COM_INIT_DB` and connect-with-database accept
only that name; `SHOW DATABASES` lists it).

## Security model
| Item | Behaviour |
|---|---|
| Transport | TLS 1.2/1.3 (rustls, ring) is **required**. A client that does not upgrade gets `ERROR 3159 … insecure transport` before any credential is sent. |
| Authentication | `caching_sha2_password` plugin, always **full authentication**: the client sends the password inside TLS and it is verified against an **Argon2id** hash (m=19 MiB, t=2, p=1). No fast-auth SHA-256 cache exists to steal. Clients asking for another plugin are switched; `mysql_native_password` (SHA1) is never offered (PLAN §4.4). |
| User enumeration | Unknown users are checked against a dummy hash; wrong user and wrong password both return `ERROR 1045 Access denied`. |
| Brute force | Before any hashing: 20 attempts/min per IP and 30/min per user, then `ERROR 1129`; at most 2 Argon2 verifications run at once (PLAN §4.5). |
| Pre-auth DoS | Packets > 64 KiB before login close the connection (nothing allocated from client lengths beyond that); the whole handshake must finish in 10 s; max 32 connections per IP and 256 total (`ERROR 1040`) (PLAN §4.6). |
| After login | `max_allowed_packet` 64 MiB, statements ≤ 16 MiB (parser limit), idle connections closed after 8 h, ≤ 1024 prepared statements per connection, long data ≤ 16 MiB per parameter. |
| Users | `CREATE USER [IF NOT EXISTS] 'u'@'host' IDENTIFIED BY '…'`, `ALTER USER … IDENTIFIED BY`, `DROP USER [IF EXISTS]` (the last user cannot be dropped). Passwords 12–128 characters. The host part is accepted but ignored (the server listens on loopback by default). |
| Not yet | **No privileges**: every user can do everything (GRANT arrives with roles in a later stage). No `mysql_clear_password`, no RSA key exchange (TLS covers it), no client certificates. |
| Logging | Failed / rate-limited logins are logged with user and IP; passwords never are. |

## Protocol coverage
* Handshake v10, SSLRequest, HandshakeResponse41 (incl. `CLIENT_PLUGIN_AUTH_LENENC`,
  connect-with-db, connection attributes), AuthSwitchRequest, caching_sha2 full auth.
* Commands: `COM_QUERY` (multi-statements + multi-results when the client enables them),
  `COM_STMT_PREPARE/EXECUTE/SEND_LONG_DATA/CLOSE/RESET` (binary protocol; all parameter
  types: integers incl. unsigned, FLOAT/DOUBLE → exact DECIMAL, DECIMAL, strings, BLOBs,
  DATE/DATETIME/TIMESTAMP, TIME), `COM_PING`, `COM_INIT_DB`, `COM_QUIT`, `COM_SET_OPTION`,
  `COM_RESET_CONNECTION`, `COM_STATISTICS`. `COM_FIELD_LIST` (deprecated) returns an error.
* Text and binary result sets with `CLIENT_DEPRECATE_EOF` and the classic EOF format.
  Column types: INT→LONG, BIGINT→LONGLONG, DECIMAL→NEWDECIMAL, VARCHAR→VAR_STRING,
  TEXT/BLOB→BLOB (utf8mb4 / binary), DATETIME→DATETIME with fractional digits.
  Expression columns get one consistent type inferred from their values.
* Errors carry MySQL error numbers and SQLSTATEs from the SQL layer unchanged.

## Client compatibility statements (Stage 4 additions to the SQL layer)
`SET NAMES …`, `SET [SESSION] var = …` (known variables accepted; behaviour stays fixed:
utf8mb4, strict mode, autocommit), `SET TRANSACTION …`, `USE`, `SHOW DATABASES`,
`SHOW VARIABLES [LIKE …]`, `SHOW STATUS`, `SHOW WARNINGS`, `@@system_variables`
(`@@version_comment`, `@@max_allowed_packet`, `@@autocommit`, …), `CURRENT_USER()`,
`CONNECTION_ID()`, `LAST_INSERT_ID()`, `?` placeholders.

Transactions (`BEGIN`/`COMMIT`/`ROLLBACK`, `SET autocommit=0`) are real since Stage 5 — see
[transactions.md](transactions.md). OK packets carry the IN_TRANS / AUTOCOMMIT status bits and a
disconnect rolls back.

## Tested with
* `mariadb` command-line client (TLS with `--ssl-ca`, batch + interactive).
* Node.js `mysql2` 3.11 (text + binary protocol, prepared statements, BLOB/DECIMAL/DATETIME/NULL,
  multi-statements, user management, error codes) — 20/20 checks.
* `scripts/wire-test.sh` (runs in the builder image on every test run): real mariadb client
  CRUD, error codes, plaintext refusal, wrong password, then `scripts/protocol-abuse.py`
  (oversized pre-auth packet, garbage, 10 s handshake timeout, 33-connection flood, brute-force
  rate limit).
* Fuzz target `protocol_decode` (handshake response, SSL request, password packet,
  COM_STMT_EXECUTE parameters incl. reused types and long data, length-encoded fields).
* Not yet tested here: PHP PDO, Python connectors, JDBC, HeidiSQL, DBeaver (GUI tools also query
  `information_schema`, which does not exist yet).
