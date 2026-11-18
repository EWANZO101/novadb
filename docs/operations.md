# Operations (Stage 7)

## Running
* **systemd**: `packaging/novadb.service` — dedicated `novadb` user, `ProtectSystem=strict`,
  only `/var/lib/novadb` writable, no capabilities, `NoNewPrivileges`, seccomp filter
  (`@system-service` minus privileged/mount/module/raw-io…), `MemoryDenyWriteExecute`,
  loopback listener, memory/task caps. Verified with `systemd-analyze verify`.
* **Docker**: `docker/server.Dockerfile` (non-root uid, data volume). Publish on loopback:
  `-p 127.0.0.1:3307:3307`, run with `--read-only --cap-drop ALL --security-opt no-new-privileges`.
* First start creates, all mode 0600 in the data directory: the one-time `root` password
  (`initial-root-password.txt`), a self-signed TLS certificate (`tls/`) unless you pass
  `--tls-cert/--tls-key`, and the **backup/binlog encryption key** (`keys/backup.key`).
  **Copy the key off the server** (password manager / offline storage); without it backups and
  binary logs cannot be read — which is the point if the server or a backup bucket is stolen.
  Use `--backup-key FILE` to keep the key elsewhere, `novadb-server --gen-backup-key FILE` to
  make one.

## Backups (online, consistent, encrypted)
    BACKUP DATABASE TO 'nightly-2026-11-18';      -- as root
* Writes `<data>/backups/<name>.nbk`. Names are restricted to `[A-Za-z0-9._-]{1,64}`: SQL can
  never write anywhere else on the filesystem.
* Consistent: the dump reads one MVCC snapshot; other sessions keep reading **and writing** while
  it runs (the engine lock is released between 200-row batches).
* Always encrypted (XChaCha20-Poly1305, 64 KiB chunks, chunk index + final-chunk flag
  authenticated → truncation, reordering and tampering are detected on restore).
* Contains tables, rows, users (password hashes) and AUTO_INCREMENT counters.
* The binary log is rotated at every backup so old files can be archived/purged together.
* Schedule with cron/systemd timers through any MySQL client, e.g.
  `mysql --defaults-extra-file=/etc/novadb/backup.cnf -e "BACKUP DATABASE TO 'nightly-$(date +%F)'"`,
  then copy the `.nbk` file off-site. **Test restores regularly.**

## Binary log + point-in-time recovery
* On by default (`--no-binlog` turns it off): every committed transaction's row changes, all DDL
  and user changes go to `<data>/binlog/NNNNNN.binlog`, **encrypted** with the same key, fsynced
  *before* the storage commit. On startup records newer than the last storage commit (a crash in
  between) and torn tails are trimmed, so the log never claims more than the database has.
* Restore + replay into a **new** directory, optionally up to a moment (UTC):

      novadb-server --restore /backups/nightly-2026-11-18.nbk --data-dir /var/lib/novadb-restored \
        --backup-key /secure/backup.key --binlog-dir /var/lib/novadb/binlog --until '2026-11-18 14:59:00'

  Then start a server on it (point the unit's `--data-dir` at it, or swap directories).
* Tested end to end: restore + replay reproduces the live database exactly (tables, rows,
  indexes, users, counters, DDL); `--until` reproduces the state at that moment; rolled-back
  transactions never appear.

## Metrics (Prometheus)
`--metrics 127.0.0.1:9104` serves `GET /metrics` (text format). A non-loopback address requires
`--metrics-token-file` (bearer token). Exported: uptime, active/total connections, failed and
rate-limited logins, statements, errors, time spent, transaction conflicts (1213), interrupted
statements (KILL / timeout), backups, open transactions, storage pages / free pages / WAL bytes /
page reads / writes / checkpoints.

## Not done yet (honest list)
* Backup retention/rotation and off-site upload are left to cron + your storage (no built-in S3).
* `PURGE BINARY LOGS` statement — delete old `binlog/*.binlog` files older than your oldest
  backup by hand or by cron.
* Backups are logical (SQL); very large databases restore slower than a physical copy would.
* Restoring requires an empty target directory; there is no in-place "rewind".
