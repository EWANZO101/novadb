# NovaDB SQL (Stages 3 + 6, single node)

Crate: `crates/novadb-sql`. Everything is hand-written (PLAN.md §2): lexer, recursive-descent
parser, value semantics, key/row encodings, catalog, planner and executor. No new dependencies
beyond `novadb-storage`.

## Try it
    novadb DATA_DIR sql "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(20)); INSERT INTO t (name) VALUES ('a')"
    novadb DATA_DIR shell        # interactive; end statements with ;  (exit / quit)

From Rust: `Engine::open(dir)?.execute(sql)` → `Vec<QueryResult>` (columns + typed `Value`s,
affected rows, last insert id). Errors are `SqlError { code, state, msg }` with **MySQL error
numbers and SQLSTATEs** (1064 syntax, 1146 no table, 1062 duplicate, 1048 not null, 1406 too
long, 1264 out of range, …) so the Stage 4 wire protocol can pass them through unchanged.

## Supported
| Area | What works |
|---|---|
| DDL | `CREATE TABLE [IF NOT EXISTS]` (column + table level `PRIMARY KEY`, `UNIQUE [KEY]`, `KEY/INDEX`, `NOT NULL`, `DEFAULT literal`, `DEFAULT CURRENT_TIMESTAMP`, `AUTO_INCREMENT`, `COMMENT`; `ENGINE=`/charset options accepted and ignored), `DROP TABLE [IF EXISTS] a, b`, `CREATE [UNIQUE] INDEX … ON t (…)` (built from existing rows, uniqueness checked), `DROP INDEX … ON t` |
| DML | `INSERT INTO t [(cols)] VALUES (…), (…)` (also `() VALUES ()`), `UPDATE … SET … [WHERE] [ORDER BY] [LIMIT]`, `DELETE FROM … [WHERE] [ORDER BY] [LIMIT]` |
| Queries | `SELECT [DISTINCT] exprs | * | t.* FROM t [AS a] [[INNER|LEFT|RIGHT|CROSS] JOIN u [AS b] ON …|USING (…) | , u …] [WHERE] [GROUP BY …] [HAVING …] [ORDER BY expr|alias|position [ASC|DESC], …] [LIMIT n [OFFSET m] | LIMIT m, n]`, `SELECT` without `FROM` (Stage 6) |
| Aggregates | `COUNT(*)`, `COUNT/SUM/AVG/MIN/MAX/GROUP_CONCAT([DISTINCT] …)`, `GROUP_CONCAT(… SEPARATOR '…')`; aggregates over joins; HAVING with aliases; ORDER BY aggregates |
| Subqueries | scalar `(SELECT …)`, `[NOT] IN (SELECT …)`, `[NOT] EXISTS (SELECT …)` in SELECT/WHERE/HAVING/UPDATE/DELETE/INSERT; `INSERT … SELECT`. Uncorrelated only — a subquery referring to an outer column returns `ERROR 1235` |
| Privileges | `GRANT priv[, …] ON *.* | t TO user [WITH GRANT OPTION]`, `REVOKE … ON … FROM user`, `SHOW GRANTS [FOR user]` — see [Privileges](#privileges) |
| Control | `KILL [QUERY|CONNECTION] id`, `SHOW PROCESSLIST` (server), `SET max_execution_time = ms` (SELECT; error 3024) |
| Introspection | `SHOW TABLES`, `DESCRIBE t` / `SHOW COLUMNS FROM t`, `SHOW CREATE TABLE t` (output re-parses), `EXPLAIN SELECT/UPDATE/DELETE` |
| Types | `INT`, `BIGINT`, `DECIMAL(p,s)` (exact, p ≤ 38), `VARCHAR(n)`/`CHAR(n)`, `TEXT`, `BLOB` (≤ 64 KiB), `DATETIME[(fsp)]` (1000-01-01 … 9999-12-31, µs) |
| Expressions | `+ - * / DIV % MOD`, comparisons incl. `<=>`, `AND OR XOR NOT`, `IS [NOT] NULL/TRUE/FALSE`, `[NOT] IN (…)`, `[NOT] BETWEEN`, `[NOT] LIKE` (`%`, `_`, `\` escape), literals incl. `X'..'`/`0x..`, `TRUE/FALSE`, `NULL` |
| Functions | `NOW([fsp])`/`CURRENT_TIMESTAMP`, `LOWER/UPPER`, `LENGTH`, `CHAR_LENGTH`, `CONCAT`, `COALESCE`, `IFNULL`, `NULLIF`, `IF`, `ABS`, `ROUND(x[,d])`, `SUBSTRING/SUBSTR`, `VERSION()`, `DATABASE()` |
| Semantics | three-valued logic; strict mode (bad data is an error, not a warning); `/` gives scale+4 like MySQL; division by zero → NULL; integer overflow → error 1690; DECIMAL rounding half away from zero; AUTO_INCREMENT on NULL/0, explicit values move the counter, `last_insert_id` = first generated id |
| Atomicity | every statement is one storage transaction: a multi-row INSERT failing on row 3 stores nothing |

## How it is stored
* Catalog tree `sql:catalog`: table schemas (binary, versioned, validated on decode), table-id
  and AUTO_INCREMENT / hidden row-id counters.
* Rows: tree `sql:t:<table id>`, key = order-preserving encoding of the primary key (or a hidden
  row id when there is no PK). Rows larger than one storage value (4 KiB) are split into 4000-byte
  chunks in `sql:o:<table id>`; max row 4 MiB.
* Secondary indexes: tree `sql:i:<table id>:<index id>`, key = indexed columns ‖ primary key,
  value = primary key. Unique indexes allow several NULLs (like MySQL).
* Key encoding is memcomparable and self-delimiting (sign-flipped big-endian ints/decimals,
  0x00-escaped strings terminated by `00 01`), so composite keys are concatenations and prefix
  scans work.

## Planner
Multi-table queries (Stage 6): every column reference is resolved once to a position in the
combined row (ambiguous / unknown names are reported there), joins run as nested loops in FROM
order (RIGHT JOIN of two tables runs as the mirrored LEFT JOIN), and each WHERE conjunct is
evaluated at the earliest join level that binds all its tables (never pushed into the
NULL-extended side of a LEFT JOIN). For every outer row the inner table is scanned with its ON
condition and those conjuncts, outer values substituted as literals, so the single-table planner
below picks the inner table's primary key or index for equi-joins (index nested-loop join).
There is no join reordering yet: put the most selective table first.

Single-table access paths:
Picks, in order: full primary-key equality (`const`) → unique index full equality (`const`) →
primary-key range on its first column (`range`) → equality prefix of any index (`ref`) → range on
an index's first column (`range`) → full scan (`ALL`). A literal is only used as a key bound if it
converts to the column type **without changing value and compares the same way** (`id = 1.5` on
an INT, or `varchar_col = 5`, fall back to a scan), and the full WHERE is always re-checked on
every row — so an index can only make a query faster, never change its result. This is tested by
running random workloads against an indexed and an unindexed copy of the same table.

## Limits / not yet (by design, later stages)
* No correlated subqueries, UNION, window functions, CTEs, derived tables (`FROM (SELECT …)`), ALTER TABLE.
* Transactions (`BEGIN … COMMIT/ROLLBACK`, snapshot isolation): see [transactions.md](transactions.md). `CREATE/DROP TABLE/INDEX` inside a transaction roll back with it ([transactional DDL](transactions.md#transactional-ddl)); user/GRANT statements still commit implicitly.
* Sorting, join results, groups and UPDATE/DELETE candidate sets are in memory, capped at
  1,000,000 rows (`MAX_ROWS_IN_MEMORY`); there is no disk spill yet.
* Collation is binary (case-sensitive `'a' <> 'A'`); MySQL's default is case-insensitive.
* Table and column names are case-insensitive (like `lower_case_table_names=1`).
* FLOAT/DOUBLE, DATE/TIME/TIMESTAMP, ENUM/SET, JSON are not implemented.
* No roles (`CREATE ROLE`), no column-level grants. Backups / binlog / PITR: [operations.md](operations.md).

## Privileges
Least privilege by default: `CREATE USER` gives a login and **nothing else**.

| scope | privileges |
|---|---|
| table (`ON t`) | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `DROP`, `INDEX`, `ALTER` |
| global (`ON *.*`) | all of the above for every table, plus `CREATE USER`, `PROCESS`, `SUPER`; `ALL [PRIVILEGES]` |

* Every table a statement touches is checked — joins, subqueries and `INSERT … SELECT` included.
  Denied → `ERROR 1142`; missing global privilege → `1227`; global-only privilege on a table → `1144`;
  grant to an unknown user → `1410`.
* `SHOW TABLES` only lists tables you have some privilege on (no name leaks).
* `WITH GRANT OPTION` lets a user pass on **only privileges they hold themselves**.
* Users may change only their own password; `DROP USER` removes their grants.
* `BACKUP` needs `SUPER`; `KILL` of someone else's connection needs `SUPER`; the full
  `SHOW PROCESSLIST` needs `PROCESS`.
* `root` always has every privilege (the server can't be locked out).
* Enforced by the network server (`Engine::with_privileges`). An embedded engine (CLI,
  dashboard workspace) is trusted and does not check grants.
* Grants are stored in tree `sql:grants`, included in backups and written to the binary log
  (replayed on restore / PITR).
* Tests: `tests/privs.rs`.

## Tests
* Unit tests in every module (lexer, parser incl. depth bombs, decimal/datetime maths, LIKE,
  key-order properties, row/catalog codecs incl. every truncation).
* `tests/sql.rs`: CRUD + persistence across reopen, NULL logic, strict typing, overflow rows
  (60 KB TEXT, shrink/grow/delete leaves no orphan chunks), constraints + statement atomicity,
  ORDER/LIMIT/DISTINCT/aliases, planner choices, DDL/introspection (SHOW CREATE TABLE re-parses),
  hostile input, and the randomised **index-vs-full-scan differential test** (600 rounds).
* Fuzz targets `sql_parse` (lexer+parser) and `sql_exec` (fuzzed statements against a live
  in-memory DB with indexes, then a full storage `verify`).
