# NovaDB SQL (Stage 3 — single node)

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
| Queries | `SELECT [DISTINCT] exprs | * [FROM t] [WHERE] [ORDER BY expr|alias|position [ASC|DESC], …] [LIMIT n [OFFSET m] | LIMIT m, n]`, `SELECT` without `FROM` |
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
Picks, in order: full primary-key equality (`const`) → unique index full equality (`const`) →
primary-key range on its first column (`range`) → equality prefix of any index (`ref`) → range on
an index's first column (`range`) → full scan (`ALL`). A literal is only used as a key bound if it
converts to the column type **without changing value and compares the same way** (`id = 1.5` on
an INT, or `varchar_col = 5`, fall back to a scan), and the full WHERE is always re-checked on
every row — so an index can only make a query faster, never change its result. This is tested by
running random workloads against an indexed and an unindexed copy of the same table.

## Limits / not yet (by design, later stages)
* No joins, GROUP BY / aggregates, subqueries, HAVING (Stage 6); no ALTER TABLE yet.
* Multi-statement transactions: see [transactions.md](transactions.md) (Stage 5, snapshot isolation). Statements execute one at a time.
* Sorting and UPDATE/DELETE candidate sets are in memory, capped at 1,000,000 rows
  (`MAX_ROWS_IN_MEMORY`); disk spill arrives with the Stage 6 planner.
* Collation is binary (case-sensitive `'a' <> 'A'`); MySQL's default is case-insensitive.
* Table and column names are case-insensitive (like `lower_case_table_names=1`).
* FLOAT/DOUBLE, DATE/TIME/TIMESTAMP, ENUM/SET, JSON are not implemented.
* No network server yet: the MySQL protocol on 127.0.0.1:3307 is Stage 4.

## Tests
* Unit tests in every module (lexer, parser incl. depth bombs, decimal/datetime maths, LIKE,
  key-order properties, row/catalog codecs incl. every truncation).
* `tests/sql.rs`: CRUD + persistence across reopen, NULL logic, strict typing, overflow rows
  (60 KB TEXT, shrink/grow/delete leaves no orphan chunks), constraints + statement atomicity,
  ORDER/LIMIT/DISTINCT/aliases, planner choices, DDL/introspection (SHOW CREATE TABLE re-parses),
  hostile input, and the randomised **index-vs-full-scan differential test** (600 rounds).
* Fuzz targets `sql_parse` (lexer+parser) and `sql_exec` (fuzzed statements against a live
  in-memory DB with indexes, then a full storage `verify`).
