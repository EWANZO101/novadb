# ALTER TABLE

```sql
ALTER TABLE t
  ADD [COLUMN] col type … [FIRST | AFTER other],
  DROP [COLUMN] col,
  MODIFY [COLUMN] col type … [FIRST | AFTER other],
  CHANGE [COLUMN] old new type … [FIRST | AFTER other],
  RENAME COLUMN a TO b,
  ALTER [COLUMN] col SET DEFAULT v | DROP DEFAULT,
  ADD [UNIQUE] {INDEX|KEY} [name] (cols), DROP {INDEX|KEY} name, RENAME {INDEX|KEY} a TO b,
  ADD PRIMARY KEY (cols), DROP PRIMARY KEY,
  RENAME [TO|AS] new_name,
  ALGORITHM = …, LOCK = …          -- accepted; NovaDB always picks the cheapest safe way
```
Several actions can be combined; they apply in order and the result is validated like a
`CREATE TABLE` (one AUTO_INCREMENT leading a key, no BLOB/TEXT keys, unique names …).
Privileges: `ALTER` on the table (+ `DROP` on the old and `CREATE` on the new name for RENAME).

## How each change runs
| Kind | Changes | Cost |
|---|---|---|
| **Instant** | rename table/column/index, SET/DROP DEFAULT, DROP INDEX, ADD a *nullable column without default at the end*, NOT NULL → NULL, widening VARCHAR or INT → BIGINT on a column that is not in a key | catalog only, O(1); old rows read the new column as NULL |
| **Online rebuild** | everything else with the primary key unchanged: DROP/reorder columns, type changes, ADD INDEX/UNIQUE, NULL → NOT NULL, new column with a default | rows copied in batches of 1,000 into a hidden shadow table; other sessions keep reading and writing |
| **Blocking rebuild** | primary key added/dropped/changed, or ALTER inside a transaction | one atomic step; the engine is busy for the whole copy; limited by memory (very large tables: change the key with a new table + `INSERT … SELECT`) |

The result's info says `(instant)` or `(online)`; `affected` = rows copied.

### Online rebuild in detail
1. A shadow table with the new schema is created under a hidden catalog key (`s\0<id>`); it is
   invisible to SQL.
2. Each step copies the next 1,000 rows (by primary key) from the latest committed data and
   converts them (type conversion is strict: a value that does not fit aborts the ALTER).
3. Every commit by any session records the primary keys it changed in the table; those rows are
   re-synced into the shadow (insert, update or delete) after the copy.
4. When the copy is done and at most one batch of changes is left, the last changes and the
   swap (catalog entry, AUTO_INCREMENT / row-id counters, old trees dropped) happen in **one
   storage transaction**. The swap needs a moment where no transaction is open (their write
   sets point at the old trees); it waits up to 50 s, then fails with 1205 and the table is
   unchanged.
5. The network server releases the engine lock between steps, so other connections run in
   between. Other DDL waits (1205) while an ALTER is running; only one runs at a time.

Failures (duplicate values for a new unique index → 1062, NOT NULL on a NULL value → 1048,
data that does not fit the new type, `KILL`, disconnect) drop the shadow; the table is unchanged.
A crash during an ALTER leaves the old table intact; the leftover shadow is removed at the next
open.

The binlog records the ALTER statement once it has succeeded, so point-in-time recovery replays
it (a column added with `DEFAULT CURRENT_TIMESTAMP` gets the replay time).

## Tests
`crates/novadb-sql/tests/alter.rs`: instant changes (incl. reopen), online rebuild reshaping rows
(drop/reorder/type/unique/rename at once, AUTO_INCREMENT continues), online rebuild with inserts,
updates, deletes and transactions from four other sessions between steps (result checked through
the new index and the PK), swap waiting for an open transaction, failures + KILL leave the table
unchanged and no shadow, crash mid-ALTER cleanup, primary key add/drop (blocking) and transactional
ALTER commit/rollback, binlog replay, parser. Over the wire: 30,000-row online ALTER with
concurrent inserts from another client.
