#!/usr/bin/env bash
# Exercise both SDKs against a running server: sdk/test-sdks.sh BASE_URL TOKEN(rows,query,sql on items)
set -euo pipefail
cd "$(dirname "$0")"
BASE=$1 TOK=$2
node --input-type=module -e "
import { NovaDB, NovaDBError } from './js/novadb.mjs';
const db = new NovaDB('$BASE', '$TOK');
const t = db.table('items');
let n = 0; const ok = (c, w) => { n++; if (!c) { console.log('FAIL js', w); process.exit(1); } };
ok((await db.health()).ok, 'health');
const ins = await t.insert([{ name: 'sdk-a', qty: 1 }, { name: 'sdk-b', qty: 2 }]);
ok(ins.affected === 2, 'insert');
ok((await t.get({ name: 'sdk-b' })).qty === 2, 'get');
await t.update({ qty: 5 }, { where: { name: 'sdk-a' } });
ok((await t.select({ where: { 'name.like': 'sdk-%' }, order: '-qty' })).rows[0].name === 'sdk-a', 'update/select');
try { await t.insert({ id: ins.last_insert_id, name: 'x' }); ok(false, 'dup'); } catch (e) { ok(e instanceof NovaDBError && e.code === 1062 && e.status === 409, 'dup error'); }
ok((await db.sql('SELECT COUNT(*) AS n FROM items WHERE name LIKE ?', ['sdk-%'])).rows[0].n === 2, 'sql');
const live = await db.live();
const got = new Promise((res) => live.subscribe('items', (ev) => { if (ev.op === 'delete') res(ev); }));
await live.sql('BEGIN'); await live.sql('DELETE FROM items WHERE name LIKE ?', ['sdk-%']); await live.sql('COMMIT');
ok((await got).table === 'items', 'live delete event');
live.close();
console.log('JS SDK: ' + n + ' checks passed');
"
python3 - "$BASE" "$TOK" <<'PY'
import sys
sys.path.insert(0, "python")
from novadb import NovaDB, NovaDBError
db = NovaDB(sys.argv[1], sys.argv[2])
t = db.table("items")
assert db.health()["ok"]
r = t.insert([{"name": "py-a", "qty": 1}, {"name": "py-b", "qty": None}])
assert r["affected"] == 2
assert t.get({"name": "py-b"})["qty"] is None
assert len(t.select(where={"qty.null": True, "name.like": "py-%"})["rows"]) == 1
t.update({"qty": 9}, where={"name": "py-b"})
assert db.sql("SELECT qty FROM items WHERE name = ?", ["py-b"])["rows"][0]["qty"] == 9
try:
    db.table("secret").select()
    raise SystemExit("FAIL py: secret readable")
except NovaDBError as e:
    assert e.status == 403 and e.code == 1142
assert t.delete(where={"name.like": "py-%"})["affected"] == 2
print("Python SDK: 7 checks passed")
PY
