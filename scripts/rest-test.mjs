// End-to-end test of the REST + WebSocket API (Stage 10).
// usage: node scripts/rest-test.mjs BASE_URL ROWS_TOKEN SQL_TOKEN LIMITED_TOKEN
//   ROWS_TOKEN    scopes rows,query as user `app` (GRANT SELECT,INSERT,UPDATE,DELETE ON items)
//   SQL_TOKEN     scopes rows,query,sql as user `app`
//   LIMITED_TOKEN scope rows, --tables items, as user `app`
// Expects table `items (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(40) NOT NULL, qty INT)`
// and `secret (x INT)` (app has no grant on it), saved query `by_name(name)`.
const [base, rowsTok, sqlTok, limTok] = process.argv.slice(2);
let failures = 0, checks = 0;
function check(cond, what, extra) {
  checks++;
  if (!cond) { failures++; console.log("FAIL", what, extra === undefined ? "" : JSON.stringify(extra)); }
}
async function call(method, path, tok, body) {
  const h = {};
  if (tok) h.authorization = `Bearer ${tok}`;
  if (body !== undefined) h["content-type"] = "application/json";
  const r = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  let j = null;
  try { j = await r.json(); } catch {}
  return { status: r.status, j };
}

// health + auth
let r = await call("GET", "/v1/health");
check(r.status === 200 && r.j.ok, "health", r);
r = await call("GET", "/v1/tables");
check(r.status === 401, "no token -> 401", r);
r = await call("GET", "/v1/tables", "nvdb_000000000000_" + "0".repeat(64));
check(r.status === 401, "bad token -> 401", r);

// rows CRUD
r = await call("POST", "/v1/tables/items/rows", rowsTok, { rows: [{ name: "apple", qty: 3 }, { name: "pear", qty: 0 }, { name: "plum", qty: "7" }] });
check(r.status === 200 && r.j.affected === 3 && r.j.last_insert_id === 1, "insert 3", r);
r = await call("GET", "/v1/tables/items/rows?order=-qty", rowsTok);
check(r.status === 200 && r.j.rows.length === 3 && r.j.rows[0].name === "plum" && r.j.rows[0].qty === 7, "select ordered", r);
r = await call("GET", "/v1/tables/items/rows?where.qty.gt=1&cols=name&order=name", rowsTok);
check(JSON.stringify(r.j.rows) === JSON.stringify([{ name: "apple" }, { name: "plum" }]), "filter gt + cols", r);
r = await call("GET", "/v1/tables/items/rows?where.name=pear&format=array", rowsTok);
check(r.j.rows.length === 1 && r.j.rows[0][1] === "pear", "eq filter, array format", r);
r = await call("GET", "/v1/tables/items/rows?limit=2&order=id", rowsTok);
check(r.j.rows.length === 2 && r.j.truncated === true, "limit + truncated", r);
r = await call("PATCH", "/v1/tables/items/rows?where.name=pear", rowsTok, { qty: 10 });
check(r.status === 200 && r.j.affected === 1, "patch", r);
r = await call("PATCH", "/v1/tables/items/rows", rowsTok, { qty: 0 });
check(r.status === 400, "patch without filter refused", r);
r = await call("DELETE", "/v1/tables/items/rows", rowsTok);
check(r.status === 400, "delete without filter refused", r);
r = await call("POST", "/v1/tables/items/rows", rowsTok, { id: 1, name: "dup" });
check(r.status === 409 && r.j.error.code === 1062, "duplicate -> 409/1062", r);
r = await call("POST", "/v1/tables/items/rows", rowsTok, { qty: 1 });
check(r.status === 400 && r.j.error.code === 1364, "NOT NULL without default -> 1364", r);

// injection attempts stay data / identifiers
r = await call("GET", "/v1/tables/items/rows?where.name=" + encodeURIComponent("x' OR '1'='1"), rowsTok);
check(r.status === 200 && r.j.rows.length === 0, "value injection is just a value", r);
r = await call("GET", "/v1/tables/" + encodeURIComponent("items` UNION SELECT * FROM secret --") + "/rows", rowsTok);
check((r.status === 404 || r.status === 403) && r.j.error.message.includes("UNION SELECT * FROM secret --"), "identifier injection = one (unknown) table name", r);
r = await call("GET", "/v1/tables/items/rows?order=" + encodeURIComponent("id; DROP TABLE items"), rowsTok);
check(r.status === 404 || r.status === 400, "order injection rejected", r);

// GRANTs apply
r = await call("GET", "/v1/tables/secret/rows", rowsTok);
check(r.status === 403 && r.j.error.code === 1142, "no grant -> 403/1142", r);
r = await call("GET", "/v1/tables", rowsTok);
check(r.status === 200 && r.j.tables.includes("items") && !r.j.tables.includes("secret"), "table list filtered by grants", r);

// scopes
r = await call("POST", "/v1/sql", rowsTok, { sql: "SELECT 1" });
check(r.status === 403, "sql scope required", r);
r = await call("POST", "/v1/sql", sqlTok, { sql: "SELECT name FROM items WHERE qty >= ? ORDER BY name", params: [5] });
check(r.status === 200 && r.j.rows.length === 2, "sql with params", r);
r = await call("POST", "/v1/sql", sqlTok, { sql: "SELECT 1; SELECT 2" });
check(r.status === 400, "one statement only", r);
r = await call("POST", "/v1/sql", sqlTok, { sql: "DROP TABLE items" });
check(r.status === 403, "sql scope still bound by grants", r);
r = await call("POST", "/v1/query/by_name", rowsTok, { params: { name: "apple" } });
check(r.status === 200 && r.j.rows.length === 1 && r.j.rows[0].qty === 3, "saved query by name", r);
r = await call("POST", "/v1/query/by_name", rowsTok, { params: ["plum"] });
check(r.status === 200 && r.j.rows[0].qty === 7, "saved query positional", r);
r = await call("POST", "/v1/query/nope", rowsTok, {});
check(r.status === 404, "unknown saved query", r);
r = await call("POST", "/v1/query/by_name", limTok, { params: ["x"] });
check(r.status === 403, "query scope required", r);
r = await call("GET", "/v1/tables/items/rows", limTok);
check(r.status === 200, "limited token on allowed table", r);

// WebSocket: queries, transaction across messages, live changes
const wsUrl = base.replace(/^http/, "ws") + "/v1/ws";
const ws = new WebSocket(wsUrl, { headers: { authorization: `Bearer ${sqlTok}` } });
const inbox = [];
const waiters = [];
ws.onmessage = (m) => { const j = JSON.parse(m.data); inbox.push(j); waiters.splice(0).forEach((w) => w()); };
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; setTimeout(() => rej(new Error("ws open timeout")), 5000); });
async function next(pred, ms = 5000) {
  const t0 = Date.now();
  for (;;) {
    const i = inbox.findIndex(pred);
    if (i >= 0) return inbox.splice(i, 1)[0];
    if (Date.now() - t0 > ms) return null;
    await new Promise((res) => { waiters.push(res); setTimeout(res, 100); });
  }
}
let id = 0;
async function req(o) { const my = ++id; ws.send(JSON.stringify({ id: my, ...o })); return next((m) => m.id === my); }
let m = await req({ op: "ping" });
check(m && m.ok && m.result === "pong", "ws ping", m);
m = await req({ op: "subscribe", table: "items" });
check(m && m.ok && m.result.columns.join() === "id,name,qty", "ws subscribe", m);
m = await req({ op: "subscribe", table: "secret" });
check(m && !m.ok && m.error.code === 1142, "ws subscribe needs SELECT grant", m);
await call("POST", "/v1/tables/items/rows", rowsTok, { name: "kiwi", qty: 4 });
let ev = await next((x) => x.event === "change" && x.op === "put");
check(ev && ev.table === "items" && ev.row.name === "kiwi" && ev.row.qty === 4, "ws change event on insert", ev);
await call("DELETE", "/v1/tables/items/rows?where.name=kiwi", rowsTok);
ev = await next((x) => x.event === "change" && x.op === "delete");
check(ev && typeof ev.key === "string", "ws delete event", ev);
m = await req({ op: "sql", sql: "BEGIN" });
check(m && m.ok, "ws BEGIN", m);
m = await req({ op: "sql", sql: "UPDATE items SET qty = ? WHERE name = ?", params: [99, "apple"] });
check(m && m.ok && m.result.affected === 1, "ws update in txn", m);
r = await call("GET", "/v1/tables/items/rows?where.name=apple", rowsTok);
check(r.j.rows[0].qty === 3, "uncommitted change invisible to others", r);
check((await next((x) => x.event === "change", 300)) === null, "no event before COMMIT");
m = await req({ op: "sql", sql: "COMMIT" });
check(m && m.ok, "ws COMMIT", m);
ev = await next((x) => x.event === "change" && x.op === "put");
check(ev && ev.row.qty === 99, "event after COMMIT", ev);
r = await call("GET", "/v1/tables/items/rows?where.name=apple", rowsTok);
check(r.j.rows[0].qty === 99, "committed change visible", r);
m = await req({ op: "select", table: "items", where: { name: "plum" } });
check(m && m.ok && m.result.rows[0].qty === 7, "ws select", m);
m = await req({ op: "query", name: "by_name", params: { name: "pear" } });
check(m && m.ok && m.result.rows[0].qty === 10, "ws saved query", m);
m = await req({ op: "frob" });
check(m && !m.ok, "ws unknown op", m);
ws.close();

console.log(failures === 0 ? `ALL ${checks} REST CHECKS PASSED` : `${failures} of ${checks} REST CHECKS FAILED`);
process.exit(failures === 0 ? 0 : 1);
