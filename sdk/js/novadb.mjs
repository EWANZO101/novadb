// NovaDB JavaScript SDK (Node 22+, Deno, Bun, browsers). No dependencies.
//
//   import { NovaDB } from "./novadb.mjs";
//   const db = new NovaDB("https://db.example.com", process.env.NOVADB_TOKEN);
//   await db.table("items").insert({ name: "apple", qty: 3 });
//   const { rows } = await db.table("items").select({ where: { "qty.gt": 1 }, order: "-qty", limit: 50 });
//   await db.table("items").update({ qty: 0 }, { where: { name: "apple" } });
//   await db.query("by_name", { name: "apple" });           // saved query (query scope)
//   await db.sql("SELECT COUNT(*) AS n FROM items WHERE qty > ?", [1]); // sql scope
//   const live = await db.live();                           // WebSocket
//   await live.subscribe("items", (ev) => console.log(ev.op, ev.row));
//   await live.sql("BEGIN"); …; await live.sql("COMMIT");   // transactions span messages

export class NovaDBError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status; // HTTP status (0 on WebSocket)
    this.code = code;     // MySQL error number (1062 duplicate, 1142 denied, …) or 0
  }
}

export class NovaDB {
  constructor(baseUrl, token, { fetch: f = globalThis.fetch } = {}) {
    this.base = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this._fetch = f;
  }

  async _call(method, path, body) {
    const headers = { authorization: `Bearer ${this.token}` };
    if (body !== undefined) headers["content-type"] = "application/json";
    const r = await this._fetch(this.base + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    });
    let j = null;
    try { j = await r.json(); } catch { /* empty body */ }
    if (!r.ok) {
      const e = (j && j.error) || {};
      throw new NovaDBError(r.status, e.code || 0, e.message || `HTTP ${r.status}`);
    }
    return j;
  }

  health() { return this._call("GET", "/v1/health"); }
  async tables() { return (await this._call("GET", "/v1/tables")).tables; }
  describe(table) { return this._call("GET", `/v1/tables/${encodeURIComponent(table)}`); }
  table(name) { return new Table(this, name); }
  query(name, params = {}, { limit } = {}) {
    return this._call("POST", `/v1/query/${encodeURIComponent(name)}${limit ? `?limit=${limit}` : ""}`, { params });
  }
  sql(sql, params = [], { limit } = {}) {
    return this._call("POST", `/v1/sql${limit ? `?limit=${limit}` : ""}`, { sql, params });
  }

  /** Open a WebSocket session (queries, transactions, live change events). */
  live({ WebSocket: WS = globalThis.WebSocket } = {}) {
    return Live.open(this, WS);
  }
}

function qs(opts = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(opts.where || {})) p.set(`where.${k}`, String(v));
  if (opts.columns) p.set("cols", opts.columns.join(","));
  if (opts.order) p.set("order", Array.isArray(opts.order) ? opts.order.join(",") : opts.order);
  if (opts.limit) p.set("limit", String(opts.limit));
  if (opts.offset) p.set("offset", String(opts.offset));
  const s = p.toString();
  return s ? `?${s}` : "";
}

class Table {
  constructor(db, name) { this.db = db; this.name = name; this.path = `/v1/tables/${encodeURIComponent(name)}/rows`; }
  /** where: { col: v, "col.gt": v, "col.like": "a%", "col.null": true } */
  select(opts = {}) { return this.db._call("GET", this.path + qs(opts)); }
  async get(where) { return (await this.select({ where, limit: 1 })).rows[0] ?? null; }
  insert(rowOrRows) {
    return this.db._call("POST", this.path, Array.isArray(rowOrRows) ? { rows: rowOrRows } : rowOrRows);
  }
  update(set, { where }) { return this.db._call("PATCH", this.path + qs({ where }), set); }
  delete({ where }) { return this.db._call("DELETE", this.path + qs({ where })); }
}

class Live {
  static open(db, WS) {
    const url = db.base.replace(/^http/, "ws") + "/v1/ws";
    // Browsers cannot set headers on WebSocket: put a reverse proxy in front that adds the
    // Authorization header, or use this SDK server-side (Node/Deno/Bun accept headers).
    const ws = new WS(url, { headers: { authorization: `Bearer ${db.token}` } });
    const live = new Live(ws);
    return new Promise((res, rej) => {
      ws.onopen = () => res(live);
      ws.onerror = (e) => rej(new NovaDBError(0, 0, `WebSocket error: ${e.message || e.type}`));
    });
  }
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    this.onEvent = null; // other events: lagged, unsubscribed
    ws.onmessage = (m) => {
      const j = JSON.parse(m.data);
      if (j.id !== undefined && this.pending.has(j.id)) {
        const { res, rej } = this.pending.get(j.id);
        this.pending.delete(j.id);
        if (j.ok) res(j.result); else rej(new NovaDBError(0, j.error.code, j.error.message));
      } else if (j.event === "change") {
        const h = this.handlers.get(String(j.table).toLowerCase());
        if (h) h(j);
      } else if (this.onEvent) {
        this.onEvent(j);
      }
    };
    ws.onclose = () => {
      for (const { rej } of this.pending.values()) rej(new NovaDBError(0, 0, "connection closed"));
      this.pending.clear();
    };
  }
  _req(o) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      this.pending.set(id, { res, rej });
      this.ws.send(JSON.stringify({ id, ...o }));
    });
  }
  ping() { return this._req({ op: "ping" }); }
  sql(sql, params = []) { return this._req({ op: "sql", sql, params }); }
  query(name, params = {}) { return this._req({ op: "query", name, params }); }
  select(table, { where, limit } = {}) { return this._req({ op: "select", table, where, limit }); }
  /** handler(event): { table, op: "put" | "delete", key, row? } after each COMMIT */
  async subscribe(table, handler) {
    const r = await this._req({ op: "subscribe", table });
    this.handlers.set(table.toLowerCase(), handler);
    return r;
  }
  async unsubscribe(table) {
    this.handlers.delete(table.toLowerCase());
    return this._req({ op: "unsubscribe", table });
  }
  close() { this.ws.close(); }
}
