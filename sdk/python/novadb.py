"""NovaDB Python SDK (REST). Standard library only, Python 3.8+.

    from novadb import NovaDB
    db = NovaDB("https://db.example.com", token)
    db.table("items").insert({"name": "apple", "qty": 3})
    rows = db.table("items").select(where={"qty.gt": 1}, order="-qty", limit=50)["rows"]
    db.table("items").update({"qty": 0}, where={"name": "apple"})
    db.query("by_name", {"name": "apple"})        # saved query (query scope)
    db.sql("SELECT COUNT(*) AS n FROM items WHERE qty > ?", [1])   # sql scope

Live change feeds and multi-statement transactions use the WebSocket API (see docs/rest.md);
the JavaScript SDK implements it.
"""
import json
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["NovaDB", "NovaDBError"]


class NovaDBError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status  # HTTP status
        self.code = code      # MySQL error number (1062 duplicate, 1142 denied, ...) or 0


class NovaDB:
    def __init__(self, base_url, token, timeout=30):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read()).get("error", {})
            except Exception:
                err = {}
            raise NovaDBError(e.code, err.get("code", 0), err.get("message", "HTTP %d" % e.code)) from None

    def health(self):
        return self._call("GET", "/v1/health")

    def tables(self):
        return self._call("GET", "/v1/tables")["tables"]

    def describe(self, table):
        return self._call("GET", "/v1/tables/" + urllib.parse.quote(table, safe=""))

    def table(self, name):
        return Table(self, name)

    def query(self, name, params=None, limit=None):
        q = "?limit=%d" % limit if limit else ""
        return self._call("POST", "/v1/query/%s%s" % (urllib.parse.quote(name, safe=""), q), {"params": params or {}})

    def sql(self, sql, params=None, limit=None):
        q = "?limit=%d" % limit if limit else ""
        return self._call("POST", "/v1/sql" + q, {"sql": sql, "params": list(params or [])})


def _qs(where=None, columns=None, order=None, limit=None, offset=None):
    p = []
    for k, v in (where or {}).items():
        if isinstance(v, bool):
            v = "true" if v else "false"
        p.append(("where." + k, str(v)))
    if columns:
        p.append(("cols", ",".join(columns)))
    if order:
        p.append(("order", order if isinstance(order, str) else ",".join(order)))
    if limit:
        p.append(("limit", str(limit)))
    if offset:
        p.append(("offset", str(offset)))
    return "?" + urllib.parse.urlencode(p) if p else ""


class Table:
    def __init__(self, db, name):
        self.db = db
        self.path = "/v1/tables/%s/rows" % urllib.parse.quote(name, safe="")

    def select(self, where=None, columns=None, order=None, limit=None, offset=None):
        """where: {"col": v, "col.gt": v, "col.like": "a%", "col.null": True}"""
        return self.db._call("GET", self.path + _qs(where, columns, order, limit, offset))

    def get(self, where):
        rows = self.select(where=where, limit=1)["rows"]
        return rows[0] if rows else None

    def insert(self, row_or_rows):
        body = {"rows": row_or_rows} if isinstance(row_or_rows, list) else row_or_rows
        return self.db._call("POST", self.path, body)

    def update(self, values, where):
        return self.db._call("PATCH", self.path + _qs(where), values)

    def delete(self, where):
        return self.db._call("DELETE", self.path + _qs(where))
