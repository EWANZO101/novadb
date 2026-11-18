//! REST + WebSocket API (Stage 10), `--rest 127.0.0.1:3380`.
//!
//! Plain HTTP on loopback only — put nginx (TLS) in front for remote clients. Every request
//! carries `Authorization: Bearer nvdb_…` (see `tokens.rs`); the token acts as an SQL user, so
//! the engine's GRANTs decide what it may touch. Scopes:
//! * `rows`  — table CRUD built from **parameterised** statements (identifiers are quoted,
//!   values are bound, never spliced into SQL); optional per-token table allow-list.
//! * `query` — run the admin's saved statements by name with bound parameters.
//! * `sql`   — arbitrary single statements (explicit opt-in; still limited by the user's GRANTs).
//!
//! Limits: 1 MiB bodies, 10 s per SELECT, ≤ 10,000 rows per response (default 1,000),
//! per-token requests/minute, per-IP failed-auth limit, 64 WebSocket connections per token.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use novadb_sql::ast::Stmt;
use novadb_sql::binlog::LogOp;
use novadb_sql::{QueryResult, Session, SqlError, Value};
use serde_json::{Map, Value as J, json};
use tokio::sync::broadcast;

use crate::Server;
use crate::tokens::{Store, Token};

const MAX_BODY: usize = 1 << 20;
const DEFAULT_ROWS: usize = 1000;
const MAX_ROWS: usize = 10_000;
const SELECT_MS: u64 = 10_000;
const MAX_WS_PER_TOKEN: usize = 64;
const MAX_SUBS: usize = 32;
/// REST/WebSocket sessions get connection ids from here (MySQL ones count up from 1).
static NEXT_ID: AtomicU32 = AtomicU32::new(1 << 30);

pub type Changes = Arc<Vec<LogOp>>;

pub struct Api {
    server: Arc<Server>,
    store: Store,
    limiter: crate::auth::RateLimiter,
    feed: broadcast::Sender<Changes>,
    ws_per_token: Mutex<HashMap<String, usize>>,
}

/// Error with an HTTP status and the MySQL error code/message.
pub struct ApiErr(StatusCode, u16, String);

impl From<SqlError> for ApiErr {
    fn from(e: SqlError) -> Self {
        let st = match e.code {
            1142 | 1143 | 1227 | 1044 | 1045 => StatusCode::FORBIDDEN,
            1146 | 1054 | 1091 => StatusCode::NOT_FOUND,
            1062 | 1213 | 1205 => StatusCode::CONFLICT,
            1317 | 3024 => StatusCode::REQUEST_TIMEOUT,
            1040 | 1038 | 1041 => StatusCode::SERVICE_UNAVAILABLE,
            _ if e.code >= 1000 => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiErr(st, e.code, e.msg.clone())
    }
}

fn bad(msg: impl Into<String>) -> ApiErr {
    ApiErr(StatusCode::BAD_REQUEST, 0, msg.into())
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error": {"code": self.1, "message": self.2}})),
        )
            .into_response()
    }
}

// ----- values --------------------------------------------------------------------------------

pub fn to_json(v: &Value) -> J {
    match v {
        Value::Null => J::Null,
        Value::Int(i) => J::from(*i),
        Value::Bytes(b) => J::String(base64::engine::general_purpose::STANDARD.encode(b)),
        other => J::String(other.to_string()),
    }
}

fn from_json(v: &J) -> Result<Value, ApiErr> {
    Ok(match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Int(i64::from(*b)),
        J::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Str(n.to_string()),
        },
        J::String(s) => Value::Str(s.clone()),
        _ => return Err(bad("values must be strings, numbers, booleans or null")),
    })
}

fn result_json(r: &QueryResult, arrays: bool, cap: usize) -> J {
    let cols: Vec<String> = r.columns.iter().map(|c| c.name.clone()).collect();
    let truncated = r.rows.len() > cap;
    let rows: Vec<J> = r
        .rows
        .iter()
        .take(cap)
        .map(|row| {
            if arrays {
                J::Array(row.iter().map(to_json).collect())
            } else {
                let mut m = Map::new();
                for (c, v) in cols.iter().zip(row) {
                    m.insert(c.clone(), to_json(v));
                }
                J::Object(m)
            }
        })
        .collect();
    let mut o = json!({"affected": r.affected});
    if !cols.is_empty() {
        o["columns"] = json!(cols);
        o["rows"] = J::Array(rows);
        o["truncated"] = J::Bool(truncated);
    }
    if r.last_insert_id > 0 {
        o["last_insert_id"] = J::from(r.last_insert_id);
    }
    if let Some(i) = &r.info {
        o["info"] = J::String(i.clone());
    }
    o
}

fn ident(n: &str) -> Result<String, ApiErr> {
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        return Err(bad(format!("bad identifier {n:?}")));
    }
    Ok(novadb_sql::exec::sql_ident(n))
}

// ----- auth + execution ----------------------------------------------------------------------

fn client_ip(peer: SocketAddr, h: &HeaderMap) -> String {
    // Trust X-Real-IP only from a local reverse proxy.
    if peer.ip().is_loopback()
        && let Some(v) = h.get("x-real-ip").and_then(|v| v.to_str().ok())
    {
        return v.to_string();
    }
    peer.ip().to_string()
}

impl Api {
    fn auth(&self, h: &HeaderMap, ip: &str) -> Result<Token, ApiErr> {
        let unauth = || {
            ApiErr(
                StatusCode::UNAUTHORIZED,
                1045,
                "missing or invalid API token".into(),
            )
        };
        if !self
            .limiter
            .hit(&format!("rest-fail:{ip}"), 30, Duration::from_secs(60))
        {
            // over the failure budget: still verify, but refuse even valid tokens for a while
            return Err(ApiErr(
                StatusCode::TOO_MANY_REQUESTS,
                0,
                "too many failed attempts".into(),
            ));
        }
        let tok = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|b| self.store.verify(b.trim()))
            .ok_or_else(unauth)?;
        // success does not count as a failure
        self.limiter.forgive(&format!("rest-fail:{ip}"));
        if !self.limiter.hit(
            &format!("rest-tok:{}", tok.id),
            tok.per_minute(),
            Duration::from_secs(60),
        ) {
            return Err(ApiErr(
                StatusCode::TOO_MANY_REQUESTS,
                0,
                "rate limit exceeded".into(),
            ));
        }
        Ok(tok)
    }

    fn need(tok: &Token, scope: &str) -> Result<(), ApiErr> {
        if tok.has(scope) {
            Ok(())
        } else {
            Err(ApiErr(
                StatusCode::FORBIDDEN,
                0,
                format!("this token lacks the '{scope}' scope"),
            ))
        }
    }

    fn need_table(tok: &Token, t: &str) -> Result<(), ApiErr> {
        if tok.table_ok(t) {
            Ok(())
        } else {
            Err(ApiErr(
                StatusCode::FORBIDDEN,
                1142,
                format!("this token may not access table '{t}'"),
            ))
        }
    }

    /// Run one parameterised statement as the token's user on connection `conn`.
    async fn exec(
        &self,
        tok: &Token,
        conn: u32,
        sql: &str,
        params: &[Value],
    ) -> Result<QueryResult, ApiErr> {
        let (mut stmts, n) = novadb_sql::parse_prepared(sql)?;
        if stmts.len() != 1 {
            return Err(bad("exactly one statement per request"));
        }
        if n != params.len() {
            return Err(bad(format!(
                "expected {n} parameters, got {}",
                params.len()
            )));
        }
        let mut st = stmts.remove(0);
        novadb_sql::bind_params(&mut st, params)?;
        self.exec_stmt(tok, conn, st).await
    }

    async fn exec_stmt(&self, tok: &Token, conn: u32, st: Stmt) -> Result<QueryResult, ApiErr> {
        let mut sess = Session {
            user: tok.user.clone(),
            conn_id: conn,
            max_execution_ms: SELECT_MS,
            ..Default::default()
        };
        let (r, _) = self.server.run(st, &mut sess).await;
        Ok(r?)
    }

    /// One-shot request: fresh connection id, rolled back/cleaned afterwards.
    async fn once(&self, tok: &Token, sql: &str, params: &[Value]) -> Result<QueryResult, ApiErr> {
        let conn = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let r = self.exec(tok, conn, sql, params).await;
        self.server.end_session(conn).await;
        r
    }
}

type St = State<Arc<Api>>;
type Hq = Query<HashMap<String, String>>;

fn cap(q: &HashMap<String, String>) -> Result<usize, ApiErr> {
    match q.get("limit") {
        None => Ok(DEFAULT_ROWS),
        Some(l) => {
            let n: usize = l.parse().map_err(|_| bad("limit must be a number"))?;
            if n == 0 || n > MAX_ROWS {
                return Err(bad(format!("limit must be 1..={MAX_ROWS}")));
            }
            Ok(n)
        }
    }
}

/// `where.col=v`, `where.col.gt=v` (gt gte lt lte ne like), `where.col.null=true|false`.
fn filters(q: &HashMap<String, String>) -> Result<(String, Vec<Value>), ApiErr> {
    let mut parts = Vec::new();
    let mut vals = Vec::new();
    let mut keys: Vec<&String> = q.keys().filter(|k| k.starts_with("where.")).collect();
    keys.sort();
    for k in keys {
        let v = &q[k];
        let spec = &k["where.".len()..];
        let (col, op) = match spec.rsplit_once('.') {
            Some((c, o)) if ["gt", "gte", "lt", "lte", "ne", "like", "null"].contains(&o) => (c, o),
            _ => (spec, "eq"),
        };
        let c = ident(col)?;
        match op {
            "null" => parts.push(format!(
                "{c} IS {}NULL",
                if v == "false" { "NOT " } else { "" }
            )),
            _ => {
                let sym = match op {
                    "eq" => "=",
                    "gt" => ">",
                    "gte" => ">=",
                    "lt" => "<",
                    "lte" => "<=",
                    "ne" => "<>",
                    _ => "LIKE",
                };
                parts.push(format!("{c} {sym} ?"));
                vals.push(Value::Str(v.clone()));
            }
        }
    }
    Ok((
        if parts.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", parts.join(" AND "))
        },
        vals,
    ))
}

async fn health() -> Json<J> {
    Json(json!({"ok": true, "service": "novadb", "version": env!("CARGO_PKG_VERSION")}))
}

async fn tables(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    let r = a.once(&tok, "SHOW TABLES", &[]).await?;
    let names: Vec<J> = r
        .rows
        .iter()
        .filter_map(|row| row.first().map(|v| v.to_string()))
        .filter(|n| tok.table_ok(n))
        .map(J::String)
        .collect();
    Ok(Json(json!({"tables": names})))
}

async fn describe(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(t): Path<String>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    Api::need_table(&tok, &t)?;
    let r = a
        .once(&tok, &format!("DESCRIBE {}", ident(&t)?), &[])
        .await?;
    Ok(Json(result_json(&r, false, MAX_ROWS)))
}

async fn rows_get(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(t): Path<String>,
    Query(q): Hq,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    Api::need_table(&tok, &t)?;
    let limit = cap(&q)?;
    let cols = match q.get("cols") {
        Some(c) => c
            .split(',')
            .map(ident)
            .collect::<Result<Vec<_>, _>>()?
            .join(", "),
        None => "*".into(),
    };
    let (w, vals) = filters(&q)?;
    let mut sql = format!("SELECT {cols} FROM {}{w}", ident(&t)?);
    if let Some(o) = q.get("order") {
        let mut ords = Vec::new();
        for part in o.split(',') {
            let (c, desc) = match part.strip_prefix('-') {
                Some(c) => (c, true),
                None => (part, false),
            };
            ords.push(format!("{}{}", ident(c)?, if desc { " DESC" } else { "" }));
        }
        sql.push_str(&format!(" ORDER BY {}", ords.join(", ")));
    }
    let offset: usize = match q.get("offset") {
        Some(o) => o.parse().map_err(|_| bad("offset must be a number"))?,
        None => 0,
    };
    // one extra row tells us whether there is more
    sql.push_str(&format!(" LIMIT {} OFFSET {offset}", limit + 1));
    let r = a.once(&tok, &sql, &vals).await?;
    Ok(Json(result_json(
        &r,
        q.get("format").is_some_and(|f| f == "array"),
        limit,
    )))
}

async fn rows_post(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(t): Path<String>,
    Json(body): Json<J>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    Api::need_table(&tok, &t)?;
    let rows: Vec<&Map<String, J>> = match &body {
        J::Object(o) if o.contains_key("rows") => o["rows"]
            .as_array()
            .ok_or_else(|| bad("rows must be an array"))?
            .iter()
            .map(|r| {
                r.as_object()
                    .ok_or_else(|| bad("each row must be an object"))
            })
            .collect::<Result<_, _>>()?,
        J::Object(o) => vec![o],
        _ => return Err(bad("body: a row object or {\"rows\": [...]}")),
    };
    if rows.is_empty() || rows.len() > MAX_ROWS {
        return Err(bad(format!("1..={MAX_ROWS} rows per request")));
    }
    let cols: Vec<&String> = rows[0].keys().collect();
    if cols.is_empty() {
        return Err(bad("a row needs at least one column"));
    }
    let mut vals = Vec::new();
    for r in &rows {
        if r.len() != cols.len() || !cols.iter().all(|c| r.contains_key(*c)) {
            return Err(bad("all rows must have the same columns"));
        }
        for c in &cols {
            vals.push(from_json(&r[*c])?);
        }
    }
    let one = format!("({})", vec!["?"; cols.len()].join(", "));
    let sql = format!(
        "INSERT INTO {} ({}) VALUES {}",
        ident(&t)?,
        cols.iter()
            .map(|c| ident(c))
            .collect::<Result<Vec<_>, _>>()?
            .join(", "),
        vec![one; rows.len()].join(", ")
    );
    let r = a.once(&tok, &sql, &vals).await?;
    Ok(Json(result_json(&r, false, 0)))
}

async fn rows_patch(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(t): Path<String>,
    Query(q): Hq,
    Json(body): Json<J>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    Api::need_table(&tok, &t)?;
    let set = body
        .as_object()
        .filter(|o| !o.is_empty())
        .ok_or_else(|| bad("body: object of column: new value"))?;
    let (w, wv) = filters(&q)?;
    if w.is_empty() {
        return Err(bad(
            "PATCH needs at least one where.* filter (no accidental full-table updates)",
        ));
    }
    let mut vals = Vec::new();
    let mut sets = Vec::new();
    for (c, v) in set {
        sets.push(format!("{} = ?", ident(c)?));
        vals.push(from_json(v)?);
    }
    vals.extend(wv);
    let sql = format!("UPDATE {} SET {}{w}", ident(&t)?, sets.join(", "));
    let r = a.once(&tok, &sql, &vals).await?;
    Ok(Json(result_json(&r, false, 0)))
}

async fn rows_delete(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(t): Path<String>,
    Query(q): Hq,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "rows")?;
    Api::need_table(&tok, &t)?;
    let (w, vals) = filters(&q)?;
    if w.is_empty() {
        return Err(bad("DELETE needs at least one where.* filter"));
    }
    let r = a
        .once(&tok, &format!("DELETE FROM {}{w}", ident(&t)?), &vals)
        .await?;
    Ok(Json(result_json(&r, false, 0)))
}

/// Parameters for a saved query: array (in order) or object (by name).
fn saved_params(names: &[String], p: Option<&J>) -> Result<Vec<Value>, ApiErr> {
    match p {
        None | Some(J::Null) => Ok(Vec::new()),
        Some(J::Array(a)) => a.iter().map(from_json).collect(),
        Some(J::Object(o)) => names
            .iter()
            .map(|n| {
                o.get(n)
                    .ok_or_else(|| bad(format!("missing parameter '{n}'")))
                    .and_then(from_json)
            })
            .collect(),
        _ => Err(bad("params: array or object")),
    }
}

async fn query(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(name): Path<String>,
    Query(q): Hq,
    body: Option<Json<J>>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "query")?;
    let sq = a
        .store
        .query(&name)
        .ok_or_else(|| ApiErr(StatusCode::NOT_FOUND, 0, format!("no saved query '{name}'")))?;
    let body = body.map(|b| b.0).unwrap_or(J::Null);
    let vals = saved_params(&sq.params, body.get("params"))?;
    let limit = cap(&q)?;
    let r = a.once(&tok, &sq.sql, &vals).await?;
    Ok(Json(result_json(
        &r,
        q.get("format").is_some_and(|f| f == "array"),
        limit,
    )))
}

async fn sql(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Query(q): Hq,
    Json(body): Json<J>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    Api::need(&tok, "sql")?;
    let text = body
        .get("sql")
        .and_then(J::as_str)
        .ok_or_else(|| bad("body: {\"sql\": \"…\", \"params\": [...]}"))?;
    let vals = match body.get("params") {
        None | Some(J::Null) => Vec::new(),
        Some(J::Array(v)) => v.iter().map(from_json).collect::<Result<_, _>>()?,
        _ => return Err(bad("params must be an array")),
    };
    let limit = cap(&q)?;
    let r = a.once(&tok, text, &vals).await?;
    Ok(Json(result_json(
        &r,
        q.get("format").is_some_and(|f| f == "array"),
        limit,
    )))
}

// ----- cluster -------------------------------------------------------------------------------

async fn cluster_status(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
) -> Result<Json<J>, ApiErr> {
    a.auth(&h, &client_ip(peer, &h))?;
    match &a.server.cluster {
        Some(c) => Ok(Json(c.status_json())),
        None => Err(ApiErr(
            StatusCode::NOT_FOUND,
            0,
            "not running in cluster mode".into(),
        )),
    }
}

async fn cluster_remove(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Path(id): Path<u64>,
) -> Result<Json<J>, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    if !tok.user.eq_ignore_ascii_case("root") {
        return Err(ApiErr(
            StatusCode::FORBIDDEN,
            1227,
            "removing cluster nodes needs a token for the root user".into(),
        ));
    }
    let c = a.server.cluster.clone().ok_or_else(|| {
        ApiErr(
            StatusCode::NOT_FOUND,
            0,
            "not running in cluster mode".into(),
        )
    })?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    c.events
        .send(crate::cluster::Event::RemoveNode(id, tx))
        .map_err(|_| bad("cluster driver stopped"))?;
    match tokio::time::timeout(Duration::from_secs(15), rx).await {
        Ok(Ok(Ok(()))) => Ok(Json(json!({"removed": id}))),
        Ok(Ok(Err(e))) => Err(ApiErr(StatusCode::CONFLICT, 0, e)),
        _ => Err(ApiErr(StatusCode::SERVICE_UNAVAILABLE, 0, "timeout".into())),
    }
}

// ----- WebSocket -----------------------------------------------------------------------------

async fn ws(
    State(a): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    up: WebSocketUpgrade,
) -> Result<Response, ApiErr> {
    let tok = a.auth(&h, &client_ip(peer, &h))?;
    {
        let mut m = a.ws_per_token.lock().map_err(|_| bad("lock"))?;
        let n = m.entry(tok.id.clone()).or_insert(0);
        if *n >= MAX_WS_PER_TOKEN {
            return Err(ApiErr(
                StatusCode::TOO_MANY_REQUESTS,
                1040,
                "too many WebSocket connections for this token".into(),
            ));
        }
        *n += 1;
    }
    Ok(up
        .max_message_size(MAX_BODY)
        .on_upgrade(move |sock| async move {
            let id = tok.id.clone();
            ws_session(a.clone(), tok, sock).await;
            if let Ok(mut m) = a.ws_per_token.lock()
                && let Some(n) = m.get_mut(&id)
            {
                *n = n.saturating_sub(1);
            }
        }))
}

struct Sub {
    cols: Vec<String>,
}

async fn ws_session(a: Arc<Api>, tok: Token, mut sock: WebSocket) {
    let conn = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut feed = a.feed.subscribe();
    let mut subs: HashMap<String, Sub> = HashMap::new();
    loop {
        tokio::select! {
            m = sock.recv() => {
                let Some(Ok(m)) = m else { break };
                let text = match m {
                    Message::Text(t) => t.to_string(),
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Binary(_) => {
                        let _ = sock.send(Message::Text(json!({"ok": false, "error": {"code": 0, "message": "send JSON text frames"}}).to_string().into())).await;
                        continue;
                    }
                };
                let reply = ws_handle(&a, &tok, conn, &text, &mut subs).await;
                if sock.send(Message::Text(reply.to_string().into())).await.is_err() {
                    break;
                }
            }
            ev = feed.recv(), if !subs.is_empty() => {
                let ops = match ev {
                    Ok(ops) => ops,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let _ = sock.send(Message::Text(json!({"event": "lagged", "missed_commits": n}).to_string().into())).await;
                        continue;
                    }
                    Err(_) => break,
                };
                let mut out = Vec::new();
                let mut recheck = false;
                for op in ops.iter() {
                    match op {
                        LogOp::Put { table, key, row } => {
                            if let Some(s) = subs.get(&table.to_lowercase()) {
                                let mut m = Map::new();
                                if s.cols.len() == row.len() {
                                    for (c, v) in s.cols.iter().zip(row) {
                                        m.insert(c.clone(), to_json(v));
                                    }
                                } else {
                                    recheck = true;
                                }
                                out.push(json!({"event": "change", "table": table, "op": "put", "key": crate::hex(key), "row": if m.is_empty() { J::Array(row.iter().map(to_json).collect()) } else { J::Object(m) }}));
                            }
                        }
                        LogOp::Del { table, key } if subs.contains_key(&table.to_lowercase()) => {
                            out.push(json!({"event": "change", "table": table, "op": "delete", "key": crate::hex(key)}));
                        }
                        LogOp::Ddl(_) | LogOp::User { .. } => recheck = true,
                        _ => {}
                    }
                }
                for e in out {
                    if sock.send(Message::Text(e.to_string().into())).await.is_err() {
                        break;
                    }
                }
                if recheck {
                    // schema or privileges changed: refresh column names, drop lost access
                    let names: Vec<String> = subs.keys().cloned().collect();
                    for t in names {
                        match sub_check(&a, &tok, conn, &t).await {
                            Ok(cols) => {
                                if let Some(s) = subs.get_mut(&t) {
                                    s.cols = cols;
                                }
                            }
                            Err(e) => {
                                subs.remove(&t);
                                let _ = sock.send(Message::Text(json!({"event": "unsubscribed", "table": t, "reason": e.2}).to_string().into())).await;
                            }
                        }
                    }
                }
            }
        }
    }
    a.server.end_session(conn).await;
}

/// May the token read `t`? Returns its column names.
async fn sub_check(a: &Api, tok: &Token, conn: u32, t: &str) -> Result<Vec<String>, ApiErr> {
    Api::need_table(tok, t)?;
    let r = a
        .exec(
            tok,
            conn,
            &format!("SELECT * FROM {} LIMIT 0", ident(t)?),
            &[],
        )
        .await?;
    Ok(r.columns.iter().map(|c| c.name.clone()).collect())
}

async fn ws_handle(
    a: &Api,
    tok: &Token,
    conn: u32,
    text: &str,
    subs: &mut HashMap<String, Sub>,
) -> J {
    let msg: J = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            return json!({"ok": false, "error": {"code": 0, "message": format!("bad JSON: {e}")}});
        }
    };
    let id = msg.get("id").cloned().unwrap_or(J::Null);
    if !a.limiter.hit(
        &format!("rest-tok:{}", tok.id),
        tok.per_minute(),
        Duration::from_secs(60),
    ) {
        return json!({"id": id, "ok": false, "error": {"code": 0, "message": "rate limit exceeded"}});
    }
    let r: Result<J, ApiErr> = async {
        let op = msg.get("op").and_then(J::as_str).unwrap_or("");
        match op {
            "ping" => Ok(json!("pong")),
            "query" => {
                Api::need(tok, "query")?;
                let name = msg
                    .get("name")
                    .and_then(J::as_str)
                    .ok_or_else(|| bad("name"))?;
                let sq = a.store.query(name).ok_or_else(|| {
                    ApiErr(StatusCode::NOT_FOUND, 0, format!("no saved query '{name}'"))
                })?;
                let vals = saved_params(&sq.params, msg.get("params"))?;
                let r = a.exec(tok, conn, &sq.sql, &vals).await?;
                Ok(result_json(&r, false, MAX_ROWS))
            }
            "sql" => {
                Api::need(tok, "sql")?;
                let s = msg
                    .get("sql")
                    .and_then(J::as_str)
                    .ok_or_else(|| bad("sql"))?;
                let vals = match msg.get("params") {
                    None | Some(J::Null) => Vec::new(),
                    Some(J::Array(v)) => v.iter().map(from_json).collect::<Result<_, _>>()?,
                    _ => return Err(bad("params must be an array")),
                };
                // transactions span messages on this socket (BEGIN … COMMIT)
                let r = a.exec(tok, conn, s, &vals).await?;
                Ok(result_json(&r, false, MAX_ROWS))
            }
            "select" => {
                Api::need(tok, "rows")?;
                let t = msg
                    .get("table")
                    .and_then(J::as_str)
                    .ok_or_else(|| bad("table"))?;
                Api::need_table(tok, t)?;
                let mut q = HashMap::new();
                if let Some(w) = msg.get("where").and_then(J::as_object) {
                    for (k, v) in w {
                        q.insert(
                            format!("where.{k}"),
                            match v {
                                J::String(s) => s.clone(),
                                other => other.to_string(),
                            },
                        );
                    }
                }
                let (w, vals) = filters(&q)?;
                let limit = msg
                    .get("limit")
                    .and_then(J::as_u64)
                    .map_or(DEFAULT_ROWS, |l| (l as usize).clamp(1, MAX_ROWS));
                let r = a
                    .exec(
                        tok,
                        conn,
                        &format!("SELECT * FROM {}{w} LIMIT {}", ident(t)?, limit + 1),
                        &vals,
                    )
                    .await?;
                Ok(result_json(&r, false, limit))
            }
            "subscribe" => {
                Api::need(tok, "rows")?;
                let t = msg
                    .get("table")
                    .and_then(J::as_str)
                    .ok_or_else(|| bad("table"))?;
                if subs.len() >= MAX_SUBS {
                    return Err(bad(format!(
                        "at most {MAX_SUBS} subscriptions per connection"
                    )));
                }
                let cols = sub_check(a, tok, conn, t).await?;
                subs.insert(t.to_lowercase(), Sub { cols: cols.clone() });
                Ok(json!({"subscribed": t, "columns": cols}))
            }
            "unsubscribe" => {
                let t = msg
                    .get("table")
                    .and_then(J::as_str)
                    .ok_or_else(|| bad("table"))?;
                subs.remove(&t.to_lowercase());
                Ok(json!({"unsubscribed": t}))
            }
            _ => Err(bad("op: ping, query, sql, select, subscribe, unsubscribe")),
        }
    }
    .await;
    match r {
        Ok(v) => json!({"id": id, "ok": true, "result": v}),
        Err(e) => json!({"id": id, "ok": false, "error": {"code": e.1, "message": e.2}}),
    }
}

// ----- server --------------------------------------------------------------------------------

pub fn router(api: Arc<Api>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/tables", get(tables))
        .route("/v1/tables/{t}", get(describe))
        .route(
            "/v1/tables/{t}/rows",
            get(rows_get)
                .post(rows_post)
                .patch(rows_patch)
                .delete(rows_delete),
        )
        .route("/v1/query/{name}", post(query))
        .route("/v1/sql", post(sql))
        .route("/v1/ws", get(ws))
        .route("/v1/cluster", get(cluster_status))
        .route("/v1/cluster/nodes/{id}/remove", post(cluster_remove))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(api)
}

/// Build the API state; `feed` receives every commit's changes from the engine hook.
pub fn api(server: Arc<Server>, feed: broadcast::Sender<Changes>) -> Arc<Api> {
    Arc::new(Api {
        store: Store::new(&server.data_dir),
        server,
        limiter: crate::auth::RateLimiter::new(),
        feed,
        ws_per_token: Mutex::new(HashMap::new()),
    })
}

pub async fn serve(api: Arc<Api>, addr: SocketAddr) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[novadb] REST: bind {addr}: {e}");
            return;
        }
    };
    println!(
        "[novadb] REST/WebSocket API on http://{addr}/v1 (bearer tokens; put TLS in front for remote use)"
    );
    let app = router(api).into_make_service_with_connect_info::<SocketAddr>();
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("[novadb] REST: {e}");
    }
}
