//! One client connection: handshake → TLS → caching_sha2_password full auth (Argon2id) →
//! command loop. Plaintext sessions are refused (`require_secure_transport`).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use novadb_protocol::packets::{self as pk, WireCol};
use novadb_protocol::{HANDSHAKE_TIMEOUT_SECS, MAX_PAYLOAD, MAX_PREAUTH_PACKET, frame};
use novadb_sql::ast::Stmt;
use novadb_sql::{QueryResult, Session, SqlError, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::Server;

/// Max prepared statements per connection (MySQL: max_prepared_stmt_count is global).
const MAX_PREPARED: usize = 1024;
/// Max bytes collected via COM_STMT_SEND_LONG_DATA per statement.
const MAX_LONG_DATA: usize = 16 << 20;
/// Idle connections are closed after this (wait_timeout).
const IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);

async fn read_packet<S: AsyncRead + Unpin>(s: &mut S, max: usize) -> io::Result<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut first_seq = None;
    loop {
        let mut h = [0u8; 4];
        s.read_exact(&mut h).await?;
        let len = usize::from(h[0]) | usize::from(h[1]) << 8 | usize::from(h[2]) << 16;
        first_seq.get_or_insert(h[3]);
        if out.len() + len > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too large",
            ));
        }
        let start = out.len();
        out.resize(start + len, 0);
        s.read_exact(&mut out[start..]).await?;
        if len < MAX_PAYLOAD {
            return Ok((first_seq.unwrap_or(0), out));
        }
    }
}

struct Writer {
    buf: Vec<u8>,
    seq: u8,
}

impl Writer {
    fn new(seq: u8) -> Self {
        Writer {
            buf: Vec::new(),
            seq,
        }
    }
    fn push(&mut self, payload: &[u8]) {
        self.seq = frame(&mut self.buf, payload, self.seq);
    }
    async fn flush<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> io::Result<()> {
        s.write_all(&self.buf).await?;
        s.flush().await?;
        self.buf.clear();
        Ok(())
    }
}

fn sql_err(e: &SqlError) -> Vec<u8> {
    pk::err(e.code, e.state, &e.msg)
}

/// Entry point for an accepted TCP connection.
pub async fn handle(server: Arc<Server>, tcp: TcpStream, peer: SocketAddr, conn_id: u32) {
    let ip = peer.ip();
    let r = tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        handshake(&server, tcp, ip, conn_id),
    )
    .await;
    let (mut tls, user, caps) = match r {
        Ok(Ok(Some(v))) => v,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            eprintln!("[novadb] {peer}: handshake failed: {e}");
            return;
        }
        Err(_) => {
            // Dropping the handshake future closes the socket.
            eprintln!("[novadb] {peer}: handshake timed out");
            return;
        }
    };
    if let Err(e) = command_loop(
        &server,
        &mut tls,
        Session {
            user,
            conn_id,
            last_insert_id: 0,
        },
        caps,
    )
    .await
        && e.kind() != io::ErrorKind::UnexpectedEof
    {
        eprintln!("[novadb] {peer}: connection error: {e}");
    }
    let _ = tls.shutdown().await;
}

type Tls = tokio_rustls::server::TlsStream<TcpStream>;

async fn deny(tls: &mut Tls, seq: u8, user: &str) -> io::Result<()> {
    let mut w = Writer::new(seq);
    w.push(&sql_err(&SqlError::access_denied(user)));
    w.flush(tls).await
}

/// Returns the TLS stream, authenticated user and client capabilities, or None after sending
/// an error to the client.
async fn handshake(
    server: &Server,
    mut tcp: TcpStream,
    ip: std::net::IpAddr,
    conn_id: u32,
) -> io::Result<Option<(Tls, String, u32)>> {
    let scramble = crate::auth::scramble().map_err(io::Error::other)?;
    let mut w = Writer::new(0);
    w.push(&pk::handshake_v10(&server.version, conn_id, &scramble));
    w.flush(&mut tcp).await?;

    let (seq, first) = read_packet(&mut tcp, MAX_PREAUTH_PACKET).await?;
    if pk::parse_ssl_request(&first).is_none() {
        let mut w = Writer::new(seq.wrapping_add(1));
        w.push(&pk::err(3159, "HY000", "Connections using insecure transport are prohibited: connect with TLS (e.g. --ssl-mode=REQUIRED)"));
        w.flush(&mut tcp).await?;
        return Ok(None);
    }
    let mut tls = server.tls.accept(tcp).await?;
    let (seq, resp) = read_packet(&mut tls, MAX_PREAUTH_PACKET).await?;
    let mut seq = seq.wrapping_add(1);
    let hr = match pk::parse_handshake_response(&resp) {
        Ok(h) => h,
        Err(e) => {
            let mut w = Writer::new(seq);
            w.push(&pk::err(1043, "08S01", &format!("Bad handshake: {e}")));
            w.flush(&mut tls).await?;
            return Ok(None);
        }
    };
    let user = hr.user.clone();
    // Switch to our plugin if the client started with another one.
    if hr.plugin.as_deref() != Some(pk::AUTH_PLUGIN) {
        let mut w = Writer::new(seq);
        w.push(&pk::auth_switch(&scramble));
        w.flush(&mut tls).await?;
        let (s2, _) = read_packet(&mut tls, MAX_PREAUTH_PACKET).await?;
        seq = s2.wrapping_add(1);
    }
    // Always full authentication: the cleartext password arrives over TLS and is checked
    // against the Argon2id hash (PLAN.md §4.4). No SHA-256 password cache to steal.
    let mut w = Writer::new(seq);
    w.push(&pk::auth_full_request());
    w.flush(&mut tls).await?;
    let (s3, pwp) = read_packet(&mut tls, MAX_PREAUTH_PACKET).await?;
    seq = s3.wrapping_add(1);
    let Ok(password) = pk::parse_cleartext_password(&pwp) else {
        deny(&mut tls, seq, &user).await?;
        return Ok(None);
    };
    // Rate limits run before any hashing (PLAN.md §4.5).
    let lim_ip = server
        .limiter
        .hit(&format!("ip:{ip}"), 20, Duration::from_secs(60));
    let lim_user = server.limiter.hit(
        &format!("user:{}", user.to_lowercase()),
        30,
        Duration::from_secs(60),
    );
    if !lim_ip || !lim_user {
        eprintln!("[novadb] auth rate-limited for '{user}' from {ip}");
        let mut w = Writer::new(seq);
        w.push(&pk::err(
            1129,
            "HY000",
            "Too many authentication attempts; try again in a minute",
        ));
        w.flush(&mut tls).await?;
        return Ok(None);
    }
    let ok = server.verify(&user, password).await;
    if !ok {
        eprintln!("[novadb] auth failed for '{user}' from {ip}");
        deny(&mut tls, seq, &user).await?;
        return Ok(None);
    }
    if let Some(db) = &hr.database
        && !db.eq_ignore_ascii_case("novadb")
    {
        let mut w = Writer::new(seq);
        w.push(&sql_err(&SqlError::unknown_db(db)));
        w.flush(&mut tls).await?;
        return Ok(None);
    }
    let mut w = Writer::new(seq);
    w.push(&pk::ok(0, 0, pk::SERVER_STATUS_AUTOCOMMIT, "", false));
    w.flush(&mut tls).await?;
    Ok(Some((tls, hr.user, hr.caps)))
}

struct Prepared {
    stmt: Stmt,
    params: usize,
    types: Vec<u16>,
    long_data: HashMap<u16, Vec<u8>>,
}

async fn command_loop<S: AsyncRead + AsyncWrite + Unpin>(
    server: &Server,
    s: &mut S,
    mut sess: Session,
    caps: u32,
) -> io::Result<()> {
    let deprecate_eof = caps & pk::CLIENT_DEPRECATE_EOF != 0;
    let mut multi = caps & pk::CLIENT_MULTI_STATEMENTS != 0;
    let mut prepared: HashMap<u32, Prepared> = HashMap::new();
    let mut next_stmt = 1u32;
    loop {
        let (_, p) =
            match tokio::time::timeout(IDLE_TIMEOUT, read_packet(s, server.max_packet)).await {
                Ok(r) => r?,
                Err(_) => return Ok(()),
            };
        let Some((&cmd, body)) = p.split_first() else {
            return Ok(());
        };
        let mut w = Writer::new(1);
        match cmd {
            pk::COM_QUIT => return Ok(()),
            pk::COM_PING => w.push(&pk::ok(0, 0, pk::SERVER_STATUS_AUTOCOMMIT, "", false)),
            pk::COM_INIT_DB => {
                let db = String::from_utf8_lossy(body);
                if db.eq_ignore_ascii_case("novadb") {
                    w.push(&pk::ok(0, 0, pk::SERVER_STATUS_AUTOCOMMIT, "", false));
                } else {
                    w.push(&sql_err(&SqlError::unknown_db(&db)));
                }
            }
            pk::COM_STATISTICS => {
                let up = server.started.elapsed().as_secs();
                w.push(format!("Uptime: {up}  Threads: {}  Questions: 0  Slow queries: 0  Opens: 0  Open tables: 0", server.active()).as_bytes());
            }
            pk::COM_SET_OPTION => {
                match body.first() {
                    Some(0) => multi = true,
                    Some(1) => multi = false,
                    _ => {}
                }
                w.push(&pk::eof(pk::SERVER_STATUS_AUTOCOMMIT));
            }
            pk::COM_RESET_CONNECTION => {
                prepared.clear();
                sess.last_insert_id = 0;
                w.push(&pk::ok(0, 0, pk::SERVER_STATUS_AUTOCOMMIT, "", false));
            }
            pk::COM_QUERY => {
                let Ok(sql) = std::str::from_utf8(body) else {
                    w.push(&pk::err(1064, "42000", "Query is not valid UTF-8"));
                    w.flush(s).await?;
                    continue;
                };
                match novadb_sql::parse_prepared(sql) {
                    Err(e) => w.push(&sql_err(&e)),
                    Ok((_, n)) if n > 0 => w.push(&pk::err(
                        1064,
                        "42000",
                        "'?' placeholders are only allowed in prepared statements",
                    )),
                    Ok((stmts, _)) if stmts.len() > 1 && !multi => w.push(&pk::err(
                        1064,
                        "42000",
                        "Multiple statements in one query need CLIENT_MULTI_STATEMENTS",
                    )),
                    Ok((stmts, _)) if stmts.is_empty() => {
                        w.push(&pk::err(1065, "42000", "Query was empty"))
                    }
                    Ok((stmts, _)) => {
                        let n = stmts.len();
                        for (i, st) in stmts.into_iter().enumerate() {
                            let more = i + 1 < n;
                            match server.run(st, &mut sess).await {
                                Ok(r) => write_result(&mut w, &r, more, deprecate_eof, false),
                                Err(e) => {
                                    w.push(&sql_err(&e));
                                    break;
                                }
                            }
                            // Stream large multi-results instead of buffering them all.
                            if w.buf.len() > 1 << 20 {
                                w.flush(s).await?;
                            }
                        }
                    }
                }
            }
            pk::COM_STMT_PREPARE => {
                let sql = String::from_utf8_lossy(body);
                match novadb_sql::parse_prepared(&sql) {
                    Err(e) => w.push(&sql_err(&e)),
                    Ok((mut stmts, n)) if stmts.len() == 1 => {
                        if prepared.len() >= MAX_PREPARED {
                            w.push(&pk::err(
                                1461,
                                "42000",
                                "Too many prepared statements on this connection",
                            ));
                        } else {
                            let id = next_stmt;
                            next_stmt = next_stmt.wrapping_add(1).max(1);
                            w.push(&pk::stmt_prepare_ok(id, 0, n as u16));
                            for _ in 0..n {
                                w.push(&pk::column_def(&WireCol {
                                    name: "?".into(),
                                    ty: pk::T_VAR_STRING,
                                    charset: pk::CHARSET_BINARY,
                                    length: 0,
                                    flags: 0,
                                    decimals: 0,
                                }));
                            }
                            if n > 0 && !deprecate_eof {
                                w.push(&pk::eof(pk::SERVER_STATUS_AUTOCOMMIT));
                            }
                            let stmt = stmts.remove(0);
                            prepared.insert(
                                id,
                                Prepared {
                                    stmt,
                                    params: n,
                                    types: Vec::new(),
                                    long_data: HashMap::new(),
                                },
                            );
                        }
                    }
                    Ok(_) => w.push(&pk::err(
                        1064,
                        "42000",
                        "A prepared statement must contain exactly one statement",
                    )),
                }
            }
            pk::COM_STMT_SEND_LONG_DATA => {
                // No response. Format: stmt id u32, param id u16, data.
                if body.len() >= 6 {
                    let id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
                    let param = u16::from_le_bytes([body[4], body[5]]);
                    if let Some(p) = prepared.get_mut(&id)
                        && usize::from(param) < p.params
                    {
                        let e = p.long_data.entry(param).or_default();
                        if e.len() + body.len() - 6 <= MAX_LONG_DATA {
                            e.extend_from_slice(&body[6..]);
                        }
                    }
                }
                continue;
            }
            pk::COM_STMT_CLOSE => {
                if let Ok(id) = pk::parse_stmt_id(body) {
                    prepared.remove(&id);
                }
                continue;
            }
            pk::COM_STMT_RESET => match pk::parse_stmt_id(body)
                .ok()
                .and_then(|id| prepared.get_mut(&id))
            {
                Some(p) => {
                    p.long_data.clear();
                    w.push(&pk::ok(0, 0, pk::SERVER_STATUS_AUTOCOMMIT, "", false));
                }
                None => w.push(&pk::err(
                    1243,
                    "HY000",
                    "Unknown prepared statement handler",
                )),
            },
            pk::COM_STMT_EXECUTE => {
                let id = pk::parse_stmt_id(body).unwrap_or(0);
                match prepared.get_mut(&id) {
                    None => w.push(&pk::err(
                        1243,
                        "HY000",
                        "Unknown prepared statement handler",
                    )),
                    Some(p) => match pk::parse_execute(body, p.params, &p.types, &p.long_data) {
                        Err(e) => w.push(&pk::err(
                            1210,
                            "HY000",
                            &format!("Incorrect arguments to mysqld_stmt_execute: {e}"),
                        )),
                        Ok(ex) => {
                            p.types = ex.types.clone();
                            p.long_data.clear();
                            let vals: Result<Vec<Value>, &str> =
                                ex.params.iter().map(pk::param_value).collect();
                            match vals {
                                Err(m) => w.push(&pk::err(1210, "HY000", m)),
                                Ok(vals) => {
                                    let mut st = p.stmt.clone();
                                    match novadb_sql::bind_params(&mut st, &vals) {
                                        Err(e) => w.push(&sql_err(&e)),
                                        Ok(()) => match server.run(st, &mut sess).await {
                                            Ok(r) => {
                                                write_result(&mut w, &r, false, deprecate_eof, true)
                                            }
                                            Err(e) => w.push(&sql_err(&e)),
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            }
            pk::COM_FIELD_LIST => w.push(&pk::err(
                1047,
                "08S01",
                "COM_FIELD_LIST is deprecated; use SHOW COLUMNS",
            )),
            _ => w.push(&pk::err(1047, "08S01", "Unknown command")),
        }
        w.flush(s).await?;
    }
}

fn write_result(w: &mut Writer, r: &QueryResult, more: bool, deprecate_eof: bool, binary: bool) {
    let status = pk::SERVER_STATUS_AUTOCOMMIT
        | if more {
            pk::SERVER_MORE_RESULTS_EXISTS
        } else {
            0
        };
    if !r.is_rows() {
        w.push(&pk::ok(
            r.affected,
            r.last_insert_id,
            status,
            r.info.as_deref().unwrap_or(""),
            false,
        ));
        return;
    }
    let types: Vec<_> = r.columns.iter().map(|c| c.ty).collect();
    let cols: Vec<WireCol> = r
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            pk::wire_col(
                &c.name,
                c.ty,
                &mut r.rows.iter().filter_map(move |row| row.get(i)),
            )
        })
        .collect();
    w.push(&pk::column_count(cols.len()));
    for c in &cols {
        w.push(&pk::column_def(c));
    }
    if !deprecate_eof {
        w.push(&pk::eof(status));
    }
    for row in &r.rows {
        if binary {
            w.push(&pk::binary_row(row, &cols, &types));
        } else {
            w.push(&pk::text_row(row, &types));
        }
    }
    if deprecate_eof {
        w.push(&pk::ok(0, 0, status, "", true));
    } else {
        w.push(&pk::eof(status));
    }
}
