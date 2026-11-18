//! Cluster networking: mutual-TLS streams between nodes (cluster CA, node identity from the
//! certificate), the join handshake (one-time token, CA pinned by fingerprint), and the
//! "add me" request a new node sends to the leader.
//!
//! Every connection starts with a 4-byte preface: `NVR1` Raft messages (client certificate
//! required; the sender's node id comes from its certificate, never from the payload),
//! `NVJ1` join (no client certificate yet; 64 KiB request limit, token checked), `NVA1` add a
//! node that already has a certificate.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use novadb_raft::{Msg, NodeId, codec};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::cluster::{self, Event, Handle, Peer, TokenBody};

const SERVER_NAME: &str = "novadb-node";
const MAX_SMALL: usize = 64 << 10;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Node identity + cluster CA, loaded from `<data>/cluster`.
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key_pem: String,
    pub ca: CertificateDer<'static>,
}

pub fn load_identity(data: &Path) -> Result<Identity, String> {
    let d = cluster::dir(data);
    let rd = |n: &str| {
        std::fs::read_to_string(d.join(n)).map_err(|e| format!("{}: {e}", d.join(n).display()))
    };
    let node =
        CertificateDer::from_pem_slice(rd("node.crt")?.as_bytes()).map_err(|e| e.to_string())?;
    let ca = CertificateDer::from_pem_slice(rd("ca.crt")?.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Identity {
        chain: vec![node, ca.clone()],
        key_pem: rd("node.key")?,
        ca,
    })
}

fn key(pem: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| format!("node key: {e}"))
}

fn roots(ca: &CertificateDer<'static>) -> Result<Arc<rustls::RootCertStore>, String> {
    let mut r = rustls::RootCertStore::empty();
    r.add(ca.clone()).map_err(|e| e.to_string())?;
    Ok(Arc::new(r))
}

pub fn server_config(id: &Identity) -> Result<rustls::ServerConfig, String> {
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(roots(&id.ca)?, provider())
            .allow_unauthenticated()
            .build()
            .map_err(|e| e.to_string())?;
    rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(id.chain.clone(), key(&id.key_pem)?)
        .map_err(|e| e.to_string())
}

pub fn client_config(id: &Identity) -> Result<rustls::ClientConfig, String> {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots(&id.ca)?)
        .with_client_auth_cert(id.chain.clone(), key(&id.key_pem)?)
        .map_err(|e| e.to_string())
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, b: &[u8]) -> std::io::Result<()> {
    w.write_all(&(b.len() as u32).to_le_bytes()).await?;
    w.write_all(b).await?;
    w.flush().await
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
    let mut l = [0u8; 4];
    r.read_exact(&mut l).await?;
    let n = u32::from_le_bytes(l) as usize;
    if n > max {
        return Err(std::io::Error::other("frame too large"));
    }
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).await?;
    Ok(b)
}

// ----- outgoing ------------------------------------------------------------------------------

/// Per-peer send queues (messages are dropped when a peer is unreachable; Raft retries).
pub struct Outbox {
    rt: tokio::runtime::Handle,
    tls: TlsConnector,
    addrs: Arc<RwLock<HashMap<NodeId, String>>>,
    queues: HashMap<NodeId, mpsc::Sender<Vec<u8>>>,
}

impl Outbox {
    pub fn new(
        rt: tokio::runtime::Handle,
        id: &Identity,
        peers: &BTreeMap<NodeId, Peer>,
    ) -> Result<Outbox, String> {
        Ok(Outbox {
            rt,
            tls: TlsConnector::from(Arc::new(client_config(id)?)),
            addrs: Arc::new(RwLock::new(
                peers.iter().map(|(k, v)| (*k, v.raft.clone())).collect(),
            )),
            queues: HashMap::new(),
        })
    }

    pub fn set_peer(&mut self, id: NodeId, addr: String) {
        if let Ok(mut a) = self.addrs.write() {
            a.insert(id, addr);
        }
    }

    pub fn send(&mut self, to: NodeId, m: &Msg) {
        let q = self.queues.entry(to).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(4096);
            self.rt
                .spawn(peer_task(to, rx, self.tls.clone(), self.addrs.clone()));
            tx
        });
        let _ = q.try_send(codec::encode_msg(m));
    }
}

async fn peer_task(
    to: NodeId,
    mut rx: mpsc::Receiver<Vec<u8>>,
    tls: TlsConnector,
    addrs: Arc<RwLock<HashMap<NodeId, String>>>,
) {
    let mut backoff = Duration::from_millis(100);
    loop {
        let addr = addrs.read().ok().and_then(|a| a.get(&to).cloned());
        let conn = async {
            let addr = addr.ok_or_else(|| std::io::Error::other("no address"))?;
            let tcp = tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(&addr))
                .await
                .map_err(|_| std::io::Error::other("connect timeout"))??;
            let _ = tcp.set_nodelay(true);
            let name = ServerName::try_from(SERVER_NAME).map_err(std::io::Error::other)?;
            let mut s = tokio::time::timeout(IO_TIMEOUT, tls.connect(name, tcp))
                .await
                .map_err(|_| std::io::Error::other("tls timeout"))??;
            s.write_all(b"NVR1").await?;
            Ok::<_, std::io::Error>(s)
        }
        .await;
        let mut s = match conn {
            Ok(s) => {
                backoff = Duration::from_millis(100);
                s
            }
            Err(_) => {
                // drop what queued up meanwhile (Raft resends), wait, retry
                while rx.try_recv().is_ok() {}
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(2));
                if rx.is_closed() {
                    return;
                }
                continue;
            }
        };
        loop {
            let Some(m) = rx.recv().await else { return };
            if write_frame(&mut s, &m).await.is_err() {
                break;
            }
        }
    }
}

// ----- incoming ------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct JoinReq {
    secret: String,
    node_id: NodeId,
    peer: Peer,
}

#[derive(Serialize, Deserialize, Default)]
pub struct JoinResp {
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub ca: String,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub peers: BTreeMap<NodeId, Peer>,
}

#[derive(Serialize, Deserialize, Default)]
struct AddResp {
    ok: bool,
    #[serde(default)]
    error: String,
}

pub async fn listen(
    addr: String,
    acceptor: TlsAcceptor,
    events: std_mpsc::Sender<Event>,
    data: PathBuf,
    handle: Arc<Handle>,
) {
    let l = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[novadb] cluster: bind {addr}: {e}");
            return;
        }
    };
    println!("[novadb] cluster: Raft listener on {addr} (mutual TLS, cluster CA)");
    let limiter = Arc::new(crate::auth::RateLimiter::new());
    loop {
        let Ok((tcp, peer)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let (acc, ev, data, h, lim) = (
            acceptor.clone(),
            events.clone(),
            data.clone(),
            handle.clone(),
            limiter.clone(),
        );
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let Ok(Ok(mut s)) = tokio::time::timeout(IO_TIMEOUT, acc.accept(tcp)).await else {
                return;
            };
            let mut pre = [0u8; 4];
            if tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut pre))
                .await
                .is_err()
            {
                return;
            }
            let cert_id = s
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|c| cluster::node_id_from_cert(c));
            match &pre {
                b"NVR1" => {
                    let Some(from) = cert_id else { return };
                    while let Ok(b) = read_frame(&mut s, novadb_raft::codec::MAX_FRAME).await {
                        match codec::decode_msg(&b) {
                            Ok(m) => {
                                if ev.send(Event::Msg(from, m)).is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                }
                b"NVJ1" => {
                    if !lim.hit(&format!("join:{}", peer.ip()), 10, Duration::from_secs(60)) {
                        return;
                    }
                    let Ok(Ok(b)) =
                        tokio::time::timeout(IO_TIMEOUT, read_frame(&mut s, MAX_SMALL)).await
                    else {
                        return;
                    };
                    let resp = handle_join(&data, &b, &h);
                    let _ =
                        write_frame(&mut s, &serde_json::to_vec(&resp).unwrap_or_default()).await;
                }
                b"NVA1" => {
                    let Some(id) = cert_id else { return };
                    let Ok(Ok(b)) =
                        tokio::time::timeout(IO_TIMEOUT, read_frame(&mut s, MAX_SMALL)).await
                    else {
                        return;
                    };
                    let resp = match serde_json::from_slice::<Peer>(&b) {
                        Ok(p) => {
                            let (tx, rx) = oneshot::channel();
                            if ev.send(Event::AddNode(id, p, tx)).is_err() {
                                return;
                            }
                            match tokio::time::timeout(Duration::from_secs(15), rx).await {
                                Ok(Ok(Ok(()))) => AddResp {
                                    ok: true,
                                    error: String::new(),
                                },
                                Ok(Ok(Err(e))) => AddResp {
                                    ok: false,
                                    error: e,
                                },
                                _ => AddResp {
                                    ok: false,
                                    error: "timeout".into(),
                                },
                            }
                        }
                        Err(_) => AddResp {
                            ok: false,
                            error: "bad request".into(),
                        },
                    };
                    let _ =
                        write_frame(&mut s, &serde_json::to_vec(&resp).unwrap_or_default()).await;
                }
                _ => {}
            }
        });
    }
}

fn handle_join(data: &Path, b: &[u8], h: &Handle) -> JoinResp {
    let fail = |m: &str| JoinResp {
        ok: false,
        error: m.into(),
        ..Default::default()
    };
    let Ok(req) = serde_json::from_slice::<JoinReq>(b) else {
        return fail("bad request");
    };
    if req.node_id == 0 {
        return fail("node id must be ≥ 1");
    }
    if h.voters
        .read()
        .map(|v| v.contains(&req.node_id))
        .unwrap_or(false)
        || h.peers
            .read()
            .map(|p| p.contains_key(&req.node_id))
            .unwrap_or(false)
    {
        return fail("that node id is already in the cluster");
    }
    if !cluster::consume_join_secret(data, &req.secret) {
        return fail("invalid, used or expired join token");
    }
    let d = cluster::dir(data);
    let (Ok(cf), Ok(ca_key), Ok(ca)) = (
        cluster::load(data),
        std::fs::read_to_string(d.join("ca.key")),
        std::fs::read_to_string(d.join("ca.crt")),
    ) else {
        return fail("this node cannot issue certificates");
    };
    let Some(cf) = cf else {
        return fail("not a cluster node");
    };
    match cluster::issue_node_cert(&cf.cluster_id, &ca_key, req.node_id) {
        Ok((cert, key)) => {
            println!(
                "[novadb] cluster: issued certificate for joining node {} ({})",
                req.node_id, req.peer.raft
            );
            JoinResp {
                ok: true,
                error: String::new(),
                cluster_id: cf.cluster_id,
                ca,
                cert,
                key,
                peers: h.peers.read().map(|p| p.clone()).unwrap_or_default(),
            }
        }
        Err(e) => fail(&e),
    }
}

// ----- join (client side) --------------------------------------------------------------------

/// Accepts the issuer's certificate only if its chain contains the CA pinned in the token and
/// the leaf verifies against that CA.
#[derive(Debug)]
struct Pinned {
    fp: String,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| cluster::fingerprint(c) == self.fp)
            .ok_or_else(|| {
                rustls::Error::General(
                    "cluster CA fingerprint does not match the join token".into(),
                )
            })?;
        let mut r = rustls::RootCertStore::empty();
        r.add(ca.clone().into_owned())
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        let v =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(r), provider())
                .build()
                .map_err(|e| rustls::Error::General(e.to_string()))?;
        v.verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn join_request(t: &TokenBody, node_id: NodeId, me: &Peer) -> Result<JoinResp, String> {
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned { fp: t.f.clone() }))
        .with_no_client_auth();
    let tcp = tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(&t.a))
        .await
        .map_err(|_| format!("connect {}: timeout", t.a))?
        .map_err(|e| format!("connect {}: {e}", t.a))?;
    let name = ServerName::try_from(SERVER_NAME).map_err(|e| e.to_string())?;
    let mut s = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS: {e}"))?;
    s.write_all(b"NVJ1").await.map_err(|e| e.to_string())?;
    let req = JoinReq {
        secret: t.s.clone(),
        node_id,
        peer: me.clone(),
    };
    write_frame(
        &mut s,
        &serde_json::to_vec(&req).map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|e| e.to_string())?;
    let b = tokio::time::timeout(IO_TIMEOUT, read_frame(&mut s, MAX_SMALL * 4))
        .await
        .map_err(|_| "no answer")?
        .map_err(|e| e.to_string())?;
    let r: JoinResp = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
    if !r.ok {
        return Err(format!("join refused: {}", r.error));
    }
    Ok(r)
}

/// A joined node asks the cluster (any peer; non-leaders refuse) to add it as a voter, until
/// it is one.
pub async fn ask_to_join(
    id: &Identity,
    me: NodeId,
    peer: Peer,
    handle: Arc<Handle>,
    data: PathBuf,
) {
    let Ok(cfg) = client_config(id) else { return };
    let tls = TlsConnector::from(Arc::new(cfg));
    loop {
        if cluster::load(&data)
            .ok()
            .flatten()
            .is_some_and(|c| c.member)
        {
            println!("[novadb] cluster: node {me} is a voting member");
            return;
        }
        let peers: Vec<(NodeId, String)> = handle
            .peers
            .read()
            .map(|p| {
                p.iter()
                    .filter(|(k, _)| **k != me)
                    .map(|(k, v)| (*k, v.raft.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (_, addr) in peers {
            let r = async {
                let tcp = tokio::time::timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(&addr))
                    .await
                    .ok()?
                    .ok()?;
                let mut s = tls
                    .connect(ServerName::try_from(SERVER_NAME).ok()?, tcp)
                    .await
                    .ok()?;
                s.write_all(b"NVA1").await.ok()?;
                write_frame(&mut s, &serde_json::to_vec(&peer).ok()?)
                    .await
                    .ok()?;
                let b =
                    tokio::time::timeout(Duration::from_secs(20), read_frame(&mut s, MAX_SMALL))
                        .await
                        .ok()?
                        .ok()?;
                serde_json::from_slice::<AddResp>(&b).ok()
            }
            .await;
            if r.is_some_and(|r| r.ok) {
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Owned-argument wrapper for spawning [`ask_to_join`].
pub async fn ask_to_join_owned(
    id: Identity,
    me: NodeId,
    peer: Peer,
    handle: Arc<Handle>,
    data: PathBuf,
) {
    ask_to_join(&id, me, peer, handle, data).await;
}
