//! UDP relay.
//!
//! UDP has no connections, so a "session" here is a fiction the tap maintains: all
//! traffic from one client address, ended by `SESSION_IDLE_SECS` of silence in both
//! directions. Each client address gets its own ephemeral upstream socket, so replies
//! are demultiplexed back to the right player without the challenge needing to know
//! anything about the tap.
//!
//! Datagram boundaries are preserved exactly — one `recv` is one `send`, never merged
//! or split — which matters because a UDP challenge's framing *is* the datagram.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::config::{Config, Proto};
use crate::record::{now_us, Recorder, Session, DIR_C2S, DIR_S2C};

/// Max UDP payload we will relay. 64 KiB covers the largest possible datagram.
const DGRAM_BUF: usize = 65_535;

struct Peer {
    up: Arc<UdpSocket>,
    session: Arc<Session>,
    last_us: Arc<AtomicU64>,
    c2s: Arc<AtomicU64>,
}

type PeerMap = Arc<Mutex<HashMap<SocketAddr, Peer>>>;

pub async fn serve(cfg: Arc<Config>, rec: Arc<Recorder>) -> anyhow::Result<()> {
    let sock = Arc::new(
        UdpSocket::bind(("0.0.0.0", cfg.listen_port))
            .await
            .map_err(|e| anyhow::anyhow!("bind udp 0.0.0.0:{}: {}", cfg.listen_port, e))?,
    );
    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; DGRAM_BUF];

    loop {
        let (n, client) = match sock.recv_from(&mut buf).await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("nervctf-tap: udp recv_from: {}", e);
                continue;
            }
        };

        // Clone out the handles under the lock; never await while holding it.
        let existing = {
            let map = peers.lock().expect("peer map poisoned");
            map.get(&client).map(|p| {
                (
                    Arc::clone(&p.up),
                    Arc::clone(&p.session),
                    Arc::clone(&p.last_us),
                    Arc::clone(&p.c2s),
                )
            })
        };

        let (up, session, last_us, c2s) = match existing {
            Some(handles) => handles,
            None => match new_peer(&cfg, &rec, &sock, &peers, client).await {
                Ok(handles) => handles,
                Err(e) => {
                    eprintln!("nervctf-tap: udp peer {}: {}", client, e);
                    continue;
                }
            },
        };

        last_us.store(now_us(), Ordering::Relaxed);
        c2s.fetch_add(n as u64, Ordering::Relaxed);
        session.record(DIR_C2S, &buf[..n]);

        if let Err(e) = up.send(&buf[..n]).await {
            eprintln!("nervctf-tap: udp send upstream for {}: {}", client, e);
        }
    }
}

/// Binds an ephemeral socket connected to the upstream for this client, registers the
/// peer, and spawns the reply pump that also owns this session's idle timeout.
async fn new_peer(
    cfg: &Arc<Config>,
    rec: &Arc<Recorder>,
    sock: &Arc<UdpSocket>,
    peers: &PeerMap,
    client: SocketAddr,
) -> anyhow::Result<(
    Arc<UdpSocket>,
    Arc<Session>,
    Arc<AtomicU64>,
    Arc<AtomicU64>,
)> {
    let up = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
    up.connect(&cfg.upstream).await?;

    let session = rec.open(&client.to_string(), Proto::Udp);
    let last_us = Arc::new(AtomicU64::new(now_us()));
    let c2s = Arc::new(AtomicU64::new(0));
    let s2c = Arc::new(AtomicU64::new(0));

    {
        let mut map = peers.lock().expect("peer map poisoned");
        map.insert(
            client,
            Peer {
                up: Arc::clone(&up),
                session: Arc::clone(&session),
                last_us: Arc::clone(&last_us),
                c2s: Arc::clone(&c2s),
            },
        );
    }

    tokio::spawn(reply_pump(
        Arc::clone(cfg),
        Arc::clone(sock),
        Arc::clone(peers),
        client,
        Arc::clone(&up),
        Arc::clone(&session),
        Arc::clone(&last_us),
        Arc::clone(&c2s),
        s2c,
    ));

    Ok((up, session, last_us, c2s))
}

#[allow(clippy::too_many_arguments)]
async fn reply_pump(
    cfg: Arc<Config>,
    sock: Arc<UdpSocket>,
    peers: PeerMap,
    client: SocketAddr,
    up: Arc<UdpSocket>,
    session: Arc<Session>,
    last_us: Arc<AtomicU64>,
    c2s: Arc<AtomicU64>,
    s2c: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; DGRAM_BUF];
    let mut error: Option<String> = None;

    loop {
        match timeout(cfg.udp_idle, up.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                last_us.store(now_us(), Ordering::Relaxed);
                s2c.fetch_add(n as u64, Ordering::Relaxed);
                session.record(DIR_S2C, &buf[..n]);
                if let Err(e) = sock.send_to(&buf[..n], client).await {
                    error = Some(format!("udp send to client: {}", e));
                    break;
                }
            }
            Ok(Err(e)) => {
                error = Some(format!("udp recv upstream: {}", e));
                break;
            }
            Err(_) => {
                // The timeout only covers this direction; client→server traffic
                // refreshes `last_us`, so re-check before declaring the session idle.
                let idle_us = now_us().saturating_sub(last_us.load(Ordering::Relaxed));
                if idle_us >= cfg.udp_idle.as_micros() as u64 {
                    break;
                }
            }
        }
    }

    // Only evict our own entry: the client address may already have been re-registered
    // with a fresh session after this one timed out.
    {
        let mut map = peers.lock().expect("peer map poisoned");
        if map
            .get(&client)
            .is_some_and(|p| Arc::ptr_eq(&p.session, &session))
        {
            map.remove(&client);
        }
    }

    session
        .close(
            c2s.load(Ordering::Relaxed),
            s2c.load(Ordering::Relaxed),
            error,
        )
        .await;
}
