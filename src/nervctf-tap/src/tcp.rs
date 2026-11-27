//! TCP relay.
//!
//! Byte-for-byte passthrough in both directions. Nothing is parsed, buffered to
//! completion, rewritten, or reordered, which is what makes the tap safe for
//! protocols the old HTTP proxy could not survive: raw `nc`, pwntools, SSH, TLS,
//! HTTP/2 prior-knowledge, and WebSockets (the `Upgrade` handshake is just bytes
//! here, where `nervctf-proxy` destroyed it by stripping `Connection`).

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{Config, Proto};
use crate::record::{Recorder, Session, DIR_C2S, DIR_S2C};

/// 64 KiB, and reads are returned as soon as *any* data is available — a read never
/// waits to fill the buffer, so a one-byte interactive write is relayed as one byte.
const RELAY_BUF: usize = 64 * 1024;

pub async fn serve(cfg: Arc<Config>, rec: Arc<Recorder>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", cfg.listen_port))
        .await
        .map_err(|e| anyhow::anyhow!("bind 0.0.0.0:{}: {}", cfg.listen_port, e))?;

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // Per-connection accept errors (EMFILE, RST during handshake) must not
                // take the listener down — the challenge would go dark.
                eprintln!("nervctf-tap: accept: {}", e);
                continue;
            }
        };
        let cfg = Arc::clone(&cfg);
        let rec = Arc::clone(&rec);
        tokio::spawn(async move {
            if let Err(e) = handle(cfg, rec, client, peer.to_string()).await {
                eprintln!("nervctf-tap: session {}: {}", peer, e);
            }
        });
    }
}

async fn handle(
    cfg: Arc<Config>,
    rec: Arc<Recorder>,
    client: TcpStream,
    peer: String,
) -> anyhow::Result<()> {
    // Nagle off on both legs: a relay that coalesced small writes would change the
    // packet timing an interactive or timing-sensitive challenge depends on.
    let _ = client.set_nodelay(true);

    let session = rec.open(&peer, Proto::Tcp);

    let upstream = match TcpStream::connect(&cfg.upstream).await {
        Ok(s) => s,
        Err(e) => {
            // Recorded as a failed session rather than dropped silently: "players
            // reached a dead challenge" is exactly the kind of thing to be able to see.
            session
                .close(0, 0, Some(format!("upstream connect: {}", e)))
                .await;
            return Err(anyhow::anyhow!(
                "session {}: connect {}: {}",
                session.id,
                cfg.upstream,
                e
            ));
        }
    };
    let _ = upstream.set_nodelay(true);

    let (client_r, client_w) = client.into_split();
    let (up_r, up_w) = upstream.into_split();

    let s1 = Arc::clone(&session);
    let s2 = Arc::clone(&session);

    // `join!`, not `try_join!`: each direction must be able to finish on its own so a
    // half-closed connection keeps working. A client that writes, shuts down its write
    // side, then waits for the reply (standard pwntools / `nc` behaviour) relies on
    // this — aborting the peer direction on the first EOF would truncate the answer.
    let (c2s, s2c) = tokio::join!(
        pump(client_r, up_w, DIR_C2S, s1),
        pump(up_r, client_w, DIR_S2C, s2),
    );

    let error = c2s.1.or(s2c.1);
    session.close(c2s.0, s2c.0, error).await;
    Ok(())
}

/// Copies one direction until EOF, recording each chunk, then propagates the
/// half-close downstream with `shutdown()`.
///
/// Returns `(bytes_relayed, first_error)`.
async fn pump<R, W>(mut r: R, mut w: W, dir: u8, session: Arc<Session>) -> (u64, Option<String>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    let mut total: u64 = 0;

    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return (total, Some(format!("read: {}", e))),
        };
        total += n as u64;

        // Record before relaying so file order matches wire order. Non-blocking:
        // this cannot delay the write below.
        session.record(dir, &buf[..n]);

        if let Err(e) = w.write_all(&buf[..n]).await {
            return (total, Some(format!("write: {}", e)));
        }
    }

    let _ = w.shutdown().await;
    (total, None)
}
