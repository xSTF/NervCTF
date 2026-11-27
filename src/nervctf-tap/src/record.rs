//! Session recording.
//!
//! Two hard rules, because this process sits in a player's data path:
//!
//! 1. **Recording never applies backpressure to the relay.** Every call from the
//!    relay path is synchronous and non-blocking (`try_send`). If the writer cannot
//!    keep up, frames are *dropped* and counted — the player's bytes are never held
//!    up waiting on a disk write. A capture subsystem that could stall a connection
//!    would change challenge timing, which is the one thing this design must not do.
//! 2. **Hitting a size cap stops recording, never relaying.** Budgets are checked
//!    only on the recording side.
//!
//! On-disk layout, under `CAPTURE_DIR`:
//!   `index.jsonl`     — one JSON object per session lifecycle event (`open`/`close`)
//!   `<session>.ntap`  — framed raw bytes for that session
//!
//! `.ntap` is an 8-byte magic (`NTAP1\0\0\0`) followed by frames of a 16-byte
//! little-endian header + payload:
//!   `u32 len | u8 dir (0=c2s, 1=s2c) | u8 flags (bit0 = gap) | u16 _pad | u64 ts_us`
//! A gap frame carries `len == 0` and records that N bytes were dropped rather than
//! letting a truncated capture look like a complete one.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;

use crate::config::{Config, Labels, Proto};

pub const MAGIC: &[u8; 8] = b"NTAP1\0\0\0";
pub const FRAME_HEADER_LEN: usize = 16;
pub const DIR_C2S: u8 = 0;
pub const DIR_S2C: u8 = 1;
pub const FLAG_GAP: u8 = 1;

/// Bytes of the client→server direction folded into the session fingerprint. Enough
/// to cover an exploit's opening payload (HTTP request line + headers, or a pwn
/// script's first write) without hashing a whole file upload.
const FINGERPRINT_BYTES: usize = 512;

/// Frames buffered per session before the recorder starts dropping. 512 × up-to-64 KiB
/// is a generous ceiling that still bounds memory per session.
const CHANNEL_CAPACITY: usize = 512;

pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

enum Msg {
    Data {
        dir: u8,
        ts_us: u64,
        payload: Vec<u8>,
    },
    Gap {
        dir: u8,
        ts_us: u64,
        dropped: u64,
    },
    Close {
        ended_us: u64,
        bytes_c2s: u64,
        bytes_s2c: u64,
        error: Option<String>,
    },
}

pub struct Recorder {
    dir: PathBuf,
    enabled: bool,
    max_session_bytes: u64,
    /// Remaining global recording budget for this instance, in bytes.
    budget: Arc<AtomicU64>,
    index_tx: mpsc::UnboundedSender<serde_json::Value>,
    counter: AtomicU64,
    labels: Labels,
}

impl Recorder {
    /// Creates the capture directory and spawns the shared `index.jsonl` writer.
    ///
    /// A disabled recorder (`CAPTURE=off`) still hands out `Session` handles, so the
    /// relay path is byte-for-byte identical whether capture is on or off — the
    /// handles simply have nowhere to send.
    pub async fn new(cfg: &Config) -> anyhow::Result<Arc<Self>> {
        let (index_tx, mut index_rx) = mpsc::unbounded_channel::<serde_json::Value>();

        if cfg.record {
            tokio::fs::create_dir_all(&cfg.capture_dir).await.map_err(|e| {
                anyhow::anyhow!("create capture dir {}: {}", cfg.capture_dir.display(), e)
            })?;

            let index_path = cfg.capture_dir.join("index.jsonl");
            tokio::spawn(async move {
                while let Some(rec) = index_rx.recv().await {
                    let line = match serde_json::to_string(&rec) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("nervctf-tap: serialize index record: {}", e);
                            continue;
                        }
                    };
                    if let Err(e) = append_line(&index_path, &line).await {
                        eprintln!("nervctf-tap: append index record: {}", e);
                    }
                }
            });
        } else {
            // Drain and discard, so senders never see a closed channel.
            tokio::spawn(async move { while index_rx.recv().await.is_some() {} });
        }

        let budget = if cfg.max_total_bytes == 0 {
            u64::MAX
        } else {
            cfg.max_total_bytes
        };

        Ok(Arc::new(Recorder {
            dir: cfg.capture_dir.clone(),
            enabled: cfg.record,
            max_session_bytes: if cfg.max_session_bytes == 0 {
                u64::MAX
            } else {
                cfg.max_session_bytes
            },
            budget: Arc::new(AtomicU64::new(budget)),
            index_tx,
            counter: AtomicU64::new(0),
            labels: cfg.labels.clone(),
        }))
    }

    /// Opens a session: allocates an id, emits the `open` index record, and spawns
    /// this session's frame writer.
    pub fn open(self: &Arc<Self>, client: &str, proto: Proto) -> Arc<Session> {
        let started_us = now_us();
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let id = format!("{}-{:04}", started_us, n);

        let _ = self.index_tx.send(serde_json::json!({
            "ev": "open",
            "session": id,
            "proto": proto.as_str(),
            "client": client,
            "started_us": started_us,
            "team_id": self.labels.team_id,
            "team_name": self.labels.team_name,
            "challenge": self.labels.challenge,
            "instance": self.labels.instance,
        }));

        let tx = if self.enabled {
            let (tx, rx) = mpsc::channel::<Msg>(CHANNEL_CAPACITY);
            let path = self.dir.join(format!("{}.ntap", id));
            tokio::spawn(writer_task(
                path,
                rx,
                Arc::clone(self),
                id.clone(),
                proto,
                client.to_string(),
                started_us,
            ));
            Some(tx)
        } else {
            None
        };

        Arc::new(Session {
            id,
            tx,
            pending_drops: [AtomicU64::new(0), AtomicU64::new(0)],
        })
    }

    /// Claims `n` bytes of the instance-wide recording budget, returning how many were
    /// actually granted (0 once exhausted).
    fn claim(&self, n: u64) -> u64 {
        let mut current = self.budget.load(Ordering::Relaxed);
        loop {
            let granted = n.min(current);
            if granted == 0 {
                return 0;
            }
            match self.budget.compare_exchange_weak(
                current,
                current - granted,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return granted,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Relay-side handle. Cloned per direction; `record` is callable from the hot path.
pub struct Session {
    pub id: String,
    tx: Option<mpsc::Sender<Msg>>,
    /// Frames dropped since the last gap marker, per direction.
    pending_drops: [AtomicU64; 2],
}

impl Session {
    /// Hands one relayed chunk to the writer. Synchronous and never fails: on a full
    /// channel the chunk is dropped and counted for a later gap marker.
    pub fn record(&self, dir: u8, payload: &[u8]) {
        let Some(tx) = &self.tx else { return };
        let ts_us = now_us();
        let idx = dir as usize & 1;

        // Flush an accumulated drop count first so the gap lands in file order.
        let dropped = self.pending_drops[idx].swap(0, Ordering::Relaxed);
        if dropped > 0
            && tx
                .try_send(Msg::Gap {
                    dir,
                    ts_us,
                    dropped,
                })
                .is_err()
        {
            self.pending_drops[idx].fetch_add(dropped, Ordering::Relaxed);
        }

        if tx
            .try_send(Msg::Data {
                dir,
                ts_us,
                payload: payload.to_vec(),
            })
            .is_err()
        {
            self.pending_drops[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Ends the session. Unlike `record` this awaits, because it runs after the
    /// connection is already finished and the close record must not be lost.
    pub async fn close(&self, bytes_c2s: u64, bytes_s2c: u64, error: Option<String>) {
        let Some(tx) = &self.tx else { return };
        let _ = tx
            .send(Msg::Close {
                ended_us: now_us(),
                bytes_c2s,
                bytes_s2c,
                error,
            })
            .await;
    }
}

/// Owns one session's `.ntap` file and is the sole writer of its stats, so the
/// relay path holds no shared counters beyond the drop tally.
async fn writer_task(
    path: PathBuf,
    mut rx: mpsc::Receiver<Msg>,
    rec: Arc<Recorder>,
    id: String,
    proto: Proto,
    client: String,
    started_us: u64,
) {
    let file = match tokio::fs::File::create(&path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("nervctf-tap: create {}: {}", path.display(), e);
            // Keep draining so the relay's try_send never starts failing.
            while rx.recv().await.is_some() {}
            return;
        }
    };
    let mut out = BufWriter::new(file);
    if let Err(e) = out.write_all(MAGIC).await {
        eprintln!("nervctf-tap: write magic to {}: {}", path.display(), e);
    }

    let mut recorded = [0u64; 2];
    let mut dropped = [0u64; 2];
    let mut capped = false;
    let mut fingerprint = 0xcbf29ce484222325u64;
    let mut fingerprint_len = 0usize;
    let mut first_byte_us: Option<u64> = None;
    let mut closed: Option<(u64, u64, u64, Option<String>)> = None;

    'outer: loop {
        let Some(msg) = rx.recv().await else { break };
        let mut msg = Some(msg);
        // Batch whatever else is already queued, then flush once.
        loop {
            match msg.take() {
                Some(Msg::Data {
                    dir,
                    ts_us,
                    payload,
                }) => {
                    let idx = dir as usize & 1;
                    if dir == DIR_C2S && fingerprint_len < FINGERPRINT_BYTES {
                        let take = (FINGERPRINT_BYTES - fingerprint_len).min(payload.len());
                        fingerprint = fnv1a(&payload[..take], fingerprint);
                        fingerprint_len += take;
                    }
                    if first_byte_us.is_none() {
                        first_byte_us = Some(ts_us);
                    }

                    // Per-session cap, then the instance-wide budget. Either one
                    // being hit stops recording for this session only.
                    let room = rec.max_session_bytes.saturating_sub(recorded[idx]);
                    let want = (payload.len() as u64).min(room);
                    let granted = if want == 0 { 0 } else { rec.claim(want) };
                    if granted == 0 {
                        capped = true;
                        dropped[idx] += 1;
                    } else {
                        let slice = &payload[..granted as usize];
                        if granted < payload.len() as u64 {
                            capped = true;
                        }
                        if let Err(e) = write_frame(&mut out, dir, 0, ts_us, slice).await {
                            eprintln!("nervctf-tap: write frame: {}", e);
                            break 'outer;
                        }
                        recorded[idx] += granted;
                    }
                }
                Some(Msg::Gap {
                    dir,
                    ts_us,
                    dropped: n,
                }) => {
                    dropped[dir as usize & 1] += n;
                    if let Err(e) = write_frame(&mut out, dir, FLAG_GAP, ts_us, &[]).await {
                        eprintln!("nervctf-tap: write gap frame: {}", e);
                        break 'outer;
                    }
                }
                Some(Msg::Close {
                    ended_us,
                    bytes_c2s,
                    bytes_s2c,
                    error,
                }) => {
                    closed = Some((ended_us, bytes_c2s, bytes_s2c, error));
                    break 'outer;
                }
                None => {}
            }
            match rx.try_recv() {
                Ok(next) => msg = Some(next),
                Err(_) => break,
            }
        }
        let _ = out.flush().await;
    }

    let _ = out.flush().await;
    let _ = out.into_inner().sync_all().await;

    let (ended_us, bytes_c2s, bytes_s2c, error) =
        closed.unwrap_or_else(|| (now_us(), recorded[0], recorded[1], None));

    let _ = rec.index_tx.send(serde_json::json!({
        "ev": "close",
        "session": id,
        "proto": proto.as_str(),
        "client": client,
        "started_us": started_us,
        "ended_us": ended_us,
        "duration_us": ended_us.saturating_sub(started_us),
        "ttfb_us": first_byte_us.map(|t| t.saturating_sub(started_us)),
        "team_id": rec.labels.team_id,
        "team_name": rec.labels.team_name,
        "challenge": rec.labels.challenge,
        "instance": rec.labels.instance,
        // Relayed through the tap (ground truth for the challenge).
        "bytes_c2s": bytes_c2s,
        "bytes_s2c": bytes_s2c,
        // Actually persisted to the .ntap file (<= relayed, once a cap is hit).
        "recorded_c2s": recorded[0],
        "recorded_s2c": recorded[1],
        "dropped_frames": dropped[0] + dropped[1],
        "capped": capped,
        // FNV-1a over the first FINGERPRINT_BYTES of client→server. Equal values
        // across two teams means a byte-identical opening payload — the raw signal
        // for exploit-reuse correlation.
        "fp_c2s": format!("{:016x}", fingerprint),
        "fp_bytes": fingerprint_len,
        "error": error,
        "file": format!("{}.ntap", id),
    }));
}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    out: &mut W,
    dir: u8,
    flags: u8,
    ts_us: u64,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[4] = dir;
    header[5] = flags;
    // header[6..8] reserved
    header[8..16].copy_from_slice(&ts_us.to_le_bytes());
    out.write_all(&header).await?;
    if !payload.is_empty() {
        out.write_all(payload).await?;
    }
    Ok(())
}

async fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    f.write_all(line.as_bytes()).await?;
    f.write_all(b"\n").await?;
    f.flush().await
}

fn fnv1a(data: &[u8], mut hash: u64) -> u64 {
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_order_sensitive_and_stable() {
        let seed = 0xcbf29ce484222325u64;
        assert_eq!(fnv1a(b"GET / HTTP/1.1", seed), fnv1a(b"GET / HTTP/1.1", seed));
        assert_ne!(fnv1a(b"GET /a", seed), fnv1a(b"GET /b", seed));
        // Chunk boundaries must not change the result: the relay sees arbitrary splits.
        assert_eq!(
            fnv1a(b"abcdef", seed),
            fnv1a(b"def", fnv1a(b"abc", seed))
        );
    }

    #[tokio::test]
    async fn frame_header_round_trips() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, DIR_S2C, 0, 0x1122334455667788, b"hey")
            .await
            .unwrap();
        assert_eq!(buf.len(), FRAME_HEADER_LEN + 3);
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 3);
        assert_eq!(buf[4], DIR_S2C);
        assert_eq!(buf[5], 0);
        assert_eq!(
            u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            0x1122334455667788
        );
        assert_eq!(&buf[FRAME_HEADER_LEN..], b"hey");
    }
}
