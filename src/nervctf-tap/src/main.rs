//! nervctf-tap — protocol-agnostic L4 tap sidecar for instance challenges.
//!
//! Replaces `nervctf-proxy`. The proxy was an HTTP reverse proxy: it re-terminated
//! HTTP in order to log it, which limited capture to `connection: http` challenges
//! and broke anything whose puzzle was HTTP behaviour itself (it stripped
//! `Connection`, so `Upgrade`/WebSocket could never work; it collapsed repeated
//! headers like `Set-Cookie` with `insert`; it buffered whole bodies, capping
//! uploads at axum's 2 MiB default).
//!
//! The tap inverts that: it relays bytes without interpreting them, and records the
//! raw stream to disk. Protocol decoding happens at *read* time, in `remote-monitor`,
//! over the stored bytes. So one sidecar covers `nc`, raw TCP, UDP, SSH, TLS and HTTP
//! identically, and a protocol it has never heard of still records correctly.
//!
//! ```text
//!   player ──► tap:LISTEN_PORT ──► UPSTREAM (challenge container)
//!                 │
//!                 └─► CAPTURE_DIR/index.jsonl   (one JSON record per session)
//!                     CAPTURE_DIR/<id>.ntap     (framed raw bytes)
//! ```
//!
//! Inspect a capture with `nervctf-tap dump <file.ntap>`, or extract one direction's
//! bytes verbatim with `nervctf-tap dump --raw=c2s <file.ntap>`.

mod config;
mod record;
mod tcp;
mod udp;

use std::sync::Arc;

use config::{Config, Proto};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("dump") {
        return dump::run(&args[1..]);
    }

    let cfg = Arc::new(Config::from_env()?);
    let rec = record::Recorder::new(&cfg).await?;

    eprintln!(
        "nervctf-tap: {} 0.0.0.0:{} -> {} (team={} challenge={} capture={})",
        cfg.proto.as_str(),
        cfg.listen_port,
        cfg.upstream,
        cfg.labels.team_id,
        cfg.labels.challenge,
        if cfg.record {
            cfg.capture_dir.display().to_string()
        } else {
            "off".to_string()
        },
    );

    match cfg.proto {
        Proto::Tcp => tcp::serve(cfg, rec).await,
        Proto::Udp => udp::serve(cfg, rec).await,
    }
}

/// Offline reader for `.ntap` files. Lives in the same binary so an operator
/// debugging on the host has no second artifact to deploy.
mod dump {
    use crate::record::{DIR_C2S, FLAG_GAP, FRAME_HEADER_LEN, MAGIC};
    use std::io::Write;

    pub fn run(args: &[String]) -> anyhow::Result<()> {
        let mut raw: Option<u8> = None;
        let mut path: Option<&str> = None;
        for a in args {
            match a.as_str() {
                "--raw=c2s" => raw = Some(0),
                "--raw=s2c" => raw = Some(1),
                other if other.starts_with("--") => {
                    anyhow::bail!("unknown flag {}", other)
                }
                other => path = Some(other),
            }
        }
        let path = path.ok_or_else(|| {
            anyhow::anyhow!("usage: nervctf-tap dump [--raw=c2s|--raw=s2c] <file.ntap>")
        })?;

        let data = std::fs::read(path)?;
        if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
            anyhow::bail!("{}: not an .ntap file (bad magic)", path);
        }

        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let mut off = MAGIC.len();
        let mut n_frames = 0u64;
        let mut bytes = [0u64; 2];

        while off + FRAME_HEADER_LEN <= data.len() {
            let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let dir = data[off + 4];
            let flags = data[off + 5];
            let ts_us = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            off += FRAME_HEADER_LEN;
            if off + len > data.len() {
                eprintln!("nervctf-tap: truncated final frame at offset {}", off);
                break;
            }
            let payload = &data[off..off + len];
            off += len;
            n_frames += 1;
            bytes[(dir & 1) as usize] += len as u64;

            if let Some(want) = raw {
                if dir == want {
                    out.write_all(payload)?;
                }
                continue;
            }

            let arrow = if dir == DIR_C2S { "C>S" } else { "S<C" };
            if flags & FLAG_GAP != 0 {
                writeln!(out, "[{:>16}] {} ---- GAP (frames dropped) ----", ts_us, arrow)?;
                continue;
            }
            writeln!(
                out,
                "[{:>16}] {} {:>6}B  {}",
                ts_us,
                arrow,
                len,
                printable(payload)
            )?;
        }

        if raw.is_none() {
            writeln!(
                out,
                "\n{} frames, {} B client->server, {} B server->client",
                n_frames, bytes[0], bytes[1]
            )?;
        }
        Ok(())
    }

    /// Single-line preview: printable ASCII kept, everything else escaped, so a
    /// binary pwn payload is still readable at a glance without a hex dump.
    fn printable(p: &[u8]) -> String {
        const MAX: usize = 180;
        let mut s = String::new();
        for &b in p.iter().take(MAX) {
            match b {
                b'\n' => s.push_str("\\n"),
                b'\r' => s.push_str("\\r"),
                b'\t' => s.push_str("\\t"),
                0x20..=0x7e => s.push(b as char),
                _ => s.push_str(&format!("\\x{:02x}", b)),
            }
        }
        if p.len() > MAX {
            s.push_str(" …");
        }
        s
    }
}
