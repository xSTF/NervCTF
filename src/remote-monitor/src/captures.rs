//! Reading `nervctf-tap` captures back for the admin API and Grafana.
//!
//! The tap writes, per instance, into `CAPTURE_BASE_DIR/<instance>/`:
//!   `index.jsonl`    — one JSON record per session lifecycle event (`open`/`close`)
//!   `<session>.ntap` — the framed raw byte stream
//!
//! The `.ntap` layout is defined by `nervctf-tap`'s `record` module. These constants
//! duplicate it because the tap is a separate binary crate with no shared library —
//! **keep them in sync with `src/nervctf-tap/src/record.rs`.**
//!
//! Nothing here trusts a caller-supplied path. A session is only ever resolved through
//! an `index.jsonl` record, so a `session` query parameter cannot address a file the
//! tap did not write (no `../` traversal, no reading arbitrary host files).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

const MAGIC: &[u8; 8] = b"NTAP1\0\0\0";
const FRAME_HEADER_LEN: usize = 16;
const DIR_C2S: u8 = 0;
const FLAG_GAP: u8 = 1;

/// Bytes of a frame rendered into the `preview` field. Enough to read an HTTP request
/// line and headers, or a pwn payload, without turning one panel into a megabyte.
const PREVIEW_BYTES: usize = 512;

/// Hard ceiling on frames returned for one session, so a Grafana panel cannot pull a
/// multi-megabyte capture into the browser. The response says when it truncated.
const MAX_FRAMES: usize = 2000;

pub fn base_dir() -> PathBuf {
    PathBuf::from(
        std::env::var("CAPTURE_BASE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "/var/lib/nervctf-captures".to_string()),
    )
}

/// Every index record across every instance directory, newest first.
///
/// `open` and `close` records for the same session are folded together, so an
/// in-flight session still lists (with `state: "open"` and no byte counts yet)
/// rather than being invisible until it ends.
pub fn list_sessions(base: &Path, limit: usize) -> Result<Vec<Value>> {
    let mut sessions: HashMap<String, Value> = HashMap::new();

    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        // A monitor with no captures yet is not an error — return an empty list so the
        // dashboard renders "no data" instead of a failing query.
        Err(_) => return Ok(Vec::new()),
    };

    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let index = entry.path().join("index.jsonl");
        let Ok(text) = std::fs::read_to_string(&index) else {
            continue;
        };
        for line in text.lines() {
            let Ok(rec) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(id) = rec["session"].as_str().map(str::to_string) else {
                continue;
            };
            let is_close = rec["ev"].as_str() == Some("close");
            match sessions.get(&id) {
                // A close record supersedes the open record for the same session.
                Some(existing) if existing["state"] == "closed" && !is_close => {}
                _ => {
                    let mut v = rec;
                    v["state"] = json!(if is_close { "closed" } else { "open" });
                    sessions.insert(id, v);
                }
            }
        }
    }

    let mut out: Vec<Value> = sessions.into_values().collect();
    // started_us is the tap's own monotonic-ish clock; sorting on it keeps a session's
    // frames and its row in the same order the player experienced.
    out.sort_by_key(|v| std::cmp::Reverse(v["started_us"].as_u64().unwrap_or(0)));
    out.truncate(limit.clamp(1, 5000));

    for v in out.iter_mut() {
        // Convenience columns for Grafana: a table cannot do arithmetic on its own.
        let us = v["started_us"].as_u64().unwrap_or(0);
        v["started_ms"] = json!(us / 1000);
        v["duration_ms"] = json!(v["duration_us"].as_u64().unwrap_or(0) / 1000);
        let c2s = v["bytes_c2s"].as_u64().unwrap_or(0);
        let s2c = v["bytes_s2c"].as_u64().unwrap_or(0);
        v["bytes_total"] = json!(c2s + s2c);
        // Strip the port: the address is the anti-cheat signal, the ephemeral port is noise.
        if let Some(client) = v["client"].as_str() {
            v["client_ip"] = json!(client.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(client));
        }
    }
    Ok(out)
}

/// Resolve a session id to its capture file *via the index*, never by path arithmetic.
fn locate(base: &Path, session: &str) -> Result<PathBuf> {
    for entry in std::fs::read_dir(base)
        .map_err(|e| anyhow!("read capture dir {}: {}", base.display(), e))?
        .flatten()
    {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = entry.path();
        let Ok(text) = std::fs::read_to_string(dir.join("index.jsonl")) else {
            continue;
        };
        for line in text.lines() {
            let Ok(rec) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if rec["session"].as_str() != Some(session) {
                continue;
            }
            // `file` comes from the tap's own record, but treat it as untrusted anyway:
            // accept a bare file name only.
            let file = rec["file"].as_str().unwrap_or_default();
            if file.is_empty() || file.contains('/') || file.contains("..") {
                continue;
            }
            let path = dir.join(file);
            if path.is_file() {
                return Ok(path);
            }
        }
    }
    Err(anyhow!("unknown session '{}'", session))
}

/// Decoded frames for one session: direction, timing, size and a printable preview.
pub fn read_frames(base: &Path, session: &str, limit: usize) -> Result<Value> {
    let path = locate(base, session)?;
    let data = std::fs::read(&path).map_err(|e| anyhow!("read {}: {}", path.display(), e))?;
    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("{} is not an .ntap file", path.display()));
    }

    let cap = limit.clamp(1, MAX_FRAMES);
    let mut frames = Vec::new();
    let mut off = MAGIC.len();
    let mut seq = 0u64;
    let mut first_ts = 0u64;
    let mut truncated = false;

    while off + FRAME_HEADER_LEN <= data.len() {
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        let dir = data[off + 4];
        let flags = data[off + 5];
        let ts_us = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
        off += FRAME_HEADER_LEN;
        if off + len > data.len() {
            // A capture of a session still in flight ends mid-frame; that is normal.
            truncated = true;
            break;
        }
        let payload = &data[off..off + len];
        off += len;
        if first_ts == 0 {
            first_ts = ts_us;
        }
        if frames.len() >= cap {
            truncated = true;
            break;
        }
        seq += 1;
        frames.push(json!({
            "seq": seq,
            // Read as "client to server" / "server to client" without a legend.
            "direction": if dir == DIR_C2S { "client -> challenge" } else { "challenge -> client" },
            "dir": if dir == DIR_C2S { "c2s" } else { "s2c" },
            "ts_ms": ts_us / 1000,
            "offset_ms": (ts_us.saturating_sub(first_ts)) / 1000,
            "bytes": len,
            "gap": flags & FLAG_GAP != 0,
            "preview": printable(payload),
        }));
    }

    Ok(json!({
        "session": session,
        "frames": frames,
        "truncated": truncated,
    }))
}

/// Single-line rendering: printable ASCII kept, everything else escaped, so a binary
/// pwn payload is still readable in a table cell without a hex viewer.
fn printable(p: &[u8]) -> String {
    let mut s = String::new();
    for &b in p.iter().take(PREVIEW_BYTES) {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{:02x}", b)),
        }
    }
    if p.len() > PREVIEW_BYTES {
        s.push_str(" …");
    }
    s
}

/// Reassembles one direction into a single text blob — the "what did the player send"
/// view, without per-frame rows.
pub fn read_stream(base: &Path, session: &str, dir_want: &str) -> Result<Value> {
    let path = locate(base, session)?;
    let data = std::fs::read(&path)?;
    if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
        return Err(anyhow!("{} is not an .ntap file", path.display()));
    }
    let want: u8 = if dir_want == "s2c" { 1 } else { 0 };
    let mut out: Vec<u8> = Vec::new();
    let mut off = MAGIC.len();
    while off + FRAME_HEADER_LEN <= data.len() {
        let len = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        let dir = data[off + 4];
        off += FRAME_HEADER_LEN;
        if off + len > data.len() {
            break;
        }
        if dir == want && out.len() < 64 * 1024 {
            out.extend_from_slice(&data[off..off + len]);
        }
        off += len;
    }
    Ok(json!({
        "session": session,
        "dir": dir_want,
        "bytes": out.len(),
        "text": printable(&out[..out.len().min(16 * 1024)]),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_capture(dir: &Path, session: &str, frames: &[(u8, &[u8])]) {
        std::fs::create_dir_all(dir).unwrap();
        let mut f = std::fs::File::create(dir.join(format!("{}.ntap", session))).unwrap();
        f.write_all(MAGIC).unwrap();
        for (i, (d, payload)) in frames.iter().enumerate() {
            let mut h = [0u8; FRAME_HEADER_LEN];
            h[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            h[4] = *d;
            h[8..16].copy_from_slice(&((1_000_000u64 + i as u64 * 1000).to_le_bytes()));
            f.write_all(&h).unwrap();
            f.write_all(payload).unwrap();
        }
        let mut idx = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("index.jsonl"))
            .unwrap();
        writeln!(
            idx,
            r#"{{"ev":"close","session":"{s}","file":"{s}.ntap","instance":"inst","challenge":"c","team_id":"7","team_name":"Seven","client":"1.2.3.4:5555","started_us":1000000,"duration_us":2000,"bytes_c2s":10,"bytes_s2c":20}}"#,
            s = session
        )
        .unwrap();
    }

    /// A private base directory per test. Deliberately not an env var: these tests run
    /// in parallel in one process, and a shared `CAPTURE_BASE_DIR` raced between them.
    struct Env(PathBuf);
    impl Env {
        fn new(name: &str) -> Self {
            let d = std::env::temp_dir().join(format!("nervctf-cap-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Env(d)
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn frames_decode_with_direction_and_preview() {
        let e = Env::new("frames");
        write_capture(
            &e.0.join("inst"),
            "1000-0001",
            &[(0, b"GET / HTTP/1.1\r\n"), (1, b"HTTP/1.1 200 OK\r\n"), (0, &[0x41, 0x00, 0xff])],
        );
        let v = read_frames(&e.0, "1000-0001", 100).unwrap();
        let f = v["frames"].as_array().unwrap();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0]["dir"], "c2s");
        assert_eq!(f[0]["preview"], "GET / HTTP/1.1\\r\\n");
        assert_eq!(f[1]["dir"], "s2c");
        assert_eq!(f[1]["direction"], "challenge -> client");
        // Non-printable bytes must be escaped, not dropped or mojibake'd.
        assert_eq!(f[2]["preview"], "A\\x00\\xff");
        assert_eq!(f[2]["bytes"], 3);
        // Relative timing is what makes a pwn interaction readable.
        assert_eq!(f[0]["offset_ms"], 0);
        assert_eq!(v["truncated"], false);
    }

    #[test]
    fn sessions_list_with_derived_columns() {
        let e = Env::new("list");
        write_capture(&e.0.join("inst"), "2000-0001", &[(0, b"hi")]);
        let s = list_sessions(&e.0, 50).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0]["challenge"], "c");
        assert_eq!(s[0]["state"], "closed");
        // Port stripped: the address identifies the player, the port is noise.
        assert_eq!(s[0]["client_ip"], "1.2.3.4");
        assert_eq!(s[0]["bytes_total"], 30);
        assert_eq!(s[0]["duration_ms"], 2);
    }

    #[test]
    fn a_missing_capture_dir_is_an_empty_list_not_an_error() {
        // The dashboard must render "no data", not a failing query, before the first
        // player connects.
        let missing = std::path::Path::new("/nonexistent/nervctf/captures");
        assert_eq!(list_sessions(missing, 50).unwrap().len(), 0);
    }

    #[test]
    fn an_unknown_session_is_rejected_and_paths_cannot_escape() {
        let e = Env::new("traverse");
        write_capture(&e.0.join("inst"), "3000-0001", &[(0, b"x")]);
        for bad in ["../../etc/passwd", "/etc/passwd", "nope", "inst/index.jsonl"] {
            assert!(
                read_frames(&e.0, bad, 10).is_err(),
                "{:?} must not resolve to a file",
                bad
            );
        }
        assert!(read_frames(&e.0, "3000-0001", 10).is_ok());
    }

    #[test]
    fn frame_limit_is_reported_as_truncated() {
        let e = Env::new("limit");
        let frames: Vec<(u8, &[u8])> = (0..10).map(|_| (0u8, b"abc".as_slice())).collect();
        write_capture(&e.0.join("inst"), "4000-0001", &frames);
        let v = read_frames(&e.0, "4000-0001", 4).unwrap();
        assert_eq!(v["frames"].as_array().unwrap().len(), 4);
        assert_eq!(v["truncated"], true);
    }

    #[test]
    fn stream_reassembles_one_direction() {
        let e = Env::new("stream");
        write_capture(
            &e.0.join("inst"),
            "5000-0001",
            &[(0, b"AAA"), (1, b"zzz"), (0, b"BBB")],
        );
        let v = read_stream(&e.0, "5000-0001", "c2s").unwrap();
        assert_eq!(v["text"], "AAABBB");
        assert_eq!(v["bytes"], 6);
        let v = read_stream(&e.0, "5000-0001", "s2c").unwrap();
        assert_eq!(v["text"], "zzz");
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Decodes a capture produced by the real `nervctf-tap` binary.
    ///
    /// The frame constants in this module are hand-copied from the tap crate, which has
    /// no shared library to import from — so the one failure mode that unit tests with
    /// synthetic files cannot catch is the two drifting apart. This reads what the tap
    /// actually wrote.
    ///
    /// Ignored by default: needs Docker, `nervctf-tap:latest` and `python:3.12-alpine`.
    ///   `cargo test -p remote-monitor -- --ignored --nocapture decodes_a_real`
    #[tokio::test]
    #[ignore = "requires Docker + nervctf-tap:latest"]
    async fn decodes_a_real_tap_capture() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = std::env::var("NERVCTF_TEST_CAPTURE_DIR").unwrap_or_else(|_| {
            std::env::temp_dir().join("nervctf-tap-it").display().to_string()
        });
        let base = std::path::Path::new(&root).join(format!("live-{}", std::process::id()));
        let cap = base.join("inst");
        std::fs::create_dir_all(&cap).expect("create capture dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cap, std::fs::Permissions::from_mode(0o777));
        }

        let app = format!("cap-app-{}", std::process::id());
        let tap = format!("cap-tap-{}", std::process::id());
        let net = format!("cap-net-{}", std::process::id());
        let sh = |cmd: String| async move {
            tokio::process::Command::new("sh").args(["-c", &cmd]).output().await
        };
        let _ = sh(format!("docker rm -f {} {} >/dev/null 2>&1", app, tap)).await;
        let _ = sh(format!("docker network rm {} >/dev/null 2>&1", net)).await;
        sh(format!("docker network create {}", net)).await.expect("net");
        sh(format!(
            "docker run -d --name {} --network {} python:3.12-alpine python -m http.server 4000",
            app, net
        )).await.expect("app");

        let port = crate::instance::docker::pick_free_ports(&std::collections::HashSet::new(), 1)
            .expect("port")[0];
        sh(format!(
            "docker run -d --name {t} --network {n} -p {p}:8080              -e UPSTREAM={a}:4000 -e PROTO=tcp -e LISTEN_PORT=8080              -e TEAM_ID=7 -e TEAM_NAME=Seven -e CHALLENGE_NAME=live-chal              -e INSTANCE_ID=inst -e CAPTURE_DIR=/cap -v {c}:/cap nervctf-tap:latest",
            t = tap, n = net, p = port, a = app, c = cap.display()
        )).await.expect("tap");

        // Drive a complete HTTP exchange through the tap.
        let mut body = String::new();
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(mut s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                if s.write_all(b"GET /?probe=nervctf HTTP/1.0\r\nHost: x\r\n\r\n").await.is_err() {
                    continue;
                }
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                    body = String::from_utf8_lossy(&buf).to_string();
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        let sessions = list_sessions(&base, 50);
        let frames = sessions.as_ref().ok().and_then(|v| {
            v.first()
                .and_then(|s| s["session"].as_str())
                .map(|id| read_frames(&base, id, 100))
        });

        let _ = sh(format!("docker rm -f {} {} >/dev/null 2>&1", app, tap)).await;
        let _ = sh(format!("docker network rm {} >/dev/null 2>&1", net)).await;
        let _ = std::fs::remove_dir_all(&base);

        assert!(body.starts_with("HTTP/1.0 200"), "no response through the tap: {:?}", body);
        let sessions = sessions.expect("list_sessions");
        assert_eq!(sessions.len(), 1, "expected one session, got {:?}", sessions);
        let s = &sessions[0];
        assert_eq!(s["challenge"], "live-chal");
        assert_eq!(s["team_name"], "Seven");
        assert_eq!(s["state"], "closed");
        assert!(s["bytes_total"].as_u64().unwrap_or(0) > 0, "{}", s);

        let frames = frames.expect("session id present").expect("read_frames");
        let f = frames["frames"].as_array().expect("frames array");
        assert!(f.len() >= 2, "expected both directions, got {:?}", f);
        // This is the assertion that catches constant drift: the request the client
        // actually sent has to come back out of the capture, in the right direction.
        let c2s: String = f.iter().filter(|x| x["dir"] == "c2s")
            .map(|x| x["preview"].as_str().unwrap_or("")).collect();
        let s2c: String = f.iter().filter(|x| x["dir"] == "s2c")
            .map(|x| x["preview"].as_str().unwrap_or("")).collect();
        assert!(c2s.contains("GET /?probe=nervctf"), "client bytes missing: {}", c2s);
        assert!(s2c.contains("HTTP/1.0 200"), "server bytes missing: {}", s2c);
    }
}
