//! Environment-driven configuration. No config file and no CLI flags for the relay
//! itself: the tap is launched by `remote-monitor` as a `docker run` sidecar, so env
//! vars are the only channel that already exists.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Identity labels copied verbatim into every session's index record. The tap does
/// not resolve or validate them — `remote-monitor` owns that and passes the result in.
#[derive(Clone, Debug)]
pub struct Labels {
    pub team_id: String,
    pub team_name: String,
    pub challenge: String,
    pub instance: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_port: u16,
    /// `host:port`, already stripped of any `scheme://` prefix.
    pub upstream: String,
    pub proto: Proto,
    pub labels: Labels,
    pub capture_dir: PathBuf,
    /// When false the tap is a pure byte relay and writes nothing. Lets an operator
    /// disable capture per challenge without changing the network path, so toggling
    /// it cannot itself change how the challenge behaves.
    pub record: bool,
    /// Recording stops for a session past this many bytes *per direction*; the relay
    /// keeps running untouched. 0 disables the cap.
    pub max_session_bytes: u64,
    /// Recording stops entirely for this instance past this many bytes on disk.
    /// 0 disables the cap.
    pub max_total_bytes: u64,
    /// A UDP pseudo-session is closed after this long with no packets in either
    /// direction. Irrelevant for TCP, which has real connection boundaries.
    pub udp_idle: Duration,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

/// Accepts `host:port`, `scheme://host:port`, or `scheme://host:port/path` and keeps
/// only `host:port`. `nervctf-proxy` took `UPSTREAM=http://app:4000`, so tolerating a
/// URL here means an in-place swap of the sidecar image needs no env change — and a
/// scheme is meaningless to a byte relay regardless.
fn normalize_upstream(raw: &str) -> String {
    let no_scheme = raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw);
    no_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(no_scheme)
        .trim()
        .to_string()
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let upstream_raw = env_or("UPSTREAM", "");
        let upstream = if upstream_raw.is_empty() {
            // Split host/port form, for callers that would rather not build a URL.
            let host = env_or("UPSTREAM_HOST", "");
            let port = env_or("UPSTREAM_PORT", "");
            if host.is_empty() || port.is_empty() {
                anyhow::bail!("set UPSTREAM=host:port (or UPSTREAM_HOST + UPSTREAM_PORT)");
            }
            format!("{}:{}", host, port)
        } else {
            normalize_upstream(&upstream_raw)
        };

        if !upstream.contains(':') {
            anyhow::bail!("UPSTREAM '{}' has no port — expected host:port", upstream);
        }

        let proto = match env_or("PROTO", "tcp").to_ascii_lowercase().as_str() {
            "udp" => Proto::Udp,
            "tcp" => Proto::Tcp,
            other => anyhow::bail!("PROTO '{}' must be 'tcp' or 'udp'", other),
        };

        // CAPTURE=off keeps the relay and drops the recorder, matching the
        // `capture: off` challenge setting.
        let record = !matches!(
            env_or("CAPTURE", "on").to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "none"
        );

        Ok(Config {
            listen_port: env_num("LISTEN_PORT", 8080u16),
            upstream,
            proto,
            labels: Labels {
                team_id: env_or("TEAM_ID", "unknown"),
                team_name: env_or("TEAM_NAME", ""),
                challenge: env_or("CHALLENGE_NAME", "unknown"),
                instance: env_or("INSTANCE_ID", "unknown"),
            },
            capture_dir: PathBuf::from(env_or("CAPTURE_DIR", "/var/lib/nervctf-tap")),
            record,
            max_session_bytes: env_num("MAX_SESSION_BYTES", 8 * 1024 * 1024u64),
            max_total_bytes: env_num("MAX_TOTAL_BYTES", 256 * 1024 * 1024u64),
            udp_idle: Duration::from_secs(env_num("SESSION_IDLE_SECS", 60u64)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_upstream;

    #[test]
    fn strips_scheme_and_path() {
        assert_eq!(normalize_upstream("http://app:4000"), "app:4000");
        assert_eq!(normalize_upstream("http://app:4000/health"), "app:4000");
        assert_eq!(normalize_upstream("app:4000"), "app:4000");
        assert_eq!(normalize_upstream("  app:4000  "), "app:4000");
        assert_eq!(normalize_upstream("tcp://1.2.3.4:22"), "1.2.3.4:22");
    }
}
