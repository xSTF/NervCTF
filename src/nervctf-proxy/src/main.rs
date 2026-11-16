//! nervctf-proxy — transparent HTTP reverse proxy sidecar for `connection: http`
//! instance challenges.
//!
//! Forwards every request to `UPSTREAM` unchanged, relays the response back to the
//! player unchanged, and prints one JSON access-log line per exchange to stdout.
//! The container running this binary is expected to use `--log-driver=loki` (or the
//! compose equivalent) so Docker ships that stdout line to Loki with team/challenge
//! labels attached — this binary has no knowledge of Loki at all.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;

struct AppState {
    upstream: String,
    team_id: String,
    challenge_name: String,
    client: reqwest::Client,
}

/// Headers that must not be copied verbatim between the two legs of the proxy —
/// hop-by-hop headers whose value one leg's HTTP stack recomputes for the other.
const HOP_BY_HOP: &[&str] = &["connection", "content-length", "transfer-encoding", "host"];

fn headers_to_json(headers: &HeaderMap) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (name, value) in headers.iter() {
        let v = value.to_str().unwrap_or("").to_string();
        map.entry(name.as_str().to_string())
            .and_modify(|existing| {
                if let serde_json::Value::String(s) = existing {
                    s.push_str(", ");
                    s.push_str(&v);
                }
            })
            .or_insert(serde_json::Value::String(v));
    }
    serde_json::Value::Object(map)
}

/// Max bytes of request/response body kept in the log line. Loki rejects very large
/// log lines outright and nobody reads a multi-KB base64 blob in a Grafana cell anyway —
/// cap it and flag when it was cut so a full-body-dependent challenge is still debuggable
/// (truncated flag visible) without flooding the dashboard.
const BODY_LOG_CAP: usize = 2048;

fn body_preview(body: &Bytes) -> (String, bool) {
    let truncated = body.len() > BODY_LOG_CAP;
    let slice = &body[..body.len().min(BODY_LOG_CAP)];
    (
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, slice),
        truncated,
    )
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let started = std::time::Instant::now();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let target_url = format!("{}{}", state.upstream, path_and_query);

    // axum/reqwest pin different major versions of the `http` crate, so HeaderName/
    // HeaderValue types differ between them — convert through bytes rather than clone.
    let mut fwd_headers = reqwest::header::HeaderMap::new();
    for (name, value) in headers.iter() {
        if HOP_BY_HOP.contains(&name.as_str().to_ascii_lowercase().as_str()) {
            continue;
        }
        let (Ok(hname), Ok(hvalue)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) else {
            continue;
        };
        fwd_headers.insert(hname, hvalue);
    }

    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    let upstream_result = state
        .client
        .request(reqwest_method, &target_url)
        .headers(fwd_headers)
        .body(body.clone())
        .send()
        .await;

    let (status, resp_headers, resp_body): (StatusCode, HeaderMap, Bytes) = match upstream_result
    {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let mut headers = HeaderMap::new();
            for (name, value) in resp.headers().iter() {
                let lname = name.as_str().to_ascii_lowercase();
                if HOP_BY_HOP.contains(&lname.as_str()) {
                    continue;
                }
                if let (Ok(hname), Ok(hvalue)) = (
                    HeaderName::from_bytes(name.as_str().as_bytes()),
                    axum::http::HeaderValue::from_bytes(value.as_bytes()),
                ) {
                    headers.insert(hname, hvalue);
                }
            }
            let bytes = resp.bytes().await.unwrap_or_default();
            (status, headers, bytes)
        }
        Err(e) => {
            eprintln!("nervctf-proxy: upstream error: {}", e);
            (StatusCode::BAD_GATEWAY, HeaderMap::new(), Bytes::new())
        }
    };

    let duration_ms = started.elapsed().as_millis();

    let (req_body_b64, req_body_truncated) = body_preview(&body);
    let (resp_body_b64, resp_body_truncated) = body_preview(&resp_body);

    let log_line = serde_json::json!({
        "ts_ms": epoch_ms(),
        "team_id": state.team_id,
        "challenge": state.challenge_name,
        "method": method.as_str(),
        "path": path_and_query,
        "status": status.as_u16(),
        "duration_ms": duration_ms,
        "req_headers": headers_to_json(&headers),
        "req_body_len": body.len(),
        "req_body_truncated": req_body_truncated,
        "req_body_b64": req_body_b64,
        "resp_headers": headers_to_json(&resp_headers),
        "resp_body_len": resp_body.len(),
        "resp_body_truncated": resp_body_truncated,
        "resp_body_b64": resp_body_b64,
    });
    println!("{}", log_line);

    let mut builder = Response::builder().status(status);
    {
        let out_headers = builder.headers_mut().expect("response builder headers");
        *out_headers = resp_headers;
    }
    builder.body(axum::body::Body::from(resp_body)).unwrap_or_else(|_| {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })
}

#[tokio::main]
async fn main() -> Result<(), Infallible> {
    let upstream = std::env::var("UPSTREAM").unwrap_or_else(|_| "http://127.0.0.1:80".to_string());
    let listen_port: u16 = std::env::var("LISTEN_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let team_id = std::env::var("TEAM_ID").unwrap_or_else(|_| "unknown".to_string());
    let challenge_name = std::env::var("CHALLENGE_NAME").unwrap_or_else(|_| "unknown".to_string());

    eprintln!(
        "nervctf-proxy: listening on 0.0.0.0:{} -> {} (team={} challenge={})",
        listen_port, upstream, team_id, challenge_name
    );

    let state = Arc::new(AppState {
        upstream,
        team_id,
        challenge_name,
        // Redirects must never be followed server-side: a 3xx from the challenge app
        // has to reach the player unchanged (transparent-proxy semantics), and
        // following it here would let a malicious/compromised challenge app redirect
        // this proxy's own outbound request to an attacker-chosen address reachable
        // from its network (SSRF pivot) instead of the real upstream.
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build reqwest client"),
    });

    let app = Router::new()
        .fallback(any(proxy_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listen port");
    axum::serve(listener, app).await.expect("server error");
    Ok(())
}
