//! Instance lifecycle management — dispatches to backend-specific modules.

pub mod compose;
pub mod docker;
pub mod lxc;
pub mod ssh;
pub mod vagrant;

use anyhow::{anyhow, Result};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde_json::Value;
use mysql_async::Pool;
use crate::db::Db;

/// Strips control characters from a value that will be embedded in generated config,
/// log labels or capture index records.
///
/// `team_name` is **player-controlled** — it is CTFd's `teams.name`, chosen by players
/// and returned verbatim by `db::get_identity_name` — so it reaches generated compose
/// YAML and sidecar environment as untrusted input. Quoting is what actually makes the
/// YAML safe (see `compose::yaml_quote`); this is defence in depth, and keeps newlines
/// out of capture records regardless of the backend.
pub fn strip_control(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

/// Traffic capture mode for an instance, resolved from its stored `config_json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    /// In-path `nervctf-tap` sidecar recording the raw byte stream.
    Tap,
    /// No capture — published directly, as an instance with no sidecar always was.
    Off,
}

/// Resolves the effective capture mode.
///
/// `capture` wins when present; otherwise the superseded `log_proxy: true` resolves to
/// `Tap`, so the many existing `challenge.yml` files that set it keep working and get
/// the tap instead of the old HTTP proxy.
///
/// Two deliberate differences from the `log_proxy` gate this replaces:
///   * it is **not** conditioned on `connection: http`. The tap interprets nothing, so
///     an `nc`/`ssh`/raw-TCP challenge is captured just as well.
///   * `pcap` is accepted by the parser but not implemented, so it resolves to `Off`
///     here. The CLI validator rejects it up front; this is the defence in depth for a
///     `config_json` written by a newer CLI than this monitor.
pub fn capture_mode(config: &Value) -> CaptureMode {
    match config["capture"].as_str() {
        Some("tap") => CaptureMode::Tap,
        Some("off") => CaptureMode::Off,
        Some(other) => {
            tracing::warn!(
                "capture mode '{}' is not supported by this monitor — running with no capture",
                other
            );
            CaptureMode::Off
        }
        None => {
            if config["log_proxy"].as_bool().unwrap_or(false) {
                CaptureMode::Tap
            } else {
                CaptureMode::Off
            }
        }
    }
}

/// Whether this instance actually gets a tap sidecar.
///
/// `capture_mode` says what the challenge asked for; this also requires the sidecar
/// image to be present on the host that runs challenge containers. The playbook builds
/// `nervctf-tap:latest` locally, and only when `nervctf setup` found a binary to ship,
/// so a deployment can legitimately not have it. The image is in no registry, so
/// referencing it anyway fails the whole provision with a misleading "pull access
/// denied" from Docker Hub.
///
/// Degrading to no capture is the right failure here, and is checked *before* the
/// primary port is withheld from the app container, so the instance is published
/// directly and stays playable. Only the capture is lost; the app container still
/// ships stdout/stderr to Loki. (A tap that fails to start *after* the app has been
/// left unpublished is a different case — there the provision is torn down, because
/// the instance would be unreachable.)
async fn tap_enabled(
    config: &Value,
    challenge_name: &str,
    capture_dir: &str,
    runner_ssh: Option<&str>,
) -> bool {
    if capture_mode(config) != CaptureMode::Tap {
        return false;
    }

    // The capture directory is checked here, not at launch time, because the tap
    // bind-mounts it: if the directory cannot be created, `docker run` fails with
    // "error while creating mount source path ... permission denied" and the whole
    // provision dies. Docker will not create it for us when the parent is unwritable,
    // so leniency at launch time does not help — the decision has to be made before
    // the app container's port is withheld, while degrading still leaves a working
    // instance.
    if let Err(e) = docker::ensure_dir(capture_dir, runner_ssh).await {
        tracing::warn!(
            "provision: '{}' asks for capture but the capture directory {} is not usable \
             ({}) — provisioning WITHOUT capture. Is CAPTURE_BASE_DIR mounted read-write \
             into the monitor?",
            challenge_name,
            capture_dir,
            e
        );
        return false;
    }

    if docker::tap_image_available(runner_ssh).await {
        return true;
    }
    tracing::warn!(
        "provision: '{}' asks for capture but image {} is missing on the challenge host —          provisioning WITHOUT capture. To enable it, build the tap          (cargo build --release --target x86_64-unknown-linux-musl -p nervctf-tap) and          re-run `nervctf setup`.",
        challenge_name,
        docker::TAP_IMAGE
    );
    false
}

/// The connection type to show players for the primary port: `"udp"` overrides the
/// challenge's declared `connection` (nc/http/ssh) whenever the primary port itself is
/// UDP, since `nc -u` (not plain `nc`) is required to reach it.
fn effective_connection_type(connection: &str, primary_protocol: &str) -> String {
    if primary_protocol == "udp" {
        "udp".to_string()
    } else {
        connection.to_string()
    }
}

/// Generate a random flag for `flag_mode = "random"`, or return None for static/no flag.
pub fn generate_flag(config: &Value) -> Option<String> {
    if config["flag_mode"].as_str().unwrap_or("static") != "random" {
        return None;
    }
    let prefix = config["flag_prefix"].as_str().unwrap_or("CTF{");
    let suffix = config["flag_suffix"].as_str().unwrap_or("}");
    let length = config["random_flag_length"].as_u64().unwrap_or(16) as usize;
    let random: String = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    Some(format!("{}{}{}", prefix, random, suffix))
}

/// Sanitize a challenge name to a valid Docker name component.
pub fn sanitize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Generate a unique container/project name for an instance.
/// Includes `team_id` so `docker ps`/`docker logs` identify the owning team without a
/// DB lookup. The 6 random lowercase alphanumeric chars still avoid name collisions
/// when a team re-provisions before the previous container is fully torn down.
pub fn container_name(challenge_name: &str, team_id: i64) -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(6)
        .map(|c| (c as char).to_ascii_lowercase())
        .collect();
    format!("ctf-{}-{}-{}", sanitize_name(challenge_name), team_id, suffix)
}

/// Stop and remove a container/project for an instance (called on expiry or explicit stop).
///
/// The `container_id` field stores either a Docker container ID (for docker backend)
/// or a compose project name (for compose backend). We try Docker removal first,
/// then compose down if it looks like a project name.
///
/// `runner_ssh` — SSH target for split-machine mode (e.g. `docker@192.168.1.50`).
pub async fn cleanup_container(container_id: &str, runner_ssh: Option<&str>) {
    // Compose project names and LXC/Docker container names all start with "ctf-"
    if container_id.starts_with("ctf-") && container_id.len() < 80 {
        let _ = compose::down(container_id, runner_ssh, None).await;
        let _ = lxc::delete(container_id).await;
    }
    // Always also try docker remove (no-op if not a container ID)
    if let Err(e) = docker::remove_container(container_id, runner_ssh).await {
        eprintln!("  cleanup: failed to remove {}: {}", container_id, e);
    }
}

/// Provision a new instance for a team.
///
/// Generates a random flag (if `flag_mode = "random"`), registers it with CTFd's DB,
/// starts the container, and persists everything in the DB.
///
/// `runner_ssh` — SSH target for split-machine mode (e.g. `docker@192.168.1.50`).
///
/// Returns `(host, port, connection_type, expires_at)`.
pub async fn provision(
    db: &Db,
    challenge_name: &str,
    team_id: i64,
    user_id: Option<i64>,
    config: &Value,
    public_host: &str,
    ctfd_pool: &Pool,
    runner_ssh: Option<&str>,
    // Pre-generated name from handler so it matches the provisioning stub's container_id,
    // preventing the orphan checker from killing the project before the DB is updated.
    container_name_hint: Option<String>,
    // Loki push endpoint for `log_proxy`-enabled `connection: http` instances.
    loki_url: Option<&str>,
    // CTFd team-mode vs user-mode, for resolving a display name for Loki's
    // `team_name` label (ctfd_teams in team-mode, ctfd_users in user-mode —
    // see `db::get_identity_name`).
    ctfd_mode: crate::ctfd_db::CtfdMode,
) -> Result<(String, u16, String, String)> {
    let backend = config["backend"].as_str().unwrap_or("docker");
    let connection = config["connection"].as_str().unwrap_or("nc").to_string();
    let timeout_minutes = config["timeout_minutes"].as_u64().unwrap_or(45);
    let command = config["command"].as_str();

    // Parse internal_ports: accept array (new) or scalar (old config_json in DB).
    // Each element may be an integer (TCP) or a "port[/protocol]" string (UDP).
    let internal_ports: Vec<(u32, String)> = if let Some(arr) = config["internal_ports"].as_array() {
        arr.iter().filter_map(parse_port).collect()
    } else if let Some(p) = config["internal_port"].as_u64() {
        vec![(p as u32, "tcp".to_string())]
    } else {
        vec![(4000, "tcp".to_string())]
    };
    let port_count = internal_ports.len().max(1);

    // Look up the CTFd challenge ID for flag registration.
    let ctfd_id = crate::db::get_ctfd_id(db, challenge_name)?;

    match backend {
        "docker" => {
            let image_tag = crate::db::get_image_tag(db, challenge_name)?
                .unwrap_or_else(|| format!("{}:latest", sanitize_name(challenge_name)));

            let used_ports = crate::db::get_used_ports(db)?;
            let host_ports = docker::pick_free_ports(&used_ports, port_count)?;
            let port_mappings: Vec<(u16, u32, String)> = host_ports.iter().zip(internal_ports.iter()).map(|(&h, (i, proto))| (h, *i, proto.clone())).collect();
            let host_port = host_ports[0];
            let cname = container_name_hint.clone().unwrap_or_else(|| container_name(challenge_name, team_id));

            let flag = generate_flag(config);
            let flag_delivery = config["flag_delivery"].as_str().unwrap_or("env");
            let flag_file_path = config["flag_file_path"].as_str();

            let mut env_vars: Vec<(String, String)> = Vec::new();
            let mut volumes: Vec<(String, String)> = Vec::new();

            if let Some(f) = flag.as_deref() {
                if flag_delivery == "file" {
                    if let Some(container_path) = flag_file_path {
                        // Write the flag to a deterministic host path so remove_container
                        // can clean it up without a separate DB lookup.
                        let flag_host_path = format!("/tmp/ctf-flags/{}.flag", cname);
                        docker::write_flag_file(&flag_host_path, f, runner_ssh).await
                            .map_err(|e| anyhow!("write flag file for {}: {}", cname, e))?;
                        volumes.push((flag_host_path, container_path.to_string()));
                    }
                } else {
                    env_vars.push(("FLAG".to_string(), f.to_string()));
                }
            }

            // A captured instance gets an `nervctf-tap` sidecar in front of it (see
            // docs/instance-challenges.md) so admins can review player traffic. The app
            // container joins a dedicated per-instance network and is not published
            // directly; the tap is published on `host_port` instead and forwards to the
            // app by container name.
            let cap_dir = docker::capture_dir(&cname);
            let tap = tap_enabled(config, challenge_name, &cap_dir, runner_ssh).await;
            let tap_net = tap.then(|| docker::instance_network_name(&cname));
            if let Some(net) = &tap_net {
                docker::create_network(net, runner_ssh).await?;
            }

            // Only the primary port is tapped; any additional ports are still published
            // directly on the app container, same as an uncaptured instance.
            let app_port_mappings: &[(u16, u32, String)] =
                if tap { &port_mappings[1..] } else { &port_mappings };

            // Every instance container (app and, if present, the proxy sidecar) ships its
            // stdout/stderr to Loki with team/challenge labels — not just `log_proxy`-opted-in
            // HTTP sidecars — so admins can see raw logs for any challenge (nc, ssh, …) on the
            // "NervCTF Player Traffic" Grafana dashboard, filtered by challenge/team.
            let loki = loki_url.unwrap_or("http://127.0.0.1:3100/loki/api/v1/push");
            let team_name = crate::db::get_identity_name(db, team_id, ctfd_mode).unwrap_or(None);

            let container_id = docker::run_container(
                &image_tag,
                &cname,
                app_port_mappings,
                command,
                &env_vars,
                &volumes,
                tap_net.as_deref(),
                &docker::loki_log_args(loki, team_id, team_name.as_deref(), challenge_name),
                runner_ssh,
            ).await?;

            if tap {
                let tap_name = docker::tap_container_name(&cname);
                // The primary port's protocol decides whether the tap listens TCP or UDP.
                let (primary_internal, primary_proto) =
                    (internal_ports[0].0, port_mappings[0].2.clone());

                let tap_env = docker::tap_env(
                    &cname,
                    primary_internal,
                    &primary_proto,
                    team_id,
                    team_name.as_deref(),
                    challenge_name,
                    &cname,
                );
                let tap_port_mappings = vec![(host_port, 8080u32, primary_proto)];

                let mut tap_args =
                    docker::loki_log_args(loki, team_id, team_name.as_deref(), challenge_name);
                tap_args.extend(docker::capture_mount_args(&cap_dir));

                // The app container is already up but deliberately unpublished, so if the
                // tap cannot start the instance is unreachable. Tear the app down and fail
                // the provision rather than leaving a running instance nobody can connect
                // to (the old proxy path left exactly that behind).
                let tap_result = async {
                    docker::run_container(
                        docker::TAP_IMAGE,
                        &tap_name,
                        &tap_port_mappings,
                        None,
                        &tap_env,
                        &[],
                        tap_net.as_deref(),
                        &tap_args,
                        runner_ssh,
                    )
                    .await
                }
                .await;

                if let Err(e) = tap_result {
                    let _ = docker::remove_container(&cname, runner_ssh).await;
                    return Err(anyhow!(
                        "tap sidecar for '{}' team {} failed to start ({}); instance torn down.                          Is the nervctf-tap:latest image built on this host?",
                        challenge_name,
                        team_id,
                        e
                    ));
                }
            }

            let extra_ports = build_extra_ports_json(&port_mappings);
            let expires_at = expires_at_string(timeout_minutes);
            let connection = effective_connection_type(&connection, &port_mappings[0].2);

            // Write instance to SQLite before creating the CTFd flag — if we crash
            // between these steps, ctfd_flag_id stays NULL and cleanup skips delete_flag.
            crate::db::insert_instance(
                db, challenge_name, team_id, user_id, &container_id,
                public_host, host_port as i64, &connection, &expires_at,
                flag.as_deref(), None, extra_ports.as_deref(),
            )?;

            if let (Some(f), Some(cid)) = (&flag, ctfd_id) {
                if let Some(flag_id) = crate::ctfd_db::create_flag(ctfd_pool, cid, f).await {
                    crate::db::set_ctfd_flag_id(db, challenge_name, team_id, flag_id)?;
                }
            }

            Ok((public_host.to_string(), host_port, connection, expires_at))
        }
        "compose" => {
            let compose_file_str = config["compose_file"].as_str().unwrap_or("docker-compose.yml");
            // Resolve compose path: absolute paths used as-is; relative paths resolved
            // against the server-side challenge directory /data/challenges/<name>/
            let compose_path = if compose_file_str.starts_with('/') {
                std::path::PathBuf::from(compose_file_str)
            } else {
                let base = std::env::var("CHALLENGES_BASE_DIR")
                    .unwrap_or_else(|_| "/opt/nervctf/challenges".to_string());
                std::path::PathBuf::from(format!(
                    "{}/{}/{}",
                    base.trim_end_matches('/'),
                    sanitize_name(challenge_name),
                    compose_file_str
                ))
            };
            let compose_service = config["compose_service"].as_str().unwrap_or("");
            let flag_delivery = config["flag_delivery"].as_str().unwrap_or("env");
            let flag_file_path = config["flag_file_path"].as_str();
            let flag_service = config["flag_service"].as_str();
            let project_name = container_name_hint.clone().unwrap_or_else(|| container_name(challenge_name, team_id));
            let used_ports = crate::db::get_used_ports(db)?;
            let flag = generate_flag(config);

            // Build service_mappings and determine primary service + host_port.
            // Path A: service_ports is present — allocate ports per-service.
            // Path B: service_ports absent — wrap existing internal_ports into single-key map.
            let (service_mappings, primary_service, host_port, primary_protocol, all_port_mappings) =
                if let Some(svc_ports_obj) = config["service_ports"].as_object() {
                    // Path A: multi-service port allocation
                    let total_count: usize = svc_ports_obj.values()
                        .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0))
                        .sum();
                    let total_count = total_count.max(1);
                    let host_ports = docker::pick_free_ports(&used_ports, total_count)?;
                    let mut offset = 0usize;
                    let mut map: std::collections::HashMap<String, Vec<(u16, u32, String)>> =
                        std::collections::HashMap::new();
                    let mut all_pairs: Vec<(u16, u32, String)> = Vec::new();
                    for (svc, ports_val) in svc_ports_obj {
                        let iports: Vec<(u32, String)> = ports_val.as_array()
                            .map(|a| a.iter().filter_map(parse_port).collect())
                            .unwrap_or_default();
                        let n = iports.len();
                        let pairs: Vec<(u16, u32, String)> = host_ports[offset..offset + n].iter()
                            .zip(iports.iter())
                            .map(|(&h, (i, proto))| (h, *i, proto.clone()))
                            .collect();
                        all_pairs.extend_from_slice(&pairs);
                        map.insert(svc.clone(), pairs);
                        offset += n;
                    }
                    // Primary service: compose_service if set and present in map, else first key.
                    let primary = if !compose_service.is_empty() && map.contains_key(compose_service) {
                        compose_service.to_string()
                    } else {
                        map.keys().next().cloned().unwrap_or_else(|| "app".to_string())
                    };
                    let (hp, proto) = map.get(&primary).and_then(|v| v.first()).map(|(h, _, p)| (*h, p.clone()))
                        .ok_or_else(|| anyhow!("service_ports: primary service '{}' has no ports", primary))?;
                    (map, primary, hp, proto, all_pairs)
                } else {
                    // Path B: single-service, existing behavior
                    let host_ports = docker::pick_free_ports(&used_ports, port_count)?;
                    let port_mappings: Vec<(u16, u32, String)> = host_ports.iter()
                        .zip(internal_ports.iter())
                        .map(|(&h, (i, proto))| (h, *i, proto.clone()))
                        .collect();
                    let hp = host_ports[0];
                    let proto = port_mappings[0].2.clone();
                    let svc_key = if compose_service.is_empty() { "app" } else { compose_service };
                    let mut map = std::collections::HashMap::new();
                    map.insert(svc_key.to_string(), port_mappings.clone());
                    (map, svc_key.to_string(), hp, proto, port_mappings)
                };

            let team_name = crate::db::get_identity_name(db, team_id, ctfd_mode).unwrap_or(None);
            // The primary service's first port decides the tap's protocol, matching the
            // docker backend. `primary_protocol` is already resolved above.
            let compose_cap_dir = docker::capture_dir(&project_name);
            let tap_spec = tap_enabled(config, challenge_name, &compose_cap_dir, runner_ssh)
                .await
                .then(|| compose::TapSpec {
                    proto: primary_protocol.clone(),
                    capture_dir: compose_cap_dir.clone(),
                    instance_id: project_name.clone(),
                });
            let (_, project) = compose::up(
                &compose_path,
                &project_name,
                &service_mappings,
                &primary_service,
                flag.as_deref(),
                flag_delivery,
                flag_file_path,
                flag_service,
                team_id,
                team_name.as_deref(),
                challenge_name,
                tap_spec,
                loki_url,
                runner_ssh,
            ).await?;

            let extra_ports = build_extra_ports_json(&all_port_mappings);
            let expires_at = expires_at_string(timeout_minutes);
            let connection = effective_connection_type(&connection, &primary_protocol);

            // Write instance to SQLite before creating the CTFd flag — if we crash
            // between these steps, ctfd_flag_id stays NULL and cleanup skips delete_flag.
            crate::db::insert_instance(
                db, challenge_name, team_id, user_id, &project,
                public_host, host_port as i64, &connection, &expires_at,
                flag.as_deref(), None, extra_ports.as_deref(),
            )?;

            if let (Some(f), Some(cid)) = (&flag, ctfd_id) {
                if let Some(flag_id) = crate::ctfd_db::create_flag(ctfd_pool, cid, f).await {
                    crate::db::set_ctfd_flag_id(db, challenge_name, team_id, flag_id)?;
                }
            }

            Ok((public_host.to_string(), host_port, connection, expires_at))
        }
        "lxc" => {
            let lxc_image = config["lxc_image"].as_str().unwrap_or("");
            let cname = container_name(challenge_name, team_id);
            let used_ports = crate::db::get_used_ports(db)?;
            let host_ports = docker::pick_free_ports(&used_ports, port_count)?;
            let port_mappings: Vec<(u16, u32, String)> = host_ports.iter().zip(internal_ports.iter()).map(|(&h, (i, proto))| (h, *i, proto.clone())).collect();
            let host_port = host_ports[0];
            let flag = generate_flag(config);
            let cid = lxc::launch(lxc_image, &cname, &port_mappings, flag.as_deref()).await?;

            let extra_ports = build_extra_ports_json(&port_mappings);
            let expires_at = expires_at_string(timeout_minutes);
            let connection = effective_connection_type(&connection, &port_mappings[0].2);

            // Write instance to SQLite before creating the CTFd flag — if we crash
            // between these steps, ctfd_flag_id stays NULL and cleanup skips delete_flag.
            crate::db::insert_instance(
                db, challenge_name, team_id, user_id, &cid,
                public_host, host_port as i64, &connection, &expires_at,
                flag.as_deref(), None, extra_ports.as_deref(),
            )?;

            if let (Some(f), Some(cid_val)) = (&flag, ctfd_id) {
                if let Some(flag_id) = crate::ctfd_db::create_flag(ctfd_pool, cid_val, f).await {
                    crate::db::set_ctfd_flag_id(db, challenge_name, team_id, flag_id)?;
                }
            }

            Ok((public_host.to_string(), host_port, connection, expires_at))
        }
        "vagrant" => {
            let vagrantfile = config["vagrantfile"].as_str().unwrap_or("");
            let vm_name = container_name(challenge_name, team_id);
            let used_ports = crate::db::get_used_ports(db)?;
            let host_ports = docker::pick_free_ports(&used_ports, port_count)?;
            let port_mappings: Vec<(u16, u32, String)> = host_ports.iter().zip(internal_ports.iter()).map(|(&h, (i, proto))| (h, *i, proto.clone())).collect();
            let host_port = host_ports[0];
            let (_, vm_id) = vagrant::up(vagrantfile, &vm_name, &port_mappings).await?;
            let extra_ports = build_extra_ports_json(&port_mappings);
            let expires_at = expires_at_string(timeout_minutes);
            let connection = effective_connection_type(&connection, &port_mappings[0].2);
            crate::db::insert_instance(
                db, challenge_name, team_id, user_id, &vm_id,
                public_host, host_port as i64, &connection, &expires_at,
                None, None, extra_ports.as_deref(),
            )?;
            Ok((public_host.to_string(), host_port, connection, expires_at))
        }
        other => Err(anyhow!("Unknown backend: {}", other)),
    }
}

/// Parse a config port value into `(port, protocol)`. Accepts an integer (TCP)
/// or a string like `"5390"` (TCP) or `"5390/udp"` (UDP).
pub fn parse_port(v: &Value) -> Option<(u32, String)> {
    if let Some(n) = v.as_u64() {
        return Some((n as u32, "tcp".to_string()));
    }
    if let Some(s) = v.as_str() {
        let (num, proto) = match s.split_once('/') {
            Some((n, p)) => (n.trim(), p.trim()),
            None => (s.trim(), "tcp"),
        };
        if let Ok(port) = num.parse::<u32>() {
            let protocol = if proto.eq_ignore_ascii_case("udp") { "udp" } else { "tcp" }.to_string();
            return Some((port, protocol));
        }
    }
    None
}

/// Build a JSON object `{"<internal>[/udp]": <host>}` for multi-port instances.
/// Returns None for single-port instances (no extra info needed).
fn build_extra_ports_json(port_mappings: &[(u16, u32, String)]) -> Option<String> {
    if port_mappings.len() <= 1 {
        return None;
    }
    let map: serde_json::Map<String, Value> = port_mappings
        .iter()
        .map(|(h, i, proto)| {
            let key = if proto == "udp" { format!("{}/udp", i) } else { i.to_string() };
            (key, serde_json::json!(*h as u64))
        })
        .collect();
    serde_json::to_string(&map).ok()
}

pub fn expires_at_string(timeout_minutes: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH, Duration};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let future = now + Duration::from_secs(timeout_minutes * 60);
    let secs = future.as_secs();
    // Format as SQLite datetime: "YYYY-MM-DD HH:MM:SS"
    let dt = chrono_from_secs(secs);
    dt
}

fn chrono_from_secs(secs: u64) -> String {
    // Manual RFC3339-like formatting without chrono dependency
    let s = secs;
    // days since epoch
    let days = s / 86400;
    let time_of_day = s % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let sec = time_of_day % 60;

    // Gregorian calendar computation
    let (year, month, day) = days_to_ymd(days as u32);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, h, m, sec)
}

fn days_to_ymd(days: u32) -> (u32, u32, u32) {
    // Days since Unix epoch (1970-01-01) to (year, month, day)
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod capture_mode_tests {
    use super::{capture_mode, CaptureMode};
    use serde_json::json;

    #[test]
    fn legacy_log_proxy_true_resolves_to_tap() {
        // The migration contract: existing challenge.yml files that opted into the old
        // HTTP proxy get the tap, with no edit.
        assert_eq!(
            capture_mode(&json!({"log_proxy": true, "connection": "http"})),
            CaptureMode::Tap
        );
    }

    #[test]
    fn legacy_log_proxy_is_no_longer_gated_on_http() {
        // The old gate was `connection == "http" && log_proxy`, so an nc challenge that
        // asked for logging silently got nothing. The tap is protocol-agnostic.
        for conn in ["nc", "ssh", "udp", "tcp", ""] {
            assert_eq!(
                capture_mode(&json!({"log_proxy": true, "connection": conn})),
                CaptureMode::Tap,
                "connection: {:?} should still be captured",
                conn
            );
        }
    }

    #[test]
    fn neither_field_means_no_capture() {
        // Default must leave the data path of every instance that never opted in
        // exactly as it was.
        assert_eq!(capture_mode(&json!({"connection": "nc"})), CaptureMode::Off);
        assert_eq!(
            capture_mode(&json!({"log_proxy": false, "connection": "http"})),
            CaptureMode::Off
        );
        assert_eq!(capture_mode(&json!({})), CaptureMode::Off);
    }

    #[test]
    fn explicit_capture_wins_over_log_proxy() {
        assert_eq!(
            capture_mode(&json!({"capture": "off", "log_proxy": true})),
            CaptureMode::Off
        );
        assert_eq!(
            capture_mode(&json!({"capture": "tap", "log_proxy": false})),
            CaptureMode::Tap
        );
    }

    #[test]
    fn unsupported_mode_degrades_to_off_rather_than_guessing() {
        // A config_json written by a newer CLI (e.g. `pcap`) must not silently become a
        // tap — that would put a relay in a path the operator asked to keep clear.
        assert_eq!(capture_mode(&json!({"capture": "pcap"})), CaptureMode::Off);
        assert_eq!(capture_mode(&json!({"capture": "wat"})), CaptureMode::Off);
        assert_eq!(
            capture_mode(&json!({"capture": "pcap", "log_proxy": true})),
            CaptureMode::Off
        );
    }
}
