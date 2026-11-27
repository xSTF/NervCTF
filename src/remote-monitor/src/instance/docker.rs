//! Docker backend for instance management.
//!
//! When `runner_ssh_target` is provided, all Docker commands execute on the
//! remote runner host via SSH instead of the local daemon.

use anyhow::{anyhow, Result};
use rand::Rng;
use tokio::io::AsyncWriteExt as _;

use super::ssh;

/// `docker run` flags that switch a container's logging driver from the default
/// `json-file` to the `loki` Docker logging-driver plugin, shipping its stdout/stderr
/// straight to Loki with team/challenge labels attached for Grafana to query. Requires
/// `docker plugin install grafana/loki-docker-driver` on whichever host actually runs this
/// container (the primary host in single-machine mode, the runner in split-machine mode —
/// see the Ansible playbooks).
///
/// `team_name`, when known (looked up from CTFd's `teams` table via the local
/// `ctfd_teams` cache), is attached as an extra `team_name` label alongside the numeric
/// `team_id` so the Grafana dashboard can show/filter by team name instead of ID.
/// Sanitized through `super::sanitize_name` since Loki's `loki-external-labels` option
/// is a comma-separated `key=val` list — a raw team name containing a comma or `=`
/// would corrupt it.
pub fn loki_log_args(loki_url: &str, team_id: i64, team_name: Option<&str>, challenge_name: &str) -> Vec<String> {
    let mut labels = format!("team_id={},challenge={}", team_id, challenge_name);
    if let Some(name) = team_name {
        let safe = super::sanitize_name(name);
        if !safe.is_empty() {
            labels.push_str(&format!(",team_name={}", safe));
        }
    }
    vec![
        "--log-driver".to_string(),
        "loki".to_string(),
        "--log-opt".to_string(),
        format!("loki-url={}", loki_url),
        "--log-opt".to_string(),
        format!("loki-external-labels={}", labels),
    ]
}

/// Find a free TCP port in the ephemeral range, avoiding ports already used by running instances.
///
/// Port availability is checked against the DB, not via bind(), because the monitor runs inside
/// a Docker container: bind() checks the container's network namespace, not the host where
/// challenge containers actually publish their ports.
pub fn pick_free_port(used_ports: &std::collections::HashSet<u16>) -> Result<u16> {
    pick_free_ports(used_ports, 1).map(|v| v[0])
}

/// Pick `count` distinct free ports in one call so that all ports for a multi-port instance
/// are allocated atomically — no two of them can collide with each other or with existing
/// instances.
pub fn pick_free_ports(used_ports: &std::collections::HashSet<u16>, count: usize) -> Result<Vec<u16>> {
    if count == 0 {
        return Ok(vec![]);
    }
    let mut rng = rand::thread_rng();
    let mut allocated: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(count);

    for _ in 0..count {
        let mut found = false;
        for _ in 0..500 {
            let port = rng.gen_range(40000u16..60000u16);
            if !used_ports.contains(&port) && !allocated.contains(&port) {
                allocated.insert(port);
                result.push(port);
                found = true;
                break;
            }
        }
        if !found {
            for port in 40000u16..60000u16 {
                if !used_ports.contains(&port) && !allocated.contains(&port) {
                    allocated.insert(port);
                    result.push(port);
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(anyhow!("No free ports available in range 40000-60000"));
        }
    }
    Ok(result)
}

/// Returns the names of all currently running Docker containers.
///
/// Uses `{{.Names}}` format so callers can match against the container name stored
/// in the DB (which is the `--name` value passed to `docker run`, not the hex ID).
///
/// Returns `None` if the query fails so the caller can skip cleanup rather than
/// risk false-positive deletions due to a transient SSH/Docker error.
pub async fn list_running_container_names(runner_ssh: Option<&str>) -> Option<std::collections::HashSet<String>> {
    let cmd = "docker ps --format '{{.Names}}'";
    let output = if let Some(target) = runner_ssh {
        ssh::output(target, cmd).await.ok()?
    } else {
        tokio::process::Command::new("sh")
            .args(["-c", cmd])
            .output()
            .await
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    )
}

/// Run `ssh -o ... <target> <cmd>` and return the output.
async fn ssh_output(target: &str, cmd: &str) -> std::io::Result<std::process::Output> {
    tokio::process::Command::new("ssh")
        .args([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes",
            "-o", "LogLevel=ERROR",
            target,
            cmd,
        ])
        .output()
        .await
}

/// Write `flag_value` to `flag_host_path` on the runner (split mode) or locally (single mode).
///
/// The parent directory is created automatically. This is used when `flag_delivery = "file"`
/// to write the per-team flag to a bind-mount source path before `docker run`.
pub async fn write_flag_file(flag_host_path: &str, flag_value: &str, runner_ssh: Option<&str>) -> Result<()> {
    if let Some(target) = runner_ssh {
        let parent = std::path::Path::new(flag_host_path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("/tmp");
        let mut child = tokio::process::Command::new("ssh")
            .args([
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes",
                target,
                &format!("mkdir -p '{}' && cat > '{}'", parent, flag_host_path),
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("ssh write flag file: {}", e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(flag_value.as_bytes()).await?;
            stdin.shutdown().await?;
        }
        let status = child.wait().await?;
        if !status.success() {
            return Err(anyhow!("ssh write flag file to {} failed", flag_host_path));
        }
    } else {
        if let Some(parent) = std::path::Path::new(flag_host_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow!("create flag dir: {}", e))?;
        }
        std::fs::write(flag_host_path, flag_value.as_bytes())
            .map_err(|e| anyhow!("write flag file {}: {}", flag_host_path, e))?;
    }
    Ok(())
}

/// Start a Docker container and return its **name** (not the Docker hex ID).
///
/// `port_mappings` — list of `(host_port, internal_port)` pairs; each becomes a
/// `-p host:internal` flag.  First entry is the primary port shown to players.
/// `volumes` — list of `(host_path, container_path)` bind mounts added as `-v …:…:ro`.
/// `network` — when set, attaches the container to this user-defined bridge network
///             instead of the default bridge, so sibling containers (e.g. an
///             HTTP-proxy sidecar) can reach it by container name via Docker's
///             embedded DNS. Used for `connection: http` instances (see
///             `create_network`/`remove_network`).
/// `extra_args` — additional raw `docker run` flags inserted before the image tag
///                (e.g. `--log-driver=loki ...` for the proxy sidecar).
pub async fn run_container(
    image_tag: &str,
    container_name: &str,
    port_mappings: &[(u16, u32, String)],
    command: Option<&str>,
    env_vars: &[(String, String)],
    volumes: &[(String, String)],
    network: Option<&str>,
    extra_args: &[String],
    runner_ssh: Option<&str>,
) -> Result<String> {
    let mut docker_args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        container_name.to_string(),
        "--restart=unless-stopped".to_string(),
    ];
    if let Some(net) = network {
        docker_args.push("--network".to_string());
        docker_args.push(net.to_string());
    }
    docker_args.extend_from_slice(extra_args);
    for (hp, ip, proto) in port_mappings {
        docker_args.push("-p".to_string());
        let spec = if proto == "udp" {
            format!("{}:{}/udp", hp, ip)
        } else {
            format!("{}:{}", hp, ip)
        };
        docker_args.push(spec);
    }
    for (k, v) in env_vars {
        docker_args.push("-e".to_string());
        docker_args.push(format!("{}={}", k, v));
    }
    for (host_path, container_path) in volumes {
        docker_args.push("-v".to_string());
        docker_args.push(format!("{}:{}:ro", host_path, container_path));
    }
    docker_args.push(image_tag.to_string());
    if let Some(cmd) = command {
        let words = shlex::split(cmd).unwrap_or_else(|| cmd.split_whitespace().map(String::from).collect());
        docker_args.extend(words);
    }

    let output = if let Some(target) = runner_ssh {
        let remote_cmd = format!("docker {}", shlex::try_join(docker_args.iter().map(|s| s.as_str())).unwrap_or_default());
        ssh_output(target, &remote_cmd).await
            .map_err(|e| anyhow!("ssh docker run failed to spawn: {}", e))?
    } else {
        tokio::process::Command::new("docker")
            .args(&docker_args)
            .output()
            .await
            .map_err(|e| anyhow!("docker run failed to spawn: {}", e))?
    };

    if !output.status.success() {
        return Err(anyhow!(
            "docker run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Return the container name rather than the Docker hex ID so that callers
    // and cleanup routines can derive the flag file path without a separate lookup.
    Ok(container_name.to_string())
}

/// Deterministic per-instance network name for a captured instance, derived from the
/// app container's name so cleanup needs no extra DB state.
pub fn instance_network_name(container_name: &str) -> String {
    format!("{}-net", container_name)
}

/// Deterministic sidecar name for the `nervctf-tap` fronting a captured instance.
pub fn tap_container_name(container_name: &str) -> String {
    format!("{}-tap", container_name)
}

/// Legacy `nervctf-proxy` sidecar name. Only used by cleanup, so an instance
/// provisioned by an older build is still torn down completely after an upgrade.
pub fn legacy_proxy_container_name(container_name: &str) -> String {
    format!("{}-proxy", container_name)
}

/// The tap sidecar image. Built locally by the Ansible playbook
/// (`docker build -t nervctf-tap:latest`) and never published to a registry, so a
/// missing image cannot be recovered by pulling — see `tap_image_available`.
pub const TAP_IMAGE: &str = "nervctf-tap:latest";

/// Whether `TAP_IMAGE` exists on the daemon that will run challenge containers
/// (the runner in split-machine mode, this host otherwise).
///
/// The playbook only builds the image when `nervctf setup` found a `nervctf-tap`
/// binary to ship, so a deployment can legitimately be missing it. Compose and
/// `docker run` would then try to pull `nervctf-tap:latest` from Docker Hub and fail
/// the whole provision with "pull access denied ... repository does not exist", which
/// points at credentials rather than at the real cause. Callers check this first and
/// provision without capture instead.
pub async fn tap_image_available(runner_ssh: Option<&str>) -> bool {
    let output = if let Some(target) = runner_ssh {
        ssh_output(target, &format!("docker image inspect '{}'", TAP_IMAGE)).await
    } else {
        tokio::process::Command::new("docker")
            .args(["image", "inspect", TAP_IMAGE])
            .output()
            .await
    };
    // Treat a failure to even run docker/ssh as "absent": provisioning without capture
    // degrades observability, provisioning with an unverifiable image fails outright.
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Host directory holding `nervctf-tap` captures, mounted into the monitor at the
/// same path so no path translation is needed (same convention as `/tmp/ctf-flags`).
pub fn capture_base_dir() -> String {
    std::env::var("CAPTURE_BASE_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/var/lib/nervctf-captures".to_string())
}

/// Per-instance capture directory. Deliberately *not* removed by `remove_container`:
/// captures are the evidence an integrity review runs on, so they have to outlive the
/// instance. Purging them is a separate retention policy.
pub fn capture_dir(container_name: &str) -> String {
    format!(
        "{}/{}",
        capture_base_dir().trim_end_matches('/'),
        container_name
    )
}

/// `mkdir -p` on whichever host will run the container, so a bind-mounted capture
/// directory exists before `docker run` (Docker would otherwise create it root-owned).
pub async fn ensure_dir(path: &str, runner_ssh: Option<&str>) -> Result<()> {
    if let Some(target) = runner_ssh {
        let output = ssh_output(target, &format!("mkdir -p '{}' && chmod 0777 '{}'", path, path))
            .await
            .map_err(|e| anyhow!("ssh mkdir {}: {}", path, e))?;
        if !output.status.success() {
            return Err(anyhow!(
                "ssh mkdir {} failed: {}",
                path,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    } else {
        std::fs::create_dir_all(path).map_err(|e| anyhow!("create dir {}: {}", path, e))?;
        // The tap container runs as its own uid; 0777 matches the project's existing
        // posture for operator-firewalled, host-local state (see the Grafana/Loki
        // data dirs in the playbook) rather than mapping uids per challenge image.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777));
        }
    }
    Ok(())
}

/// Environment for a tap sidecar fronting `upstream_host:upstream_port`.
///
/// Pure so the exact contract between the monitor and the tap binary is unit-testable:
/// a typo in one of these keys would silently mislabel every capture.
pub fn tap_env(
    upstream_host: &str,
    upstream_port: u32,
    proto: &str,
    team_id: i64,
    team_name: Option<&str>,
    challenge_name: &str,
    instance_id: &str,
) -> Vec<(String, String)> {
    vec![
        // No scheme: the tap is a byte relay, not an HTTP client.
        ("UPSTREAM".to_string(), format!("{}:{}", upstream_host, upstream_port)),
        ("PROTO".to_string(), proto.to_string()),
        ("LISTEN_PORT".to_string(), "8080".to_string()),
        ("TEAM_ID".to_string(), team_id.to_string()),
        // Stripped even though `docker run -e` passes these as argv (no shell, so not
        // injectable here): `team_name` is player-chosen, and a newline in it has no
        // business reaching capture index records.
        ("TEAM_NAME".to_string(), super::strip_control(team_name.unwrap_or(""))),
        ("CHALLENGE_NAME".to_string(), super::strip_control(challenge_name)),
        ("INSTANCE_ID".to_string(), super::strip_control(instance_id)),
        ("CAPTURE_DIR".to_string(), "/cap".to_string()),
    ]
}

/// Extra `docker run` flags for a tap sidecar: its capture directory, read-write.
/// Passed as raw args rather than through `run_container`'s `volumes`, which appends
/// `:ro` — correct for flag files, wrong for a recorder.
pub fn capture_mount_args(host_dir: &str) -> Vec<String> {
    vec!["-v".to_string(), format!("{}:/cap", host_dir)]
}

/// Create a user-defined bridge network for one instance, so the app container and
/// its tap sidecar can reach each other by name. Only used for captured
/// docker-backend instances.
pub async fn create_network(name: &str, runner_ssh: Option<&str>) -> Result<()> {
    let cmd = format!("docker network create '{}'", name);
    let output = if let Some(target) = runner_ssh {
        ssh_output(target, &cmd).await
            .map_err(|e| anyhow!("ssh docker network create failed to spawn: {}", e))?
    } else {
        tokio::process::Command::new("docker")
            .args(["network", "create", name])
            .output()
            .await
            .map_err(|e| anyhow!("docker network create failed: {}", e))?
    };
    if !output.status.success() {
        return Err(anyhow!(
            "docker network create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Remove a per-instance network. Best-effort — safe to call even if it never
/// existed (non-http instances) or still has containers attached mid-teardown.
pub async fn remove_network(name: &str, runner_ssh: Option<&str>) {
    if let Some(target) = runner_ssh {
        let _ = ssh_output(target, &format!("docker network rm '{}'", name)).await;
    } else {
        let _ = tokio::process::Command::new("docker")
            .args(["network", "rm", name])
            .output()
            .await;
    }
}

/// Stop and remove a Docker container, and clean up any flag file written for it.
///
/// `container_id` may be a Docker hex ID or a container name (the latter is stored
/// by `run_container` now).  Both are accepted by `docker stop/rm`.
///
/// If a flag file exists at `/tmp/ctf-flags/{container_id}.flag` (written during
/// file-delivery provisioning) it is removed as a best-effort cleanup.
pub async fn remove_container(container_id: &str, runner_ssh: Option<&str>) -> Result<()> {
    // Best-effort flag file cleanup (no-op if file does not exist).
    let flag_path = format!("/tmp/ctf-flags/{}.flag", container_id);
    if let Some(target) = runner_ssh {
        let _ = ssh_output(target, &format!("rm -f '{}'", flag_path)).await;
    } else {
        let _ = std::fs::remove_file(&flag_path);
    }

    // Best-effort sidecar cleanup. No-op for instances that never had one (names are
    // derived deterministically — see `tap_container_name`/`instance_network_name` — so
    // there's no extra DB state to track whether a given instance was captured).
    // The legacy `-proxy` name is included so instances provisioned by a pre-tap build
    // are still fully removed after an upgrade.
    for sidecar in [
        tap_container_name(container_id),
        legacy_proxy_container_name(container_id),
    ] {
        if let Some(target) = runner_ssh {
            let _ = ssh_output(target, &format!("docker rm -f '{}'", sidecar)).await;
        } else {
            let _ = tokio::process::Command::new("docker")
                .args(["rm", "-f", &sidecar])
                .output()
                .await;
        }
    }
    // Remove the app container *before* its network: Docker refuses to delete a
    // network that still has an attached endpoint. The previous order (network first)
    // meant every captured instance leaked its `<name>-net` network.
    let app_removal: Result<()> = if let Some(target) = runner_ssh {
        // Stop + remove on runner
        let _ = ssh_output(target, &format!("docker stop --time 3 '{}'", container_id)).await;
        match ssh_output(target, &format!("docker rm -f '{}'", container_id)).await {
            Err(e) => Err(anyhow!("ssh docker rm failed: {}", e)),
            Ok(output) if !output.status.success() => Err(anyhow!(
                "docker rm failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Ok(_) => Ok(()),
        }
    } else {
        // Stop with a short grace period (3s) before SIGKILL — best effort
        let _ = tokio::process::Command::new("docker")
            .args(["stop", "--time", "3", container_id])
            .output()
            .await;

        match tokio::process::Command::new("docker")
            .args(["rm", "-f", container_id])
            .output()
            .await
        {
            Err(e) => Err(anyhow!("docker rm failed: {}", e)),
            Ok(output) if !output.status.success() => Err(anyhow!(
                "docker rm failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Ok(_) => Ok(()),
        }
    };

    // Attempted even when the container removal failed, so a partially torn-down
    // instance does not leave the network behind as well. Best-effort by design.
    remove_network(&instance_network_name(container_id), runner_ssh).await;

    app_removal
}

/// Build a Docker image from a tar.gz build context stored on disk.
pub async fn build_image(tar_path: &std::path::Path, image_tag: &str, runner_ssh: Option<&str>) -> Result<()> {
    let output = if let Some(target) = runner_ssh {
        // Pipe the tar through SSH to docker build on the runner
        let tar_file = std::fs::File::open(tar_path).map_err(|e| anyhow!("open tar: {}", e))?;
        tokio::process::Command::new("ssh")
            .args([
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes",
                target,
                &format!("DOCKER_BUILDKIT=1 docker build -t '{}' -", image_tag),
            ])
            .stdin(std::process::Stdio::from(tar_file))
            .output()
            .await
            .map_err(|e| anyhow!("ssh docker build failed: {}", e))?
    } else {
        tokio::process::Command::new("docker")
            .args(["build", "-t", image_tag, "-"])
            .stdin(std::process::Stdio::from(
                std::fs::File::open(tar_path).map_err(|e| anyhow!("open tar: {}", e))?,
            ))
            .output()
            .await
            .map_err(|e| anyhow!("docker build failed: {}", e))?
    };

    if !output.status.success() {
        return Err(anyhow!(
            "docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_and_capture_paths_are_derived_from_the_container_name() {
        assert_eq!(instance_network_name("ctf-web-t7"), "ctf-web-t7-net");
        assert_eq!(tap_container_name("ctf-web-t7"), "ctf-web-t7-tap");
        // Still derivable so an instance from a pre-tap build is fully torn down.
        assert_eq!(legacy_proxy_container_name("ctf-web-t7"), "ctf-web-t7-proxy");
    }

    #[test]
    fn tap_env_matches_the_binary_contract() {
        let env = tap_env("app-c", 4000, "tcp", 42, Some("team_42"), "my-chal", "app-c");
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("missing env var {}", k))
        };
        // No scheme — nervctf-proxy took a URL here; a byte relay must not.
        assert_eq!(get("UPSTREAM"), "app-c:4000");
        assert_eq!(get("PROTO"), "tcp");
        assert_eq!(get("LISTEN_PORT"), "8080");
        assert_eq!(get("TEAM_ID"), "42");
        assert_eq!(get("TEAM_NAME"), "team_42");
        assert_eq!(get("CHALLENGE_NAME"), "my-chal");
        assert_eq!(get("INSTANCE_ID"), "app-c");
        assert_eq!(get("CAPTURE_DIR"), "/cap");
    }

    #[test]
    fn tap_env_tolerates_an_unknown_team_name() {
        let env = tap_env("app-c", 9999, "udp", 1, None, "c", "i");
        assert!(env.iter().any(|(k, v)| k == "TEAM_NAME" && v.is_empty()));
        assert!(env.iter().any(|(k, v)| k == "PROTO" && v == "udp"));
    }

    /// End-to-end exercise of the docker-backend capture path using the real
    /// `create_network` / `run_container` / `remove_container` functions: app container
    /// unpublished on a private network, tap published in front of it, captures landing
    /// on disk, and the whole lot torn down afterwards.
    ///
    /// Ignored by default — needs a working Docker daemon, the `nervctf-tap:latest`
    /// image, and `python:3.12-alpine`. Run with:
    ///   `cargo test -p remote-monitor -- --ignored --nocapture tap_sidecar`
    /// Set `NERVCTF_TEST_CAPTURE_DIR` to a path your Docker daemon can bind-mount
    /// (required on Docker Desktop, where the default temp dir is not shared).
    #[tokio::test]
    #[ignore = "requires Docker + nervctf-tap:latest"]
    async fn tap_sidecar_fronts_a_docker_instance_and_records_it() {
        use std::collections::HashSet;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let base = std::env::var("NERVCTF_TEST_CAPTURE_DIR").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("nervctf-tap-it")
                .display()
                .to_string()
        });
        std::env::set_var("CAPTURE_BASE_DIR", &base);

        let cname = format!("nervctf-it-{}", std::process::id());
        let net = instance_network_name(&cname);
        let tap_name = tap_container_name(&cname);
        let cap = capture_dir(&cname);

        // Clean slate, in case a previous run died mid-test.
        let _ = remove_container(&cname, None).await;

        create_network(&net, None).await.expect("create network");

        // App container: deliberately NO port mappings — exactly how `provision`
        // launches it when a tap is in front, so if the tap is not reachable the
        // instance is not reachable at all and this test fails loudly.
        run_container(
            "python:3.12-alpine",
            &cname,
            &[],
            Some("python -m http.server 4000"),
            &[],
            &[],
            Some(&net),
            &[],
            None,
        )
        .await
        .expect("run app container");

        ensure_dir(&cap, None).await.expect("ensure capture dir");
        let host_port = pick_free_ports(&HashSet::new(), 1).expect("pick port")[0];
        let env = tap_env(&cname, 4000, "tcp", 42, Some("team_42"), "it-chal", &cname);
        let extra = capture_mount_args(&cap);

        run_container(
            "nervctf-tap:latest",
            &tap_name,
            &[(host_port, 8080u32, "tcp".to_string())],
            None,
            &env,
            &[],
            Some(&net),
            &extra,
            None,
        )
        .await
        .expect("run tap sidecar");

        // Reach the app *through* the tap.
        let mut body = String::new();
        let mut last_err = String::new();
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            match tokio::net::TcpStream::connect(("127.0.0.1", host_port)).await {
                Ok(mut sock) => {
                    if sock
                        .write_all(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
                        .await
                        .is_err()
                    {
                        continue;
                    }
                    let mut buf = Vec::new();
                    if sock.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                        body = String::from_utf8_lossy(&buf).to_string();
                        break;
                    }
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        assert!(
            body.starts_with("HTTP/1.0 200"),
            "no 200 through the tap (last connect error: {}); got: {:?}",
            last_err,
            body.chars().take(120).collect::<String>()
        );

        // The session must have been recorded, with the labels the monitor passed in.
        let index = std::path::Path::new(&cap).join("index.jsonl");
        let mut records = String::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(c) = std::fs::read_to_string(&index) {
                if c.contains("\"close\"") {
                    records = c;
                    break;
                }
            }
        }
        assert!(
            !records.is_empty(),
            "no close record in {}",
            index.display()
        );
        let close: serde_json::Value = records
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["ev"] == "close")
            .expect("a close record");
        assert_eq!(close["challenge"], "it-chal");
        assert_eq!(close["team_name"], "team_42");
        assert_eq!(close["team_id"], "42");
        assert_eq!(close["instance"], cname.as_str());
        assert!(
            close["bytes_c2s"].as_u64().unwrap_or(0) > 0
                && close["bytes_s2c"].as_u64().unwrap_or(0) > 0,
            "both directions should have bytes: {}",
            close
        );
        assert_eq!(close["dropped_frames"].as_u64(), Some(0));

        // Teardown must remove the sidecar and the private network too.
        remove_container(&cname, None).await.expect("remove app");
        for name in [&cname, &tap_name] {
            let out = tokio::process::Command::new("docker")
                .args(["inspect", name])
                .output()
                .await
                .expect("docker inspect");
            assert!(!out.status.success(), "{} still exists after teardown", name);
        }
        let out = tokio::process::Command::new("docker")
            .args(["network", "inspect", &net])
            .output()
            .await
            .expect("docker network inspect");
        assert!(!out.status.success(), "network {} still exists", net);
    }

    /// Regression guard for the incident that took six live challenges down.
    ///
    /// The monitor mounted CAPTURE_BASE_DIR read-only, so creating the per-instance
    /// capture directory failed with EROFS and every challenge asking for capture
    /// stopped provisioning. Two facts this pins down:
    ///
    ///   * `ensure_dir` reports the failure rather than hiding it, so the decision to
    ///     degrade can be made *before* the app container's port is withheld.
    ///   * Docker will not rescue a bad mount source: launching the tap against an
    ///     uncreatable directory fails the `docker run` outright, which is why leniency
    ///     at launch time is not a fix.
    #[tokio::test]
    #[ignore = "requires Docker + nervctf-tap:latest"]
    async fn an_unusable_capture_dir_is_detected_before_launch() {
        use std::collections::HashSet;

        let base = std::env::var("NERVCTF_TEST_CAPTURE_DIR").unwrap_or_else(|_| {
            std::env::temp_dir().join("nervctf-tap-it").display().to_string()
        });
        let locked = std::path::Path::new(&base).join("locked-ro");
        let _ = std::fs::create_dir_all(&locked);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
                .expect("lock the dir");
        }
        std::env::set_var("CAPTURE_BASE_DIR", locked.display().to_string());

        let cname = format!("nervctf-ro-{}", std::process::id());
        let cap = capture_dir(&cname);

        // 1. The failure is surfaced, not swallowed — this is what lets `tap_enabled`
        //    choose to provision without capture while the instance is still publishable.
        let pre_create = ensure_dir(&cap, None).await;
        assert!(
            pre_create.is_err(),
            "an unwritable capture dir must be reported so the caller can degrade"
        );

        // 2. Proof that degrading is the only workable response: with the directory
        //    uncreatable, the tap cannot be launched at all.
        let net = instance_network_name(&cname);
        let tap_name = tap_container_name(&cname);
        let _ = remove_container(&cname, None).await;
        create_network(&net, None).await.expect("create network");
        let host_port = pick_free_ports(&HashSet::new(), 1).expect("pick port")[0];
        let launched = run_container(
            TAP_IMAGE,
            &tap_name,
            &[(host_port, 8080u32, "tcp".to_string())],
            None,
            &tap_env(&cname, 4000, "tcp", 1, None, "ro-chal", &cname),
            &[],
            Some(&net),
            &capture_mount_args(&cap),
            None,
        )
        .await;

        let _ = remove_container(&cname, None).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::remove_dir_all(&locked);
        }

        let err = launched.expect_err("the tap must not start with an uncreatable mount source");
        assert!(
            err.to_string().contains("mount source path")
                || err.to_string().to_lowercase().contains("permission denied"),
            "unexpected failure: {}",
            err
        );
    }

    #[test]
    fn capture_mount_is_read_write() {
        // The recorder writes here, so this must NOT carry `:ro` the way the
        // flag-file mounts in `run_container` do.
        let args = capture_mount_args("/var/lib/nervctf-captures/x");
        assert_eq!(args, vec!["-v".to_string(), "/var/lib/nervctf-captures/x:/cap".to_string()]);
        assert!(!args.iter().any(|a| a.ends_with(":ro")));
    }
}
