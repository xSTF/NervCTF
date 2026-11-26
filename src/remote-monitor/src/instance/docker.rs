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

/// Deterministic per-instance network name for an HTTP-proxied instance, derived from
/// the app container's name so cleanup needs no extra DB state.
pub fn proxy_network_name(container_name: &str) -> String {
    format!("{}-net", container_name)
}

/// Deterministic sidecar proxy container name for an HTTP-proxied instance.
pub fn proxy_container_name(container_name: &str) -> String {
    format!("{}-proxy", container_name)
}

/// The log-proxy sidecar image. Built locally by the Ansible playbook
/// (`docker build -t nervctf-proxy:latest`) and never published to a registry, so a
/// missing image cannot be recovered by pulling — see `proxy_image_available`.
pub const PROXY_IMAGE: &str = "nervctf-proxy:latest";

/// Whether `PROXY_IMAGE` exists on the daemon that will run challenge containers
/// (the runner in split-machine mode, this host otherwise).
///
/// The playbook only builds the image when `nervctf setup` found a `nervctf-proxy`
/// binary to ship, so a deployment can legitimately be missing it. Compose and
/// `docker run` would then try to pull `nervctf-proxy:latest` from Docker Hub and fail
/// the whole provision with "pull access denied ... repository does not exist", which
/// points at credentials rather than at the real cause. Callers check this first and
/// skip the sidecar instead.
pub async fn proxy_image_available(runner_ssh: Option<&str>) -> bool {
    let output = if let Some(target) = runner_ssh {
        ssh_output(target, &format!("docker image inspect '{}'", PROXY_IMAGE)).await
    } else {
        tokio::process::Command::new("docker")
            .args(["image", "inspect", PROXY_IMAGE])
            .output()
            .await
    };
    // Treat a failure to even run docker/ssh as "absent": provisioning without the
    // sidecar degrades logging, provisioning with an unverifiable image fails outright.
    output.map(|o| o.status.success()).unwrap_or(false)
}

/// Create a user-defined bridge network for one instance, so the app container and
/// its HTTP-proxy sidecar can reach each other by name. Best-effort: only used for
/// `connection: http` docker-backend instances.
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

    // Best-effort HTTP-proxy sidecar cleanup. No-op for instances that never had one
    // (names derived deterministically — see `proxy_container_name`/`proxy_network_name`
    // — so there's no extra DB state to track whether a given instance used a proxy).
    let proxy_name = proxy_container_name(container_id);
    if let Some(target) = runner_ssh {
        let _ = ssh_output(target, &format!("docker rm -f '{}'", proxy_name)).await;
    } else {
        let _ = tokio::process::Command::new("docker")
            .args(["rm", "-f", &proxy_name])
            .output()
            .await;
    }
    remove_network(&proxy_network_name(container_id), runner_ssh).await;

    if let Some(target) = runner_ssh {
        // Stop + remove on runner
        let _ = ssh_output(target, &format!("docker stop --time 3 '{}'", container_id)).await;
        let output = ssh_output(target, &format!("docker rm -f '{}'", container_id)).await
            .map_err(|e| anyhow!("ssh docker rm failed: {}", e))?;
        if !output.status.success() {
            return Err(anyhow!(
                "docker rm failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    } else {
        // Stop with a short grace period (3s) before SIGKILL — best effort
        let _ = tokio::process::Command::new("docker")
            .args(["stop", "--time", "3", container_id])
            .output()
            .await;

        let output = tokio::process::Command::new("docker")
            .args(["rm", "-f", container_id])
            .output()
            .await
            .map_err(|e| anyhow!("docker rm failed: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "docker rm failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    Ok(())
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
