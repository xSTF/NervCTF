//! Docker Compose backend for instance provisioning.
//!
//! In split-machine mode (`runner_ssh_target` is set), all compose commands and
//! file writes happen on the remote runner host via SSH.  The monitor never
//! touches the local Docker daemon.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use super::ssh;

/// Return the runner SSH target if configured (split-machine mode).
fn runner_target() -> Option<String> {
    std::env::var("RUNNER_SSH_TARGET").ok()
        .or_else(|| {
            std::env::var("DOCKER_HOST").ok()
                .filter(|h| h.starts_with("ssh://"))
                .map(|h| h.trim_start_matches("ssh://").to_string())
        })
        .filter(|s| !s.is_empty())
}

/// Build a `docker compose` or `docker-compose` command depending on what is available.
///
/// Only used in single-machine mode (no SSH target).
pub async fn compose_cmd() -> tokio::process::Command {
    let available = tokio::process::Command::new("docker")
        .args(["compose", "version"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if available {
        let mut cmd = tokio::process::Command::new("docker");
        cmd.arg("compose");
        cmd
    } else {
        tokio::process::Command::new("docker-compose")
    }
}

/// What a compose project needs in order to front its primary service with an
/// `nervctf-tap` sidecar.
#[derive(Debug, Clone)]
pub struct TapSpec {
    /// `"tcp"` or `"udp"` — the primary port's protocol, so the tap listens on the
    /// right one. A UDP challenge gets a UDP tap.
    pub proto: String,
    /// Host directory bind-mounted into the tap at `/cap`. Created before
    /// `compose up` so Docker does not create it root-owned.
    pub capture_dir: String,
    /// Compose project name, recorded in every capture index entry.
    pub instance_id: String,
}

/// Serializes a value as a YAML double-quoted scalar.
///
/// YAML 1.2 is a superset of JSON and its double-quoted style accepts the same escape
/// sequences, so a JSON string literal is always a safe, correctly-escaped YAML scalar.
///
/// This matters because `team_name` is **player-controlled**: it comes from CTFd's
/// `teams.name`, which players choose themselves (`db::get_identity_name` returns it
/// verbatim). Interpolated raw into the override, a team name containing a newline
/// could inject arbitrary keys into the generated service — `privileged: true`, a
/// `/:/host` bind mount — and escalate a team rename into host access on the runner.
/// The Loki label path already passed it through `sanitize_name`; this path must be
/// just as careful.
fn yaml_quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

/// Renders the `tap:` service for a per-instance compose override.
///
/// Pure so the generated YAML is unit-testable without Docker: this block decides
/// whether a captured compose instance is reachable at all, since the primary
/// service's own `ports:` entry is suppressed in favour of it.
///
/// Every interpolated value is emitted as a quoted scalar, and `environment` uses
/// compose's mapping form rather than `- KEY=value` list entries, so no value can
/// terminate its own line. See `yaml_quote`.
#[allow(clippy::too_many_arguments)]
fn tap_service_block(
    spec: &TapSpec,
    primary_service: &str,
    primary_internal_port: u32,
    host_port: u16,
    team_id: i64,
    team_name: Option<&str>,
    challenge_name: &str,
    loki: &str,
    loki_labels: &str,
) -> String {
    // Compose needs the published port tagged `/udp` for a UDP challenge, or the
    // datagrams never reach the tap.
    let port_spec = if spec.proto == "udp" {
        format!("{}:8080/udp", host_port)
    } else {
        format!("{}:8080", host_port)
    };
    let mut out = String::from("  tap:\n");
    out.push_str(&format!("    image: {}\n", super::docker::TAP_IMAGE));
    // `pull_policy: never` because the image is built locally by the playbook and
    // exists in no registry: without it compose tries Docker Hub when the image is
    // absent and fails with a credentials error that hides the real cause. Callers
    // already skip the sidecar in that case (`tap_enabled`); this keeps a race or a
    // hand-edited override honest about what is wrong.
    out.push_str("    pull_policy: never\n");
    out.push_str("    restart: unless-stopped\n");
    out.push_str("    ports:\n");
    out.push_str(&format!("      - {}\n", yaml_quote(&port_spec)));
    out.push_str("    environment:\n");
    for (key, value) in [
        (
            "UPSTREAM",
            format!("{}:{}", primary_service, primary_internal_port),
        ),
        ("PROTO", spec.proto.clone()),
        ("LISTEN_PORT", "8080".to_string()),
        ("TEAM_ID", team_id.to_string()),
        ("TEAM_NAME", super::strip_control(team_name.unwrap_or(""))),
        ("CHALLENGE_NAME", super::strip_control(challenge_name)),
        ("INSTANCE_ID", super::strip_control(&spec.instance_id)),
        ("CAPTURE_DIR", "/cap".to_string()),
    ] {
        out.push_str(&format!("      {}: {}\n", key, yaml_quote(&value)));
    }
    out.push_str("    volumes:\n");
    out.push_str(&format!(
        "      - {}\n",
        yaml_quote(&format!("{}:/cap", spec.capture_dir))
    ));
    out.push_str("    logging:\n");
    out.push_str("      driver: loki\n");
    out.push_str("      options:\n");
    out.push_str(&format!("        loki-url: {}\n", yaml_quote(loki)));
    out.push_str(&format!(
        "        loki-external-labels: {}\n",
        yaml_quote(loki_labels)
    ));
    out
}

/// Bring up a compose project for a team instance.
///
/// `compose_file`     — path to the docker-compose.yml (on runner in split mode, local otherwise)
/// `project_name`     — unique project name (e.g. ctf-challenge-t42)
/// `service_mappings` — maps each service name to its pre-allocated `[(host_port, internal_port)]`
///                      pairs.  The primary service's first host port is returned to the caller.
/// `primary_service`  — service whose first port is shown to players; empty = "app"
/// `flag`             — optional per-instance flag value
/// `flag_delivery`    — `"env"` (default): FLAG exposed as a compose env var for
///                      `${FLAG}` substitution; `"file"`: flag written to a bind-mounted
///                      file at `flag_file_path` inside `flag_service`
/// `flag_file_path`   — absolute path inside the container (required for `"file"` mode)
/// `flag_service`     — service that receives the flag file mount; defaults to `primary_service`
/// `team_id`/`challenge_name` — passed to the tap sidecar's env (`TEAM_ID`/`CHALLENGE_NAME`)
///                      when `tap` is set; also attached as Loki labels on every
///                      service (see `loki_url`), unused for env otherwise.
/// `team_name`        — team's display name if known (looked up from CTFd's `teams`
///                      table); attached as an extra `team_name` Loki label alongside
///                      `team_id` so Grafana can show/filter by name instead of ID.
/// `tap`              — when set (challenge resolved to `capture: tap`), the primary
///                      service is *not* published directly; instead an `nervctf-tap`
///                      sidecar is published on its host port and relays bytes to the
///                      primary service by compose service-name DNS (the same mechanism
///                      `compose_service` already relies on), recording the raw stream
///                      under `capture_dir` (see `docs/instance-challenges.md`).
/// `loki_url`         — Loki push endpoint for every service's `--log-driver=loki`.
/// `runner_ssh`       — override SSH target; falls back to `runner_target()` if `None`
///
/// Returns `(primary_host_port, container_id_or_project)`.
pub async fn up(
    compose_file: &Path,
    project_name: &str,
    service_mappings: &std::collections::HashMap<String, Vec<(u16, u32, String)>>,
    primary_service: &str,
    flag: Option<&str>,
    flag_delivery: &str,
    flag_file_path: Option<&str>,
    flag_service: Option<&str>,
    team_id: i64,
    team_name: Option<&str>,
    challenge_name: &str,
    tap: Option<TapSpec>,
    loki_url: Option<&str>,
    runner_ssh: Option<&str>,
) -> Result<(u16, String)> {
    let svc_name = if primary_service.is_empty() { "app" } else { primary_service };
    let host_port = service_mappings
        .get(svc_name)
        .and_then(|v| v.first())
        .map(|(h, _, _)| *h)
        .ok_or_else(|| anyhow::anyhow!("service_mappings has no entry for primary service '{}'", svc_name))?;

    let compose_dir = compose_file.parent().unwrap_or(Path::new("."));

    // Images were built with `-p <dir_name>`, so they are tagged `<dir_name>-<service>`.
    // We need `image:` overrides for every such service in the per-instance override file
    // so that Docker Compose uses the pre-built images instead of deriving a per-instance
    // project-based name (`<project>-<service>`) that doesn't exist.
    let challenge_dir_name = compose_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "ctf-challenge".to_string());

    // Resolve SSH target early — needed for both the image query and the compose operations.
    let effective_target = runner_ssh.map(|s| s.to_string()).or_else(runner_target);

    // Query all images on the runner/host that were pre-built for this challenge
    // (tagged `<dir_name>-<service>`).  We only add `image:` overrides for those that
    // actually exist, so public-image services (postgres, redis, …) are left untouched.
    let image_prefix = format!("{}-", challenge_dir_name);
    let pre_built_services: Vec<String> = {
        // `docker images --format '{{.Repository}}'` lists repo names (no tag).
        // We grep for lines starting with the challenge prefix to find all built services.
        let img_cmd = format!(
            "docker images --format '{{{{.Repository}}}}' | grep '^{}' | sort -u",
            image_prefix,
        );
        let raw = if let Some(ref target) = effective_target {
            ssh::output(target, &img_cmd).await.ok()
        } else {
            tokio::process::Command::new("sh")
                .args(["-c", &img_cmd])
                .output()
                .await
                .ok()
        };
        raw.filter(|o| o.status.success())
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter_map(|line| {
                        line.trim()
                            .strip_prefix(&image_prefix)
                            .map(|svc| svc.to_string())
                    })
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    // Determine flag file info up-front so we can embed volumes in the right service block.
    // Returns (host_path, bytes, target_service_name, container_path).
    let flag_info: Option<(String, Vec<u8>, String, String)> = if flag_delivery == "file" {
        match (flag, flag_file_path) {
            (Some(fval), Some(cpath)) => {
                let hp = compose_dir
                    .join(format!("{}.flag", project_name))
                    .display()
                    .to_string();
                let tsvc = flag_service.unwrap_or(svc_name).to_string();
                Some((hp, fval.as_bytes().to_vec(), tsvc, cpath.to_string()))
            }
            _ => None,
        }
    } else {
        None
    };

    // Per-instance compose projects are never joined to the main ctfd stack's network,
    // so the `loki` container-name DNS used by Grafana's datasource doesn't resolve
    // here — this always goes over loopback instead (reachable directly in
    // single-machine mode, or via the primary→runner reverse SSH tunnel in
    // split-machine mode; see the Ansible playbooks).
    let loki = loki_url.unwrap_or("http://127.0.0.1:3100/loki/api/v1/push");
    // Loki's `loki-external-labels` option is a comma-separated `key=val` list — a raw
    // team name containing a comma or `=` would corrupt it, so it's sanitized through
    // the same slug function used for container names.
    let mut loki_labels = format!("team_id={},challenge={}", team_id, challenge_name);
    if let Some(name) = team_name {
        let safe = super::sanitize_name(name);
        if !safe.is_empty() {
            loki_labels.push_str(&format!(",team_name={}", safe));
        }
    }

    // Build the per-instance override YAML.
    //
    // Structure:
    //   1. Main service (svc_name): image + ports + optional flag volume.
    //   2. All other pre-built services: image + optional flag volume.
    //   3. Flag-service stub if it differs from the main service and wasn't pre-built.
    // Every service ships stdout/stderr to Loki with team/challenge labels, so raw logs
    // for any challenge (nc, ssh, …) show up in Grafana filtered by challenge/team. That
    // is container *stdout* only — the request/response bytes come from the tap's capture
    // files, not from here.
    let mut override_content = String::from("services:\n");

    // Helper closure — add image + optional ports/volumes for one service.
    // (Rust closures can't mutate `override_content` from within, so we inline the logic.)
    macro_rules! add_service {
        ($svc:expr) => {
            add_service!($svc, false)
        };
        ($svc:expr, $skip_ports:expr) => {{
            let svc: &str = $svc;
            let skip_ports: bool = $skip_ports;
            override_content.push_str(&format!("  {}:\n    image: {}-{}\n", svc, challenge_dir_name, svc));
            if let Some(mappings) = service_mappings.get(svc) {
                if !mappings.is_empty() && !skip_ports {
                    override_content.push_str("    ports:\n");
                    for (hp, ip, proto) in mappings {
                        let spec = if proto == "udp" {
                            format!("{}:{}/udp", hp, ip)
                        } else {
                            format!("{}:{}", hp, ip)
                        };
                        override_content.push_str(&format!("      - \"{}\"\n", spec));
                    }
                }
            }
            if let Some((ref hp, _, ref tsvc, ref cp)) = flag_info {
                if tsvc.as_str() == svc {
                    override_content.push_str(&format!(
                        "    volumes:\n      - {}:{}:ro\n",
                        hp, cp
                    ));
                }
            }
            override_content.push_str(&format!(
                "    logging:\n      driver: loki\n      options:\n        loki-url: \"{}\"\n        loki-external-labels: \"{}\"\n",
                loki, loki_labels,
            ));
        }};
    }

    // Main service first so any appended lines land in the right block. When a tap
    // sidecar fronts this instance, the primary service is not published directly —
    // only the sidecar (added below) is.
    add_service!(svc_name, tap.is_some());

    // All other pre-built services.
    for svc in &pre_built_services {
        if svc.as_str() == svc_name {
            continue;
        }
        add_service!(svc.as_str());
    }

    // If the flag service is neither the main service nor a pre-built service,
    // add a minimal stub that carries only the volume mount.
    if let Some((ref hp, _, ref tsvc, ref cp)) = flag_info {
        let tsvc_str = tsvc.as_str();
        if tsvc_str != svc_name && !pre_built_services.iter().any(|s| s.as_str() == tsvc_str) {
            override_content.push_str(&format!(
                "  {}:\n    volumes:\n      - {}:{}:ro\n    logging:\n      driver: loki\n      options:\n        loki-url: \"{}\"\n        loki-external-labels: \"{}\"\n",
                tsvc_str, hp, cp, loki, loki_labels,
            ));
        }
    }

    // Tap sidecar: published on the primary service's host port, relaying to the
    // primary service by compose's built-in service-name DNS (the same mechanism
    // `compose_service` already relies on for inter-service traffic).
    if let Some(ref spec) = tap {
        let primary_internal_port = service_mappings
            .get(svc_name)
            .and_then(|v| v.first())
            .map(|(_, ip, _)| *ip)
            .unwrap_or(80);
        // Best-effort, exactly as in the docker backend: if this fails (read-only
        // mount, full disk) the tap creates `/cap` itself on startup and Docker creates
        // the host side of the bind mount, so capture still works. Failing the whole
        // `compose up` over a capture directory would let a capture problem take a
        // challenge down, which this design does not allow.
        if let Err(e) =
            super::docker::ensure_dir(&spec.capture_dir, effective_target.as_deref()).await
        {
            tracing::warn!(
                "compose: could not pre-create capture dir {} ({}); the tap will create it",
                spec.capture_dir,
                e
            );
        }
        override_content.push_str(&tap_service_block(
            spec,
            svc_name,
            primary_internal_port,
            host_port,
            team_id,
            team_name,
            challenge_name,
            loki,
            &loki_labels,
        ));
    }

    let flag_file_content: Option<(String, Vec<u8>)> =
        flag_info.map(|(hp, bytes, _, _)| (hp, bytes));

    let override_path = compose_dir.join(format!("{}.override.yml", project_name));
    let compose_file_str = compose_file.to_str().unwrap();
    let override_path_str = override_path.display().to_string();

    if let Some(ref target) = effective_target {
        // ── Split-machine mode: all writes and compose commands happen on the runner ──

        // Write flag file to runner
        if let Some((ref path, ref content)) = flag_file_content {
            ssh::write_file(target, path, content).await
                .with_context(|| format!("write flag file to runner: {}", path))?;
        }

        // Write override YAML to runner
        ssh::write_file(target, &override_path_str, override_content.as_bytes()).await
            .with_context(|| format!("write compose override to runner: {}", override_path_str))?;

        // Build the remote compose command — all path values are shell-quoted.
        let flag_env = if flag_delivery != "file" {
            flag.map(|f| format!("FLAG={} ", ssh::shell_quote(f)))
                .unwrap_or_default()
        } else {
            String::new()
        };

        let compose_dir_q = ssh::shell_quote(&compose_dir.display().to_string());
        let compose_file_q = ssh::shell_quote(compose_file_str);
        let override_path_q = ssh::shell_quote(&override_path_str);
        let project_name_q = ssh::shell_quote(project_name);

        let remote_cmd = format!(
            "cd {} && {}DOCKER_BUILDKIT=1 docker compose -f {} -f {} -p {} up -d --force-recreate",
            compose_dir_q,
            flag_env,
            compose_file_q,
            override_path_q,
            project_name_q,
        );

        let status = ssh::status(target, &remote_cmd).await
            .with_context(|| "failed to ssh to runner for docker compose up")?;

        if !status.success() {
            // Clean up override on runner (best effort)
            let _ = ssh::status(target, &format!("rm -f {}", ssh::shell_quote(&override_path_str))).await;
            return Err(anyhow!("docker compose up failed for project {} (on runner)", project_name));
        }
    } else {
        // ── Single-machine mode: local execution ──

        if !compose_file.exists() {
            return Err(anyhow!(
                "Compose file not found: {}",
                compose_file.display()
            ));
        }

        // Write flag file locally
        if let Some((ref path, ref content)) = flag_file_content {
            std::fs::write(path, content)?;
        }

        // Write override locally
        std::fs::write(&override_path, &override_content)
            .with_context(|| format!("write compose override to {}", override_path.display()))?;

        let mut cmd = compose_cmd().await;
        cmd.args([
            "-f", compose_file_str,
            "-f", override_path_str.as_str(),
            "-p", project_name,
            "up", "-d", "--force-recreate",
        ]);
        cmd.env("DOCKER_BUILDKIT", "1");
        if flag_delivery != "file" {
            if let Some(flag_value) = flag {
                cmd.env("FLAG", flag_value);
            }
        }
        let status = cmd.status().await
            .with_context(|| "failed to spawn docker compose (is docker installed in PATH?)")?;

        if !status.success() {
            let _ = std::fs::remove_file(&override_path);
            return Err(anyhow!("docker compose up failed for project {}", project_name));
        }
    }

    Ok((host_port, project_name.to_string()))
}

/// List compose project names that start with `ctf-` and are currently running.
///
/// Returns `None` if the query fails (SSH error, docker unavailable) so the
/// caller can skip cleanup rather than risk false-positive deletions.
pub async fn list_running_ctf_project_names() -> Option<std::collections::HashSet<String>> {
    let output = if let Some(target) = runner_target() {
        ssh::output(&target, "docker compose ls --format json").await.ok()?
    } else {
        tokio::process::Command::new("docker")
            .args(["compose", "ls", "--format", "json"])
            .output()
            .await
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    Some(
        parsed.as_array()?
            .iter()
            .filter_map(|entry| entry["Name"].as_str().map(String::from))
            .filter(|name| name.starts_with("ctf-"))
            .collect()
    )
}

/// List all compose project names that start with `ctf-` (running or stopped).
/// Used by the background expiry task to detect orphaned projects.
pub async fn list_ctf_projects() -> Vec<String> {
    let output = if let Some(target) = runner_target() {
        ssh::output(&target, "docker compose ls --all --format json").await
    } else {
        tokio::process::Command::new("docker")
            .args(["compose", "ls", "--all", "--format", "json"])
            .output()
            .await
    };

    let bytes = match output {
        Ok(o) if o.status.success() => o.stdout,
        _ => return vec![],
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    parsed.as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|entry| entry["Name"].as_str().map(String::from))
        .filter(|name| name.starts_with("ctf-"))
        .collect()
}

/// Tear down a compose project.
///
/// `runner_ssh`    — override SSH target; falls back to `runner_target()` if `None`
/// `cleanup_dir`   — if provided, removes `<project_name>.override.yml` and
///                   `<project_name>.flag` from this directory after a successful
///                   `docker compose down` (best-effort, errors are ignored)
pub async fn down(
    project_name: &str,
    runner_ssh: Option<&str>,
    cleanup_dir: Option<&Path>,
) -> Result<()> {
    // Resolve which SSH target to use.
    let effective_target = runner_ssh.map(|s| s.to_string()).or_else(runner_target);

    let project_name_q = ssh::shell_quote(project_name);

    let status = if let Some(ref target) = effective_target {
        let remote_cmd = format!("docker compose -p {} down -v", project_name_q);
        ssh::status(target, &remote_cmd).await
            .with_context(|| "failed to ssh to runner for docker compose down")?
    } else {
        compose_cmd().await
            .args(["-p", project_name, "down", "-v"])
            .status()
            .await
            .with_context(|| "failed to spawn docker compose down")?
    };

    if !status.success() {
        return Err(anyhow!("docker compose down failed for project {}", project_name));
    }

    // Best-effort cleanup of per-instance files left on disk.
    if let Some(dir) = cleanup_dir {
        let override_file = dir.join(format!("{}.override.yml", project_name));
        let flag_file = dir.join(format!("{}.flag", project_name));

        if let Some(ref target) = effective_target {
            let override_q = ssh::shell_quote(&override_file.display().to_string());
            let flag_q = ssh::shell_quote(&flag_file.display().to_string());
            let _ = ssh::status(target, &format!("rm -f {} {}", override_q, flag_q)).await;
        } else {
            let _ = std::fs::remove_file(&override_file);
            let _ = std::fs::remove_file(&flag_file);
        }
    }

    Ok(())
}

/// Build images for a compose project on the runner (split mode) or locally.
///
/// `runner_ssh` — explicit SSH target; falls back to `runner_target()` if `None`.
pub async fn build(compose_file: &str, runner_ssh: Option<&str>) -> Result<()> {
    let effective_target = runner_ssh.map(|s| s.to_string()).or_else(runner_target);

    // Derive a stable project name from the compose file's parent directory so that
    // `docker compose build -p <name>` tags images as `<name>-<service>`, matching
    // the `image:` reference written by `up()` into every per-instance override.
    let project_name = Path::new(compose_file)
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| "ctf-challenge".to_string());

    if let Some(ref target) = effective_target {
        let compose_file_q = ssh::shell_quote(compose_file);
        let project_name_q = ssh::shell_quote(&project_name);
        let remote_cmd = format!(
            "DOCKER_BUILDKIT=1 docker compose -f {} -p {} build",
            compose_file_q, project_name_q,
        );
        let out = ssh::output(target, &remote_cmd).await
            .with_context(|| "failed to ssh to runner for docker compose build")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("docker compose build failed for {}: {}", compose_file, stderr.trim()));
        }
    } else {
        let status = compose_cmd().await
            .args(["-f", compose_file, "-p", &project_name, "build"])
            .env("DOCKER_BUILDKIT", "1")
            .status()
            .await
            .with_context(|| "failed to spawn docker compose build")?;
        if !status.success() {
            return Err(anyhow!("docker compose build failed for {}", compose_file));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(proto: &str) -> TapSpec {
        TapSpec {
            proto: proto.to_string(),
            capture_dir: "/var/lib/nervctf-captures/proj-t7".to_string(),
            instance_id: "proj-t7".to_string(),
        }
    }

    fn block(proto: &str) -> String {
        tap_service_block(
            &spec(proto),
            "web",
            8000,
            31337,
            7,
            Some("team_seven"),
            "my-chal",
            "http://127.0.0.1:3100/loki/api/v1/push",
            "team_id=7,challenge=my-chal,team_name=team_seven",
        )
    }

    #[test]
    fn tcp_tap_block_publishes_the_primary_host_port() {
        let b = block("tcp");
        assert!(b.contains("  tap:\n"), "{}", b);
        assert!(b.contains("image: nervctf-tap:latest"), "{}", b);
        assert!(b.contains("- \"31337:8080\""), "{}", b);
        // Relays to the primary service by compose service-name DNS, no scheme.
        assert!(b.contains("UPSTREAM: \"web:8000\""), "{}", b);
        assert!(b.contains("PROTO: \"tcp\""), "{}", b);
        assert!(b.contains("INSTANCE_ID: \"proj-t7\""), "{}", b);
        assert!(b.contains("TEAM_NAME: \"team_seven\""), "{}", b);
        assert!(
            b.contains("- \"/var/lib/nervctf-captures/proj-t7:/cap\""),
            "capture mount must be read-write: {}",
            b
        );
    }

    #[test]
    fn udp_tap_block_tags_the_published_port() {
        let b = block("udp");
        // Without /udp compose publishes TCP and the datagrams never arrive.
        assert!(b.contains("- \"31337:8080/udp\""), "{}", b);
        assert!(b.contains("PROTO: \"udp\""), "{}", b);
    }

    #[test]
    fn player_controlled_team_name_cannot_inject_yaml() {
        // CTFd lets players choose their own team name, and it reaches here verbatim.
        // A newline would otherwise let a team rename add service keys to the override.
        let evil = "pwn\n      privileged: true\n      volumes:\n        - /:/host\n";
        let b = tap_service_block(
            &spec("tcp"), "web", 8000, 31337, 7, Some(evil), "chal",
            "http://loki/push", "team_id=7",
        );
        // The payload may appear *inside* a quoted scalar — that is harmless. What
        // must not happen is it becoming YAML structure of its own, so assert on keys
        // and list entries rather than on the substring.
        for line in b.lines().filter(|l| !l.trim().is_empty()) {
            let t = line.trim_start();
            assert!(
                !t.starts_with("privileged"),
                "injected key became YAML structure: {:?}\n{}",
                line,
                b
            );
            assert!(
                !t.starts_with("- /:/host"),
                "injected list entry became YAML structure: {:?}\n{}",
                line,
                b
            );
            // Every line must still belong to the tap service block.
            assert!(
                line.starts_with("  "),
                "line escaped the service block: {:?}",
                line
            );
        }
        // Exactly the keys this block is supposed to declare, no more.
        let keys: Vec<&str> = b
            .lines()
            .filter(|l| l.starts_with("    ") && !l.starts_with("     "))
            .map(|l| l.trim())
            .collect();
        assert_eq!(
            keys,
            vec![
                "image: nervctf-tap:latest",
                // Never pull: the image is local-only (see tap_service_block).
                "pull_policy: never",
                "restart: unless-stopped",
                "ports:",
                "environment:",
                "volumes:",
                "logging:",
            ],
            "unexpected service keys:\n{}",
            b
        );
        // The name survives as a single-line scalar, control chars removed.
        assert!(
            b.contains("TEAM_NAME: \"pwn      privileged: true      volumes:        - /:/host\""),
            "unexpected TEAM_NAME rendering:\n{}",
            b
        );
    }

    #[test]
    fn quotes_and_backslashes_in_a_team_name_are_escaped() {
        let evil = r#"a" + b\ "c"#;
        let b = tap_service_block(
            &spec("tcp"), "web", 8000, 31337, 7, Some(evil), "chal",
            "http://loki/push", "team_id=7",
        );
        // serde_json escaping keeps the scalar closed; the value round-trips as JSON,
        // which is exactly what a YAML double-quoted scalar accepts.
        let line = b
            .lines()
            .find(|l| l.trim_start().starts_with("TEAM_NAME:"))
            .expect("TEAM_NAME line");
        let rendered = line.trim_start().trim_start_matches("TEAM_NAME: ");
        let parsed: String = serde_json::from_str(rendered).expect("valid quoted scalar");
        assert_eq!(parsed, evil);
    }

    #[test]
    fn capture_dir_is_quoted_too() {
        // Derived from a sanitized project name today, but it is interpolated into a
        // volume entry, so it must not depend on that for safety.
        let s = TapSpec {
            proto: "tcp".to_string(),
            capture_dir: "/caps/a b\n      privileged: true".to_string(),
            instance_id: "p".to_string(),
        };
        let b = tap_service_block(
            &s, "web", 80, 1, 1, None, "c", "http://loki/push", "l",
        );
        assert!(!b.contains("privileged: true\n"), "{}", b);
        for line in b.lines().filter(|l| !l.trim().is_empty()) {
            assert!(line.starts_with("  "), "line escaped: {:?}", line);
        }
    }

    #[test]
    fn tap_block_is_valid_yaml_under_a_services_key() {
        // The block is concatenated into `services:` — indentation errors here break
        // the whole override, not just the tap.
        let doc = format!("services:\n{}", block("tcp"));
        for line in doc.lines().skip(1).filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with("  "),
                "service block line must be indented under `services:`: {:?}",
                line
            );
        }
        assert_eq!(doc.matches("  tap:").count(), 1);
    }

    /// Brings a real two-service compose project up from the generated `tap:` block:
    /// `web` unpublished, the tap published in front of it, reaching `web` by compose
    /// service-name DNS, and recording to a bind-mounted capture directory.
    ///
    /// Ignored by default — needs Docker, `docker compose`, `nervctf-tap:latest` and
    /// `python:3.12-alpine`. Run with:
    ///   `cargo test -p remote-monitor -- --ignored --nocapture compose_tap`
    /// Set `NERVCTF_TEST_CAPTURE_DIR` to a Docker-mountable path.
    ///
    /// The `logging: driver: loki` stanza is stripped before `up`, because the Loki
    /// Docker plugin is installed by the playbook on the deployment hosts and is not
    /// present in a bare test environment. Everything else — indentation, the published
    /// port spec, env, the upstream service DNS name and the capture mount — is exactly
    /// what `up()` writes.
    #[tokio::test]
    #[ignore = "requires Docker + docker compose + nervctf-tap:latest"]
    async fn compose_tap_block_brings_up_a_working_instance() {
        use std::collections::HashSet;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let base_dir = std::env::var("NERVCTF_TEST_CAPTURE_DIR").unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("nervctf-tap-it")
                .display()
                .to_string()
        });
        let proj = format!("nervctf-cit-{}", std::process::id());
        let work = std::path::Path::new(&base_dir).join(&proj);
        let cap = work.join("cap");
        std::fs::create_dir_all(&cap).expect("create capture dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&cap, std::fs::Permissions::from_mode(0o777));
        }

        let host_port = super::super::docker::pick_free_ports(&HashSet::new(), 1)
            .expect("pick port")[0];

        // Base compose file: `web` declares no ports, exactly as `up()` leaves the
        // primary service when a tap fronts it.
        let base_yml = work.join("docker-compose.yml");
        std::fs::write(
            &base_yml,
            "services:\n  web:\n    image: python:3.12-alpine\n    command: python -m http.server 8000\n",
        )
        .expect("write base compose");

        let spec = TapSpec {
            proto: "tcp".to_string(),
            capture_dir: cap.display().to_string(),
            instance_id: proj.clone(),
        };
        let block = tap_service_block(
            &spec, "web", 8000, host_port, 7, Some("team_seven"), "compose-chal",
            "http://127.0.0.1:3100/loki/api/v1/push", "team_id=7,challenge=compose-chal",
        );
        let block = block
            .split("    logging:\n")
            .next()
            .expect("block prefix")
            .to_string();
        let override_yml = work.join("override.yml");
        std::fs::write(&override_yml, format!("services:\n{}", block))
            .expect("write override");

        let compose = |args: Vec<String>| {
            let mut c = tokio::process::Command::new("docker");
            c.arg("compose");
            c.args(args);
            c
        };
        let up = compose(vec![
            "-f".into(), base_yml.display().to_string(),
            "-f".into(), override_yml.display().to_string(),
            "-p".into(), proj.clone(),
            "up".into(), "-d".into(),
        ])
        .output()
        .await
        .expect("compose up");
        assert!(
            up.status.success(),
            "compose up failed: {}\n--- override ---\n{}",
            String::from_utf8_lossy(&up.stderr),
            std::fs::read_to_string(&override_yml).unwrap_or_default()
        );

        // Reach `web` through the tap.
        let mut body = String::new();
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok(mut sock) = tokio::net::TcpStream::connect(("127.0.0.1", host_port)).await {
                if sock.write_all(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").await.is_err() {
                    continue;
                }
                let mut buf = Vec::new();
                if sock.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                    body = String::from_utf8_lossy(&buf).to_string();
                    break;
                }
            }
        }

        // Capture the diagnostics before teardown, so a failure is explainable.
        let logs = compose(vec!["-p".into(), proj.clone(), "logs".into()])
            .output()
            .await
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let index = cap.join("index.jsonl");
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

        let _ = compose(vec![
            "-p".into(), proj.clone(),
            "down".into(), "-v".into(), "--remove-orphans".into(),
        ])
        .output()
        .await;

        assert!(
            body.starts_with("HTTP/1.0 200"),
            "no 200 through the compose tap; body={:?}\n--- compose logs ---\n{}",
            body.chars().take(120).collect::<String>(),
            logs
        );
        assert!(!records.is_empty(), "no close record in {}", index.display());
        let close: serde_json::Value = records
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["ev"] == "close")
            .expect("a close record");
        assert_eq!(close["challenge"], "compose-chal");
        assert_eq!(close["team_name"], "team_seven");
        assert_eq!(close["instance"], proj.as_str());
        assert!(close["bytes_s2c"].as_u64().unwrap_or(0) > 0, "{}", close);

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn unknown_team_name_renders_empty_not_the_word_none() {
        let b = tap_service_block(
            &spec("tcp"), "web", 80, 1234, 7, None, "c",
            "http://loki/push", "team_id=7",
        );
        assert!(b.contains("TEAM_NAME: \"\"\n"), "{}", b);
        assert!(!b.contains("None"), "{}", b);
    }
}
