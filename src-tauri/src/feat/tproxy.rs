//! Linux-only TPROXY transparent proxy.
//!
//! The Verge toggle only opens `tproxy-port` in the Mihomo config
//! ([`crate::enhance::tproxy::use_tproxy`]); without kernel rules nothing is
//! diverted, so this module installs and removes the iptables/policy-routing
//! rules (the embedded `tproxy.sh`) that actually make this machine's and the
//! LAN's traffic flow through the Core.
//!
//! The rules are root-owned kernel state, so they are applied through the same
//! graphical elevation helper the service installer uses ([`linux_elevator`]),
//! and they do not survive a reboot: the app re-applies them at startup while
//! the toggle stays on. Because the local-traffic rules exclude the Core by
//! uid, and the Core's uid depends on the running mode (service or sidecar),
//! every Core start re-applies them ([`crate::core::CoreManager::core_started`]);
//! on the way out they are removed again so a dead app cannot blackhole traffic.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use clash_verge_logging::{Type, logging};
use tokio::time::sleep;

use crate::{
    config::Config,
    constants,
    core::{CoreManager, handle, manager::RunningMode},
    utils::{dirs, help::linux_elevator},
};

/// The rule script, embedded at build time and written to the app data dir on demand.
const TPROXY_SCRIPT: &str = include_str!("../../assets/tproxy.sh");

/// How long a user gets to answer the elevation prompt before the toggle fails.
const ELEVATION_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the toggle takes the transparent proxy, decided before the Core restarts
/// so rules and listener are never out of sync for long.
#[derive(Clone, Copy, Debug)]
pub enum RulesReconcile {
    /// Rules must point at this TPROXY port.
    Enable(u16),
    /// Rules must be removed.
    Disable,
}

/// Install (or refresh) the rules for `tproxy_port`.
pub async fn rules_enable(tproxy_port: u16) -> Result<()> {
    run_script("enable", tproxy_port).await
}

/// Remove the rules.
pub async fn rules_disable() -> Result<()> {
    run_script("disable", 0).await
}

/// Best-effort rules removal for the exit path, which cannot do anything with
/// an error but log it. The stale-rules probe avoids popping an elevation
/// prompt on exits where the kernel state is already clean.
pub async fn tproxy_rules_disabled_cleanup() -> Result<()> {
    if !stale_rules_present() {
        return Ok(());
    }
    rules_disable().await
}

/// Align the rules with a committed toggle value, e.g. after the port dialog saves.
pub async fn reconcile_tproxy_rules(enabled: bool, tproxy_port: u16) -> Result<()> {
    if enabled {
        rules_enable(tproxy_port).await
    } else {
        rules_disable().await
    }
}

/// Re-apply the rules at startup: iptables state does not survive a reboot, but
/// it does survive a crash, so a leftover rule set must be removed even while the
/// toggle is off - otherwise a killed app blackholes the machine's traffic.
///
/// Both the startup path and the [`crate::core::CoreManager::core_started`] hook
/// call this, so a short debounce collapses the back-to-back calls into a single
/// elevation prompt.
pub async fn reconcile_startup_tproxy_rules() {
    const DEBOUNCE: Duration = Duration::from_secs(5);
    static LAST_APPLY_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0);
    let last_ms = LAST_APPLY_MS.load(std::sync::atomic::Ordering::Acquire);
    if now_ms.saturating_sub(last_ms) < DEBOUNCE.as_millis() as u64 {
        return;
    }
    LAST_APPLY_MS.store(now_ms, std::sync::atomic::Ordering::Release);

    let verge = Config::verge().await.data_arc();
    let enabled = verge.verge_tproxy_enabled.unwrap_or(false);
    if !enabled {
        // A crash or `kill -9` leaves the kernel rules behind, which keeps
        // blackholing traffic after the app is gone. Only ask for elevation
        // when the policy-routing fingerprint of our rules is really present,
        // so an ordinary start never pops an elevation prompt for nothing.
        if stale_rules_present() {
            logging!(warn, Type::Setup, "removing stale TPROXY rules left by a previous run");
            if let Err(error) = rules_disable().await {
                logging!(error, Type::Setup, "failed to remove stale TPROXY rules: {error:#}");
            }
        }
        return;
    }
    let port = verge
        .verge_tproxy_port
        .unwrap_or(constants::network::ports::DEFAULT_TPROXY);
    if let Err(error) = rules_enable(port).await {
        logging!(
            error,
            Type::Setup,
            "failed to restore TPROXY rules at startup: {error:#}"
        );
    }
}

async fn run_script(action: &str, tproxy_port: u16) -> Result<()> {
    let script = write_script().await?;
    let args = [
        action,
        &format!("{:#x}", constants::tproxy::MARK),
        &constants::tproxy::TABLE.to_string(),
        &constants::tproxy::PREF.to_string(),
        &tproxy_port.to_string(),
        &constants::tproxy::DNS_PORT.to_string(),
        &core_uid(),
    ];

    let output = if running_as_root() {
        let mut command = StdCommand::new("bash");
        command.arg(&script).args(args).stdin(Stdio::null());
        run_elevated(&mut command).await?
    } else {
        run_with_elevation(&script, &args).await?
    };

    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let code = output.status.code();
        let stderr = stderr.trim();
        bail!("TPROXY rules {action} failed (exit {code:?}): {stderr}");
    }
    let stderr = stderr.trim();
    logging!(
        info,
        Type::Core,
        "TPROXY rules {action}ed for port {tproxy_port}: {stderr}"
    );
    Ok(())
}

/// Whether our policy-routing rules are still installed. `ip rule` works
/// unprivileged, so this never asks for elevation.
///
/// iproute2 prints a rule as `<pref>: from all fwmark 0xff lookup 100`, so the
/// fwmark (hex) and the table id must sit on one line. Only the routing piece is
/// probed: reading iptables/nftables needs root, and the local route cannot be
/// left behind without the rule anyway.
#[cfg(target_os = "linux")]
fn stale_rules_present() -> bool {
    let mark = constants::tproxy::MARK;
    let table = constants::tproxy::TABLE;
    // iproute2 prints the mark in hex (`fwmark 0xff`); accept the decimal form
    // too so a formatting change cannot hide a stale rule set.
    let matches = |line: &str| {
        (line.contains(&format!("fwmark {mark:#x} lookup {table}"))
            || line.contains(&format!("fwmark {mark} lookup {table}")))
    };
    StdCommand::new("ip")
        .arg("rule")
        .stdin(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).lines().any(matches))
        .unwrap_or(false)
}

/// The uid the Core runs as, so the local-traffic rules can exclude it.
///
/// In service mode the root-owned systemd service starts the Core, which makes
/// its sockets identifiable as uid 0. A sidecar Core runs as this desktop user,
/// the same uid as every other application, so it cannot be excluded without
/// also exempting all of them; an empty value tells the script to install the
/// LAN rules only and warn instead.
fn core_uid() -> String {
    if matches!(*CoreManager::global().get_running_mode(), RunningMode::Service) {
        return "0".to_owned();
    }
    String::new()
}

/// Run `command` and return its output, failing loudly on a stuck elevation prompt.
///
/// `std::process` on purpose: the workspace Tokio build does not guarantee the
/// `process` feature, and the elevation prompt can outlive the child, so the
/// timeout is enforced by polling `try_wait` instead of blocking on the child.
async fn run_elevated(command: &mut StdCommand) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn TPROXY rules script")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to wait for TPROXY rules script")? {
            let stdout = drain_pipe(child.stdout.take());
            let stderr = drain_pipe(child.stderr.take());
            return Ok(Output {
                status,
                stdout: stdout.into_bytes(),
                stderr: stderr.into_bytes(),
            });
        }
        if started.elapsed() > ELEVATION_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "TPROXY rules took more than {}s to apply; the elevation prompt may have been ignored",
                ELEVATION_TIMEOUT.as_secs()
            );
        }
        sleep(Duration::from_millis(200)).await;
    }
}

fn drain_pipe<R: Read>(pipe: Option<R>) -> String {
    let mut buffer = String::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.read_to_string(&mut buffer);
    }
    buffer
}

/// Run the script through pkexec (falling back to sudo), mirroring the service installer.
async fn run_with_elevation(script: &Path, args: &[&str]) -> Result<Output> {
    let elevator = linux_elevator();
    let mut command = StdCommand::new(&elevator);
    command
        .arg("--disable-internal-agent")
        .arg("bash")
        .arg(script)
        .args(args)
        .stdin(Stdio::null());
    let output = run_elevated(&mut command).await?;

    // pkexec fails fast when no graphical agent answers; sudo is the fallback there.
    if !output.status.success() && elevator.contains("pkexec") {
        logging!(
            warn,
            Type::Core,
            "pkexec failed (exit {:?}), falling back to sudo",
            output.status.code()
        );
        let mut command = StdCommand::new("sudo");
        command.arg("bash").arg(script).args(args).stdin(Stdio::null());
        return run_elevated(&mut command).await;
    }
    Ok(output)
}

/// Persist the embedded script so the elevation helper can execute it.
async fn write_script() -> Result<PathBuf> {
    let path = dirs::app_home_dir()?.join("tproxy.sh");
    tokio::fs::write(&path, TPROXY_SCRIPT)
        .await
        .with_context(|| format!("failed to write TPROXY rules script to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .await
            .with_context(|| format!("failed to make TPROXY rules script executable at {}", path.display()))?;
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    tauri_plugin_clash_verge_sysinfo::is_current_app_handle_admin(handle::Handle::app_handle())
}
