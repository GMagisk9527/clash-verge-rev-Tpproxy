//! Linux-only TPROXY transparent proxy.
//!
//! The Verge toggle only opens `tproxy-port` in the Mihomo config
//! ([`crate::enhance::tproxy::use_tproxy`]); without kernel rules nothing is
//! diverted, so this module installs and removes the iptables/policy-routing
//! rules (the embedded `tproxy.sh`) that actually make LAN traffic flow
//! through the Core.
//!
//! The rules are root-owned kernel state, so they are applied through the same
//! graphical elevation helper the service installer uses ([`linux_elevator`]),
//! and they do not survive a reboot: the app re-applies them at startup while
//! the toggle stays on.

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
    core::handle,
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

/// Align the rules with a committed toggle value, e.g. after the port dialog saves.
pub async fn reconcile_tproxy_rules(enabled: bool, tproxy_port: u16) -> Result<()> {
    if enabled {
        rules_enable(tproxy_port).await
    } else {
        rules_disable().await
    }
}

/// Re-apply the rules at startup: iptables state does not survive a reboot.
pub async fn reconcile_startup_tproxy_rules() {
    let verge = Config::verge().await.data_arc();
    let Some(enabled) = verge.verge_tproxy_enabled else {
        return;
    };
    if !enabled {
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
