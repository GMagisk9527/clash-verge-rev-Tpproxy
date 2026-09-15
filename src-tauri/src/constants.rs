use std::time::Duration;

pub mod network {
    pub const DEFAULT_EXTERNAL_CONTROLLER: &str = "127.0.0.1:9097";

    pub mod ports {
        #[cfg(not(target_os = "windows"))]
        pub const DEFAULT_REDIR: u16 = 7895;
        #[cfg(target_os = "linux")]
        pub const DEFAULT_TPROXY: u16 = 7896;
        pub const DEFAULT_MIXED: u16 = 7897;
        pub const DEFAULT_SOCKS: u16 = 7898;
        pub const DEFAULT_HTTP: u16 = 7899;
    }
}

pub mod timing {
    use super::Duration;

    pub const CONFIG_UPDATE_DEBOUNCE: Duration = Duration::from_millis(300);
    pub const STARTUP_ERROR_DELAY: Duration = Duration::from_secs(2);

    // How long a re-asked staging request is worth waiting for. One that already landed answers in
    // milliseconds; anything slower means the Service is still working, so ReplaceCore beats waiting.
    pub const STAGE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

    // Windows 服务冷启动较慢,避免过早回退 sidecar。
    #[cfg(target_os = "windows")]
    pub const SERVICE_WAIT_MAX: Duration = Duration::from_millis(30000);
    #[cfg(target_os = "windows")]
    pub const SERVICE_WAIT_INTERVAL: Duration = Duration::from_millis(200);

    // 回退 sidecar 后继续等待服务就绪并尝试交接。
    #[cfg(target_os = "windows")]
    pub const SERVICE_HANDOFF_WINDOW: Duration = Duration::from_secs(120);
    #[cfg(target_os = "windows")]
    pub const SERVICE_HANDOFF_INTERVAL: Duration = Duration::from_secs(2);

    // 交接时等待 sidecar 释放 ext-controller 通道。
    #[cfg(target_os = "windows")]
    pub const SERVICE_START_RETRIES: usize = 5;
    #[cfg(target_os = "windows")]
    pub const SERVICE_START_RETRY_DELAY: Duration = Duration::from_millis(300);
}

pub mod files {
    pub const RUNTIME_CONFIG: &str = "clash-verge.yaml";
    pub const CHECK_CONFIG: &str = "clash-verge-check.yaml";
    pub const DNS_CONFIG: &str = "dns_config.yaml";
    pub const WINDOW_STATE: &str = "window_state.json";
}

/// Linux-only TPROXY transparent proxy.
#[cfg(target_os = "linux")]
pub mod tproxy {
    /// fwmark TPROXY sets on diverted packets and the policy-rule matches.
    pub const MARK: u32 = 0xff;

    /// Routing table holding the `local 0.0.0.0/0` route that delivers marked packets to the TPROXY socket.
    pub const TABLE: u32 = 100;

    /// `ip rule` priority, kept apart from the rules other tools install.
    pub const PREF: u32 = 7890;

    /// Mihomo `dns.listen` port that diverted LAN DNS (port 53) is redirected to.
    pub const DNS_PORT: u16 = 1053;
}

pub mod tun {
    pub const DEFAULT_STACK: &str = "gvisor";

    pub const DNS_HIJACK: &[&str] = &["any:53"];
}
