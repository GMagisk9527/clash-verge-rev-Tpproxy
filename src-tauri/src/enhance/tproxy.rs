//! Linux-only DNS wiring for the TPROXY transparent proxy.

use serde_yaml_ng::{Mapping, Value};

macro_rules! revise {
    ($map: expr, $key: expr, $val: expr) => {
        let ret_key = Value::String($key.into());
        $map.insert(ret_key, Value::from($val));
    };
}

/// While the transparent proxy is on, make Mihomo listen for the DNS that the
/// TPROXY rules redirect (port 53 → `dns.listen`) and answer it with fake-ip,
/// so domain rules keep working on TPROXY traffic that only carries IPs.
///
/// Mirrors [`super::tun::use_tun`]: mutates DNS only while enabling and leaves
/// it alone when disabling, so turning the feature off never surprises the user
/// with a half-restored config.
pub fn use_tproxy(mut config: Mapping, enabled: bool, dns_port: u16) -> Mapping {
    if !enabled {
        return config;
    }

    let dns_key = Value::from("dns");
    let dns_val = config
        .get(&dns_key)
        .and_then(Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    let current_mode = dns_val
        .get(Value::from("enhanced-mode"))
        .and_then(Value::as_str)
        .unwrap_or("fake-ip");

    if current_mode == "fake-ip" || !dns_val.contains_key(Value::from("enhanced-mode")) {
        revise!(dns_val, "enable", true);
        revise!(dns_val, "listen", format!("0.0.0.0:{dns_port}"));

        if !dns_val.contains_key(Value::from("enhanced-mode")) {
            revise!(dns_val, "enhanced-mode", "fake-ip");
        }

        if !dns_val.contains_key(Value::from("fake-ip-range")) {
            revise!(dns_val, "fake-ip-range", "198.18.0.1/16");
        }
    }

    revise!(config, "dns", dns_val);
    config
}