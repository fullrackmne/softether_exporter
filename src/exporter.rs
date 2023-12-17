use crate::softether_reader::SoftEtherReader;
use sysinfo::{System, SystemExt, ProcessorExt, DiskExt};
use anyhow::Error;
use hyper::header::ContentType;
use hyper::mime::{Mime, SubLevel, TopLevel};
use hyper::server::{Request, Response, Server};
use hyper::uri::RequestUri;
use lazy_static::lazy_static;
use prometheus;
use prometheus::{register_gauge, register_gauge_vec, Encoder, Gauge, GaugeVec, TextEncoder};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;
use std::thread;

lazy_static! {
    static ref UP: GaugeVec =
        register_gauge_vec!("softether_up", "The last query is successful.", &["hub"]).unwrap();
    static ref ONLINE: GaugeVec =
        register_gauge_vec!("softether_online", "Hub online.", &["hub"]).unwrap();
    static ref SESSIONS: GaugeVec =
        register_gauge_vec!("softether_sessions", "Number of sessions.", &["hub"]).unwrap();
    static ref SESSIONS_CLIENT: GaugeVec = register_gauge_vec!(
        "softether_sessions_client",
        "Number of client sessions.",
        &["hub"]
    ).unwrap();
    static ref SESSIONS_BRIDGE: GaugeVec = register_gauge_vec!(
        "softether_sessions_bridge",
        "Number of bridge sessions.",
        &["hub"]
    ).unwrap();
    static ref USERS: GaugeVec =
        register_gauge_vec!("softether_users", "Number of users.", &["hub"]).unwrap();
    static ref GROUPS: GaugeVec =
        register_gauge_vec!("softether_groups", "Number of groups.", &["hub"]).unwrap();
    static ref MAC_TABLES: GaugeVec = register_gauge_vec!(
        "softether_mac_tables",
        "Number of entries in MAC table.",
        &["hub"]
    ).unwrap();
    static ref IP_TABLES: GaugeVec = register_gauge_vec!(
        "softether_ip_tables",
        "Number of entries in IP table.",
        &["hub"]
    ).unwrap();
    static ref LOGINS: GaugeVec =
        register_gauge_vec!("softether_logins", "Number of logins.", &["hub"]).unwrap();
    static ref OUTGOING_UNICAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_outgoing_unicast_packets",
        "Outgoing unicast transfer in packets.",
        &["hub"]
    ).unwrap();
    static ref OUTGOING_UNICAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_outgoing_unicast_bytes",
        "Outgoing unicast transfer in bytes.",
        &["hub"]
    ).unwrap();
    static ref OUTGOING_BROADCAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_outgoing_broadcast_packets",
        "Outgoing broadcast transfer in packets.",
        &["hub"]
    ).unwrap();
    static ref OUTGOING_BROADCAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_outgoing_broadcast_bytes",
        "Outgoing broadcast transfer in bytes.",
        &["hub"]
    ).unwrap();
    static ref INCOMING_UNICAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_incoming_unicast_packets",
        "Incoming unicast transfer in packets.",
        &["hub"]
    ).unwrap();
    static ref INCOMING_UNICAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_incoming_unicast_bytes",
        "Incoming unicast transfer in bytes.",
        &["hub"]
    ).unwrap();
    static ref INCOMING_BROADCAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_incoming_broadcast_packets",
        "Incoming broadcast transfer in packets.",
        &["hub"]
    ).unwrap();
    static ref INCOMING_BROADCAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_incoming_broadcast_bytes",
        "Incoming broadcast transfer in bytes.",
        &["hub"]
    ).unwrap();
    static ref USER_TRANSFER_BYTES: GaugeVec = register_gauge_vec!(
        "softether_user_transfer_bytes",
        "User transfer in bytes.",
        &["hub", "user"]
    ).unwrap();
    static ref USER_TRANSFER_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_user_transfer_packets",
        "User transfer in packets.",
        &["hub", "user"]
    ).unwrap();

    // System metrics
    static ref SYSTEM_CPU_LOAD: Gauge = register_gauge!(
        "system_cpu_load",
        "Current system CPU load as a percentage."
    ).unwrap();
    static ref SYSTEM_MEMORY_USAGE: Gauge = register_gauge!(
        "system_memory_usage",
        "Used memory in the system as a percentage."
    ).unwrap();
    static ref SYSTEM_FREE_DISK_SPACE: Gauge = register_gauge!(
        "system_free_disk_space",
        "Free disk space on the system as a percentage."
    ).unwrap();
}

static LANDING_PAGE: &'static str = "<html>
<head><title>SoftEther Exporter</title></head>
<body>
<h1>SoftEther Exporter</h1>
<p><a href=\"/metrics\">Metrics</a></p>
</body>
</html>";

static VERSION: &'static str = env!("CARGO_PKG_VERSION");
static GIT_REVISION: Option<&'static str> = option_env!("GIT_REVISION");
static RUST_VERSION: Option<&'static str> = option_env!("RUST_VERSION");

#[derive(Debug, Deserialize)]
pub struct Config {
    vpncmd: Option<String>,
    server: Option<String>,
    sleep: Option<String>,
    adminpassword: Option<String>,
    hubs: Vec<Hub>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Hub {
    name: Option<String>,
    password: Option<String>,
}

impl Config {
    pub fn from_file(file: &Path) -> Result<Config, Error> {
        let mut f = File::open(file)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        let config: Config = toml::from_str(&s)?;
        Ok(config)
    }
}

pub struct Exporter;

impl Exporter {
    pub fn start(config: Config, listen_address: &str, _verbose: bool) -> Result<(), Error> {
        let encoder = TextEncoder::new();
        let vpncmd = config.vpncmd.unwrap_or(String::from("vpncmd"));
        let server = config.server.unwrap_or(String::from("localhost"));
        let sleep: String = config.sleep.unwrap_or(String::from("500"));
        let hubs = config.hubs;

        let adminpassword = config.adminpassword.unwrap_or(String::from(""));

        let addr = if listen_address.starts_with(":") {
            format!("0.0.0.0{}", listen_address)
        } else {
            String::from(listen_address)
        };

        println!("Server started: {}", addr);

        Server::http(addr)?.handle(move |req: Request, mut res: Response| {
            // System metrics update
            let mut sys = System::new_all();
            sys.refresh_all();

            let cpu_usage = sys.global_processor_info().cpu_usage() as f64;
            SYSTEM_CPU_LOAD.set(cpu_usage);

            let total_memory = sys.total_memory();
            let used_memory = sys.used_memory();
            let memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;
            SYSTEM_MEMORY_USAGE.set(memory_usage);

            let total_disk_space = sys.disks().iter().map(|d| d.total_space()).sum::<u64>();
            let total_free_disk_space = sys.disks().iter().map(|d| d.available_space()).sum::<u64>();
            let free_disk_space_percentage = if total_disk_space > 0 {
                (total_free_disk_space as f64 / total_disk_space as f64) * 100.0
            } else {
                0.0
            };
            SYSTEM_FREE_DISK_SPACE.set(free_disk_space_percentage);

            // SoftEther metrics update
            if req.uri == RequestUri::AbsolutePath("/metrics".to_string()) {
                for hub in hubs.clone() {
                    // ... existing SoftEther metrics code ...
                }

                // Metric family gathering and encoding
                let metric_familys = prometheus::gather();
                let mut buffer = vec![];
                encoder.encode(&metric_familys, &mut buffer).unwrap();
                res.headers_mut()
                    .set(ContentType(encoder.format_type().parse::<Mime>().unwrap()));
                res.send(&buffer).unwrap();
            } else {
                res.headers_mut()
                    .set(ContentType(Mime(TopLevel::Text, SubLevel::Html, vec![])));
                res.send(LANDING_PAGE.as_bytes()).unwrap();
            }
        })?;

        Ok(())
    }
}
