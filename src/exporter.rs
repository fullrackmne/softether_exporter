use crate::softether_reader::SoftEtherReader;
use anyhow::Error;
use hyper::{header::ContentType, mime::{Mime, SubLevel, TopLevel}, server::{Request, Response, Server}, uri::RequestUri};
use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, GaugeVec, register_gauge, register_gauge_vec, TextEncoder};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread;
use std::time::Duration;
use systemstat::{System, Platform};

lazy_static! {
    static ref UP: GaugeVec =
        register_gauge_vec!("softether_up", "The last query is successful.", &["hub"]).unwrap();
    static ref ONLINE: GaugeVec =
        register_gauge_vec!("softether_online", "Hub online.", &["hub"]).unwrap();
    static ref SESSIONS: GaugeVec = 
        register_gauge_vec!("softether_sessions", "Number of sessions.", &["hub"]).unwrap();
    static ref SESSIONS_CLIENT: GaugeVec = 
        register_gauge_vec!("softether_sessions_client", "Number of client sessions.", &["hub"]).unwrap();
    static ref SESSIONS_BRIDGE: GaugeVec = 
        register_gauge_vec!("softether_sessions_bridge", "Number of bridge sessions.", &["hub"]).unwrap();
    static ref USERS: GaugeVec = 
        register_gauge_vec!("softether_users", "Number of users.", &["hub"]).unwrap();
    static ref GROUPS: GaugeVec = 
        register_gauge_vec!("softether_groups", "Number of groups.", &["hub"]).unwrap();
    static ref MAC_TABLES: GaugeVec = 
        register_gauge_vec!("softether_mac_tables", "Number of entries in MAC table.", &["hub"]).unwrap();
    static ref IP_TABLES: GaugeVec = 
        register_gauge_vec!("softether_ip_tables", "Number of entries in IP table.", &["hub"]).unwrap();
    static ref LOGINS: GaugeVec = 
        register_gauge_vec!("softether_logins", "Number of logins.", &["hub"]).unwrap();
    static ref OUTGOING_UNICAST_PACKETS: GaugeVec = 
        register_gauge_vec!("softether_outgoing_unicast_packets", "Outgoing unicast transfer in packets.", &["hub"]).unwrap();
    static ref OUTGOING_UNICAST_BYTES: GaugeVec = 
        register_gauge_vec!("softether_outgoing_unicast_bytes", "Outgoing unicast transfer in bytes.", &["hub"]).unwrap();
    static ref OUTGOING_BROADCAST_PACKETS: GaugeVec = 
        register_gauge_vec!("softether_outgoing_broadcast_packets", "Outgoing broadcast transfer in packets.", &["hub"]).unwrap();
    static ref OUTGOING_BROADCAST_BYTES: GaugeVec = 
        register_gauge_vec!("softether_outgoing_broadcast_bytes", "Outgoing broadcast transfer in bytes.", &["hub"]).unwrap();
    static ref INCOMING_UNICAST_PACKETS: GaugeVec = 
        register_gauge_vec!("softether_incoming_unicast_packets", "Incoming unicast transfer in packets.", &["hub"]).unwrap();
    static ref INCOMING_UNICAST_BYTES: GaugeVec = 
        register_gauge_vec!("softether_incoming_unicast_bytes", "Incoming unicast transfer in bytes.", &["hub"]).unwrap();
    static ref INCOMING_BROADCAST_PACKETS: GaugeVec = 
        register_gauge_vec!("softether_incoming_broadcast_packets", "Incoming broadcast transfer in packets.", &["hub"]).unwrap();
    static ref INCOMING_BROADCAST_BYTES: GaugeVec = 
        register_gauge_vec!("softether_incoming_broadcast_bytes", "Incoming broadcast transfer in bytes.", &["hub"]).unwrap();
    static ref USER_TRANSFER_BYTES: GaugeVec = 
        register_gauge_vec!("softether_user_transfer_bytes", "User transfer in bytes.", &["hub", "user"]).unwrap();
    static ref USER_TRANSFER_PACKETS: GaugeVec = 
        register_gauge_vec!("softether_user_transfer_packets", "User transfer in packets.", &["hub", "user"]).unwrap();
    
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
    static ref SYSTEM_LOAD_AVERAGE: GaugeVec = register_gauge_vec!(
        "system_load_average",
        "Load average over 1, 5, and 15 minutes.",
        &["interval"]
    ).unwrap();
    static ref SYSTEM_UPTIME: Gauge = register_gauge!(
        "system_uptime",
        "System uptime in seconds."
    ).unwrap();
    static ref SYSTEM_BOOT_TIME: Gauge = register_gauge!(
        "system_boot_time",
        "System boot time in UNIX timestamp."
    ).unwrap();
    static ref SYSTEM_NETWORK_PACKETS_IN: GaugeVec = register_gauge_vec!(
        "system_network_packets_in",
        "Number of packets received on the network interface.",
        &["interface"]
    ).unwrap();
    static ref SYSTEM_NETWORK_PACKETS_OUT: GaugeVec = register_gauge_vec!(
        "system_network_packets_out",
        "Number of packets sent from the network interface.",
        &["interface"]
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
        let sleep: u64 = config.sleep.unwrap_or(String::from("500")).parse().unwrap_or(500);
        let hubs = config.hubs;

        let adminpassword = config.adminpassword.unwrap_or(String::from(""));

        let addr = if listen_address.starts_with(":") {
            format!("0.0.0.0{}", listen_address)
        } else {
            String::from(listen_address)
        };

        println!("Server started: {}", addr);

        Server::http(addr)?.handle(move |req: Request, mut res: Response| {
            if req.uri == RequestUri::AbsolutePath("/metrics".to_string()) {
                let sys = System::new();

                if let Ok(load) = sys.load_average() {
                    let cpu_load = load.one; // 1-minute average
                    SYSTEM_CPU_LOAD.set(cpu_load.into());
                }

                if let Ok(mem) = sys.memory() {
                    let memory_usage = (mem.total.as_u64() - mem.free.as_u64()) as f64 / mem.total.as_u64() as f64 * 100.0;
                    SYSTEM_MEMORY_USAGE.set(memory_usage);
                }

                if let Ok(mounts) = sys.mounts() {
                    let total_space: u64 = mounts.iter().map(|m| m.total.as_u64()).sum();
                    let total_free: u64 = mounts.iter().map(|m| m.avail.as_u64()).sum();
                    let disk_usage = (total_space - total_free) as f64 / total_space as f64 * 100.0;
                    SYSTEM_FREE_DISK_SPACE.set(disk_usage);
                }

                if let Ok(load_avg) = sys.load_average() {
                    SYSTEM_LOAD_AVERAGE.with_label_values(&["1_min"]).set(load_avg.one.into());
                    SYSTEM_LOAD_AVERAGE.with_label_values(&["5_min"]).set(load_avg.five.into());
                    SYSTEM_LOAD_AVERAGE.with_label_values(&["15_min"]).set(load_avg.fifteen.into());
                }

                if let Ok(uptime) = sys.uptime() {
                    SYSTEM_UPTIME.set(uptime.as_secs() as f64);
                }
                
                if let Ok(boot_time) = sys.boot_time() {
                    SYSTEM_BOOT_TIME.set(boot_time.unix_timestamp() as f64);
                }
                
                if let Ok(networks) = sys.networks() {
                    for (interface_name, network) in networks.iter() {
                        if let Ok(stats) = sys.network_stats(interface_name) {
                            SYSTEM_NETWORK_PACKETS_IN.with_label_values(&[interface_name]).set(stats.rx_packets as f64);
                            SYSTEM_NETWORK_PACKETS_OUT.with_label_values(&[interface_name]).set(stats.tx_packets as f64);
                        }
                    }
                }            
                
                // Refresh SoftEther metrics for each hub
                for hub in hubs.clone() {
                    let name = hub.name.unwrap_or(String::from(""));
                    let status = match SoftEtherReader::hub_status(&vpncmd, &server, &name, &adminpassword) {
                        Ok(x) => x,
                        Err(x) => {
                            UP.with_label_values(&[&name]).set(0.0);
                            println!("Hub status read failed: {}", x);
                            continue;
                        }
                    };
                
                    UP.with_label_values(&[&name]).set(1.0);
                    ONLINE.with_label_values(&[&name]).set(if status.online { 1.0 } else { 0.0 });
                    SESSIONS.with_label_values(&[&name]).set(status.sessions);
                    SESSIONS_CLIENT.with_label_values(&[&name]).set(status.sessions_client);
                    SESSIONS_BRIDGE.with_label_values(&[&name]).set(status.sessions_bridge);
                    USERS.with_label_values(&[&name]).set(status.users);
                    GROUPS.with_label_values(&[&name]).set(status.groups);
                    MAC_TABLES.with_label_values(&[&name]).set(status.mac_tables);
                    IP_TABLES.with_label_values(&[&name]).set(status.ip_tables);
                    LOGINS.with_label_values(&[&name]).set(status.logins);
                    OUTGOING_UNICAST_PACKETS.with_label_values(&[&name]).set(status.outgoing_unicast_packets);
                    OUTGOING_UNICAST_BYTES.with_label_values(&[&name]).set(status.outgoing_unicast_bytes);
                    OUTGOING_BROADCAST_PACKETS.with_label_values(&[&name]).set(status.outgoing_broadcast_packets);
                    OUTGOING_BROADCAST_BYTES.with_label_values(&[&name]).set(status.outgoing_broadcast_bytes);
                    INCOMING_UNICAST_PACKETS.with_label_values(&[&name]).set(status.incoming_unicast_packets);
                    INCOMING_UNICAST_BYTES.with_label_values(&[&name]).set(status.incoming_unicast_bytes);
                    INCOMING_BROADCAST_PACKETS.with_label_values(&[&name]).set(status.incoming_broadcast_packets);
                    INCOMING_BROADCAST_BYTES.with_label_values(&[&name]).set(status.incoming_broadcast_bytes);
                }                            

                // Gather and encode metrics
                let metric_familys = prometheus::gather();
                let mut buffer = vec![];
                encoder.encode(&metric_familys, &mut buffer).unwrap();
                res.headers_mut().set(ContentType(encoder.format_type().parse::<Mime>().unwrap()));
                res.send(&buffer).unwrap();
            } else {
                // Landing page response
                res.headers_mut().set(ContentType(Mime(TopLevel::Text, SubLevel::Html, vec![])));
                res.send(LANDING_PAGE.as_bytes()).unwrap();
            }

            thread::sleep(Duration::from_millis(sleep));
        })?;

        Ok(())
    }
}
