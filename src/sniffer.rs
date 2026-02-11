use pcap::{Capture, Device};
use etherparse::{PacketHeaders, NetHeaders, TransportHeader, EtherType};
use crate::models::{Asset, Connection};
use crate::utils::{TCP_PROTOCOLS, UDP_PROTOCOLS};
use std::collections::{HashMap, HashSet};
use chrono::Utc;
use tracing::{warn, error};
use mac_oui::Oui;

pub struct Sniffer {
    interface: String,
    network: String,
    oui_db: Option<Oui>,
}

impl Sniffer {
    pub fn new(interface: String, network: String) -> Self {
        let oui_db = match Oui::default() {
            Ok(db) => Some(db),
            Err(e) => {
                warn!("Failed to load OUI database: {}", e);
                None
            }
        };
        Sniffer { interface, network, oui_db }
    }

    fn is_private_ip(ip: [u8; 4]) -> bool {
        match ip {
            [10, _, _, _] => true,
            [172, b, _, _] if b >= 16 && b <= 31 => true,
            [192, 168, _, _] => true,
            _ => false,
        }
    }

    fn get_vendor(&self, mac: &str) -> Option<String> {
        self.oui_db.as_ref()?.lookup_by_mac(mac).ok().flatten().map(|e| e.company_name.clone())
    }

    pub fn sniff(&self, timeout_secs: i32) -> (Vec<Asset>, Vec<Connection>) {
        let mut assets: HashMap<String, Asset> = HashMap::new();
        let mut connections: Vec<Connection> = Vec::new();
        let mut seen_connections: HashSet<String> = HashSet::new();

        let device = match Device::list() {
            Ok(devices) => devices.into_iter().find(|d| d.name == self.interface),
            Err(e) => {
                error!("Failed to list devices: {}", e);
                return (vec![], vec![]);
            }
        };

        let device = match device {
            Some(d) => d,
            None => {
                error!("Device {} not found", self.interface);
                return (vec![], vec![]);
            }
        };

        let mut cap = match Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .timeout(timeout_secs * 1000)
            .open() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open device {}: {}", self.interface, e);
                    return (vec![], vec![]);
                }
            };

        let filter = format!("net {}", self.network);
        if let Err(e) = cap.filter(&filter, true) {
             warn!("Failed to set BPF filter '{}': {}", filter, e);
        }

        let start_time = std::time::Instant::now();
        while start_time.elapsed().as_secs() < timeout_secs as u64 {
            let packet = match cap.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("Error capturing packet: {}", e);
                    break;
                }
            };

            match PacketHeaders::from_ethernet_slice(&packet.data) {
                Ok(value) => {
                    // 1. Asset Discovery (ARP)
                    if let Some(link) = value.link {
                        if let etherparse::LinkHeader::Ethernet2(eth) = link {
                            if eth.ether_type == EtherType::ARP {
                                 if packet.data.len() >= 28 + 14 {
                                     let psrc = &packet.data[28+14..32+14];
                                     let hwsrc = &packet.data[22+14..28+14];
                                     let ip_str = format!("{}.{}.{}.{}", psrc[0], psrc[1], psrc[2], psrc[3]);
                                     let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                                        hwsrc[0], hwsrc[1], hwsrc[2], hwsrc[3], hwsrc[4], hwsrc[5]);

                                     if Self::is_private_ip([psrc[0], psrc[1], psrc[2], psrc[3]]) {
                                         let vendor = self.get_vendor(&mac_str);
                                         assets.entry(ip_str.clone()).or_insert(Asset {
                                             ip_address: ip_str,
                                             mac_address: Some(mac_str),
                                             hostname: None,
                                             os_name: None,
                                             vendor,
                                             last_seen_at: Some(Utc::now()),
                                             created_at: Some(Utc::now()),
                                             updated_at: Some(Utc::now()),
                                         });
                                     }
                                 }
                            }
                        }
                    }

                    // 2. Connection Tracking (IP + TCP/UDP/ICMP)
                    if let Some(net) = value.net {
                        if let NetHeaders::Ipv4(ipv4, _) = net {
                            let src_ip = format!("{}.{}.{}.{}", ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3]);
                            let dst_ip = format!("{}.{}.{}.{}", ipv4.destination[0], ipv4.destination[1], ipv4.destination[2], ipv4.destination[3]);
                            
                            let mut proto_str = "UNKNOWN".to_string();
                            let mut src_port = None;
                            let mut dst_port = None;
                            let mut app_str = None;

                            match value.transport {
                                Some(TransportHeader::Tcp(tcp)) => {
                                    if tcp.syn && !tcp.ack {
                                        proto_str = "TCP".to_string();
                                        src_port = Some(tcp.source_port as i32);
                                        dst_port = Some(tcp.destination_port as i32);
                                        app_str = Some(TCP_PROTOCOLS.get(&tcp.destination_port)
                                            .map(|s| s.to_string())
                                            .unwrap_or_else(|| format!("{}/TCP", tcp.destination_port)));
                                    } else {
                                        continue;
                                    }
                                }
                                Some(TransportHeader::Udp(udp)) => {
                                    proto_str = "UDP".to_string();
                                    src_port = Some(udp.source_port as i32);
                                    dst_port = Some(udp.destination_port as i32);
                                    app_str = Some(UDP_PROTOCOLS.get(&udp.destination_port)
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| format!("{}/UDP", udp.destination_port)));
                                }
                                Some(TransportHeader::Icmpv4(_icmp)) => {
                                    proto_str = "ICMP".to_string();
                                    app_str = Some("ICMP".to_string());
                                }
                                _ => continue,
                            }

                            let conn_key = format!("{}-{}-{}-{}", src_ip, dst_ip, proto_str, dst_port.unwrap_or(0));
                            if !seen_connections.contains(&conn_key) {
                                seen_connections.insert(conn_key);
                                connections.push(Connection {
                                    id: None,
                                    datetime: Utc::now(),
                                    source_ip: src_ip,
                                    source_port: src_port,
                                    destination_ip: dst_ip,
                                    destination_port: dst_port,
                                    protocol: proto_str,
                                    application: app_str,
                                    created_at: Some(Utc::now()),
                                    updated_at: Some(Utc::now()),
                                });
                            }
                        }
                    }
                }
                Err(_e) => {}
            }
        }

        (assets.into_values().collect(), connections)
    }
}
