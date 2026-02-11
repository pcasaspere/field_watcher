use pcap::{Capture, Device};
use etherparse::{PacketHeaders, NetHeaders, LinkHeader, EtherType, TransportHeader, Icmpv6Type};
use crate::domain::models::Asset;
use chrono::Utc;
use tracing::{warn, error, info};
use mac_oui::Oui;
use tokio::sync::mpsc;

pub struct Sniffer {
    interface: String,
    oui_db: Option<Oui>,
}

#[derive(Debug)]
struct RawDiscovery {
    mac: String,
    ip: String,
    method: String,
    hostname: Option<String>,
    vlan_id: u16,
}

impl Sniffer {
    pub fn new(interface: String) -> Self {
        let oui_db = match Oui::default() {
            Ok(db) => Some(db),
            Err(e) => {
                warn!("Failed to load OUI database: {}", e);
                None
            }
        };
        Sniffer { interface, oui_db }
    }

    fn is_private_ip(ip: &[u8]) -> bool {
        if ip.len() == 4 {
            match ip {
                [10, _, _, _] => true,
                [172, b, _, _] if *b >= 16 && *b <= 31 => true,
                [192, 168, _, _] => true,
                [169, 254, _, _] => true,
                _ => false,
            }
        } else if ip.len() == 16 {
            ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80 || (ip[0] & 0xfe) == 0xfc
        } else {
            false
        }
    }

    fn get_vendor(&self, mac: &str) -> Option<String> {
        self.oui_db.as_ref()?.lookup_by_mac(mac).ok().flatten().map(|e| e.company_name.clone())
    }

    pub fn start(self, tx: mpsc::Sender<Asset>) {
        let interface_name = self.interface.clone();
        let device = match Device::list().map(|list| list.into_iter().find(|d| d.name == interface_name)) {
            Ok(Some(d)) => d,
            _ => {
                error!("Device {} not found", interface_name);
                return;
            }
        };

        let mut cap = match Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(1024)
            .buffer_size(2 * 1024 * 1024)
            .immediate_mode(true)
            .open() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open device {}: {}", interface_name, e);
                    return;
                }
            };

        let filter = "arp or ip or ip6 or ether proto 0x88cc or ether proto 0x2000";
        if let Err(e) = cap.filter(filter, true) {
             warn!("Failed to set BPF filter: {}", e);
        }

        info!("Specialized discovery sniffer started on {}", interface_name);

        loop {
            let packet = match cap.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("Capture error: {}", e);
                    break;
                }
            };

            if let Some(discovery) = self.process_packet(&packet.data) {
                let asset = Asset {
                    mac_address: discovery.mac.clone(),
                    ip_address: discovery.ip,
                    hostname: discovery.hostname,
                    vendor: self.get_vendor(&discovery.mac),
                    vlan_id: discovery.vlan_id,
                    discovery_method: discovery.method,
                    first_seen_at: Utc::now(),
                    last_seen_at: Utc::now(),
                };
                
                if let Err(_) = tx.blocking_send(asset) {
                    break; 
                }
            }
        }
    }

    fn process_packet(&self, data: &[u8]) -> Option<RawDiscovery> {
        let value = PacketHeaders::from_ethernet_slice(data).ok()?;
        
        let mut vlan_id = 1;
        if let Some(vlan) = value.vlan() {
            use etherparse::VlanHeader::*;
            vlan_id = match vlan {
                Single(v) => v.vlan_id.into(),
                Double(v) => v.outer.vlan_id.into(),
            };
        }

        let Some(link) = value.link else { return None; };
        let LinkHeader::Ethernet2(eth) = link else { return None; };
        
        let src_mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
            eth.source[0], eth.source[1], eth.source[2], eth.source[3], eth.source[4], eth.source[5]);

        // 1. ARP
        if eth.ether_type == EtherType::ARP && data.len() >= 42 {
            let psrc = &data[28..32];
            if Self::is_private_ip(psrc) {
                return Some(RawDiscovery {
                    mac: src_mac,
                    ip: format!("{}.{}.{}.{}", psrc[0], psrc[1], psrc[2], psrc[3]),
                    method: "ARP".to_string(),
                    hostname: None,
                    vlan_id,
                });
            }
        }

        // 2. IPv6 / NDP
        if let Some(NetHeaders::Ipv6(ip6, _)) = &value.net {
            if let Some(TransportHeader::Icmpv6(icmp6)) = &value.transport {
                match icmp6.icmp_type {
                    Icmpv6Type::NeighborSolicitation | Icmpv6Type::NeighborAdvertisement(_) | Icmpv6Type::RouterAdvertisement(_) => {
                        return Some(RawDiscovery {
                            mac: src_mac,
                            ip: format!("{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}", 
                                ip6.source[0], ip6.source[1], ip6.source[2], ip6.source[3],
                                ip6.source[4], ip6.source[5], ip6.source[6], ip6.source[7],
                                ip6.source[8], ip6.source[9], ip6.source[10], ip6.source[11],
                                ip6.source[12], ip6.source[13], ip6.source[14], ip6.source[15]),
                            method: "NDP".to_string(),
                            hostname: None,
                            vlan_id,
                        });
                    }
                    _ => {}
                }
            }
        }

        // 3. DHCP, DNS, mDNS, LLMNR, NBNS (via UDP)
        if let Some(TransportHeader::Udp(udp)) = &value.transport {
            let mut method = None;
            let mut hostname = None;
            let mut ip = None;

            if let Some(NetHeaders::Ipv4(ipv4, _)) = &value.net {
                ip = Some(format!("{}.{}.{}.{}", ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3]));
                
                match udp.destination_port {
                    67 | 68 => method = Some("DHCP"),
                    53 => method = Some("DNS"),
                    5353 => {
                        method = Some("mDNS");
                        hostname = self.extract_hostname_from_dns(value.payload.slice());
                    }
                    5355 => {
                        method = Some("LLMNR");
                        hostname = self.extract_hostname_from_dns(value.payload.slice());
                    }
                    137 => method = Some("NBNS"),
                    _ => {}
                }
            }

            if let Some(m) = method {
                if let Some(src_ip) = ip {
                    return Some(RawDiscovery {
                        mac: src_mac,
                        ip: src_ip,
                        method: m.to_string(),
                        hostname,
                        vlan_id,
                    });
                }
            }
        }

        // 4. CDP / LLDP
        if eth.ether_type == EtherType(0x88CC) {
            return Some(RawDiscovery {
                mac: src_mac,
                ip: "0.0.0.0".to_string(),
                method: "LLDP".to_string(),
                hostname: None,
                vlan_id,
            });
        }

        None
    }

    fn extract_hostname_from_dns(&self, payload: &[u8]) -> Option<String> {
        if payload.len() < 13 { return None; }
        let mut pos = 12; 
        while pos < payload.len() {
            let len = payload[pos] as usize;
            if len == 0 { break; }
            pos += 1;
            if pos + len <= payload.len() {
                let segment = &payload[pos..pos+len];
                if let Ok(s) = std::str::from_utf8(segment) {
                    if s.len() > 2 && s.chars().all(|c| c.is_alphanumeric() || c == '-') {
                        return Some(s.to_string());
                    }
                }
                pos += len;
            } else { break; }
        }
        None
    }
}
