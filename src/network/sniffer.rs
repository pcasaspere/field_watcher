use pcap::{Capture, Device};
use etherparse::{PacketHeaders, NetHeaders, LinkHeader, EtherType};
use crate::domain::models::Asset;
use std::collections::HashMap;
use chrono::Utc;
use tracing::{warn, error, debug};
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

    pub fn sniff(&self, timeout_secs: i32) -> Vec<Asset> {
        let mut assets: HashMap<String, Asset> = HashMap::new();

        let device = match Device::list() {
            Ok(devices) => devices.into_iter().find(|d| d.name == self.interface),
            Err(e) => {
                error!("Failed to list devices: {}", e);
                return vec![];
            }
        };

        let device = match device {
            Some(d) => d,
            None => {
                error!("Device {} not found", self.interface);
                return vec![];
            }
        };

        let mut cap = match Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(128) // We only need headers for discovery, keep it light
            .timeout(timeout_secs * 1000)
            .open() {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to open device {}: {}", self.interface, e);
                    return vec![];
                }
            };

        // For discovery on SPAN ports, we want ARP and any IP traffic to map MAC->IP
        let filter = format!("arp or (ip and net {})", self.network);
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

            if let Ok(value) = PacketHeaders::from_ethernet_slice(&packet.data) {
                let mut mac_opt = None;
                let mut ip_opt = None;

                // 1. Extract MAC from Ethernet Header
                if let Some(LinkHeader::Ethernet2(eth)) = value.link {
                    let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                        eth.source[0], eth.source[1], eth.source[2], eth.source[3], eth.source[4], eth.source[5]);
                    
                    // Ignore broadcast/multicast sources
                    if eth.source[0] & 1 == 0 && mac_str != "00:00:00:00:00:00" {
                        mac_opt = Some(mac_str);
                    }

                    // Special case: ARP
                    if eth.ether_type == EtherType::ARP && packet.data.len() >= 42 {
                        let psrc = &packet.data[28..32]; // ARP source IP
                        let hwsrc = &packet.data[22..28]; // ARP source MAC
                        let arp_ip = format!("{}.{}.{}.{}", psrc[0], psrc[1], psrc[2], psrc[3]);
                        let arp_mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                            hwsrc[0], hwsrc[1], hwsrc[2], hwsrc[3], hwsrc[4], hwsrc[5]);
                        
                        if Self::is_private_ip([psrc[0], psrc[1], psrc[2], psrc[3]]) {
                            mac_opt = Some(arp_mac);
                            ip_opt = Some(arp_ip);
                        }
                    }
                }

                // 2. Extract IP from IP Header if not already found by ARP
                if ip_opt.is_none() {
                    if let Some(NetHeaders::Ipv4(ipv4, _)) = value.net {
                        if Self::is_private_ip(ipv4.source) {
                            ip_opt = Some(format!("{}.{}.{}.{}", ipv4.source[0], ipv4.source[1], ipv4.source[2], ipv4.source[3]));
                        }
                    }
                }

                // 3. If we have both, we found/confirmed a host
                if let (Some(mac), Some(ip)) = (mac_opt, ip_opt) {
                    assets.entry(mac.clone()).or_insert_with(|| {
                        let vendor = self.get_vendor(&mac);
                        Asset {
                            mac_address: mac,
                            ip_address: ip,
                            hostname: None,
                            vendor,
                            last_seen_at: Utc::now(),
                        }
                    }).last_seen_at = Utc::now();
                }
            }
        }

        assets.into_values().collect()
    }
}
