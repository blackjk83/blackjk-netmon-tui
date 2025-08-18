use pcap::{Capture, Device};
use pnet::packet::{Packet, ethernet::EthernetPacket};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Insufficient privileges. Try: sudo setcap cap_net_raw,cap_net_admin=eip ./network-monitor")]
    InsufficientPrivileges,
    
    #[error("Network interface '{0}' not found. Available interfaces: {1:?}")]
    InterfaceNotFound(String, Vec<String>),
    
    #[error("Packet capture failed: {0}")]
    CaptureError(String),
    
    #[error("Device error: {0}")]
    DeviceError(String),
}

pub struct PacketInfo {
    pub timestamp: std::time::SystemTime,
    pub length: usize,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

pub struct NetworkStats {
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub packets_dropped: u64,
    pub interface: String,
}

pub struct PcapEngine {
    capture: Option<Capture<pcap::Active>>,
    interface: String,
    stats: NetworkStats,
}

impl PcapEngine {
    pub fn new(interface: Option<String>) -> Result<Self, CaptureError> {
        let available_devices = Self::list_devices()?;
        
        let interface = interface.unwrap_or_else(|| {
            // Try to find a suitable default interface
            available_devices.first()
                .map(|d| d.name.clone())
                .unwrap_or_else(|| "any".to_string())
        });
        
        // Validate interface exists
        if !available_devices.iter().any(|d| d.name == interface) && interface != "any" {
            let device_names: Vec<String> = available_devices.iter()
                .map(|d| d.name.clone())
                .collect();
            return Err(CaptureError::InterfaceNotFound(interface, device_names));
        }
        
        println!("Attempting to open capture on interface: {}", interface);
        
        // CRITICAL: Handle permissions gracefully on Rocky Linux
        let device = Device::from(interface.as_str());
        let capture = match Capture::from_device(device) {
            Ok(cap) => {
                match cap.promisc(false).timeout(1000).open() {
                    Ok(active_cap) => Some(active_cap),
                    Err(e) => {
                        eprintln!("Failed to open capture device: {}", e);
                        eprintln!("Try running with sudo or setting capabilities:");
                        eprintln!("sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/network-monitor");
                        return Err(CaptureError::InsufficientPrivileges);
                    }
                }
            },
            Err(e) => {
                return Err(CaptureError::DeviceError(format!("Device error: {}", e)));
            }
        };
        
        let stats = NetworkStats {
            packets_captured: 0,
            bytes_captured: 0,
            packets_dropped: 0,
            interface: interface.clone(),
        };
        
        Ok(PcapEngine {
            capture,
            interface,
            stats,
        })
    }
    
    pub fn list_devices() -> Result<Vec<Device>, CaptureError> {
        Device::list().map_err(|e| CaptureError::DeviceError(format!("Failed to list devices: {}", e)))
    }
    
    pub fn start_capture(&mut self) -> Result<(), CaptureError> {
        if self.capture.is_none() {
            return Err(CaptureError::CaptureError("No capture device available".to_string()));
        }
        
        println!("Starting packet capture on interface: {}", self.interface);
        Ok(())
    }
    
    pub fn get_next_packet(&mut self) -> Result<Option<PacketInfo>, CaptureError> {
        if let Some(ref mut capture) = self.capture {
            match capture.next_packet() {
                Ok(packet) => {
                    self.stats.packets_captured += 1;
                    self.stats.bytes_captured += packet.data.len() as u64;
                    
                    let packet_data = packet.data.to_vec();
                    let packet_info = Self::parse_packet_static(&packet_data);
                    Ok(Some(packet_info))
                },
                Err(pcap::Error::TimeoutExpired) => Ok(None),
                Err(e) => Err(CaptureError::CaptureError(format!("Packet capture error: {}", e))),
            }
        } else {
            Err(CaptureError::CaptureError("No active capture".to_string()))
        }
    }
    
    pub fn get_statistics(&self) -> &NetworkStats {
        &self.stats
    }
    
    fn parse_packet_static(data: &[u8]) -> PacketInfo {
        let timestamp = std::time::SystemTime::now();
        let length = data.len();
        
        // Try to parse as Ethernet frame
        if let Some(ethernet_packet) = EthernetPacket::new(data) {
            match ethernet_packet.get_ethertype() {
                pnet::packet::ethernet::EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                        let src_ip = Some(ipv4_packet.get_source().to_string());
                        let dst_ip = Some(ipv4_packet.get_destination().to_string());
                        
                        match ipv4_packet.get_next_level_protocol() {
                            pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp_packet) = pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()) {
                                    return PacketInfo {
                                        timestamp,
                                        length,
                                        protocol: "TCP".to_string(),
                                        src_ip,
                                        dst_ip,
                                        src_port: Some(tcp_packet.get_source()),
                                        dst_port: Some(tcp_packet.get_destination()),
                                    };
                                }
                            },
                            pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                                if let Some(udp_packet) = pnet::packet::udp::UdpPacket::new(ipv4_packet.payload()) {
                                    return PacketInfo {
                                        timestamp,
                                        length,
                                        protocol: "UDP".to_string(),
                                        src_ip,
                                        dst_ip,
                                        src_port: Some(udp_packet.get_source()),
                                        dst_port: Some(udp_packet.get_destination()),
                                    };
                                }
                            },
                            _ => {
                                return PacketInfo {
                                    timestamp,
                                    length,
                                    protocol: format!("IPv4-{}", ipv4_packet.get_next_level_protocol()),
                                    src_ip,
                                    dst_ip,
                                    src_port: None,
                                    dst_port: None,
                                };
                            }
                        }
                    }
                },
                pnet::packet::ethernet::EtherTypes::Ipv6 => {
                    return PacketInfo {
                        timestamp,
                        length,
                        protocol: "IPv6".to_string(),
                        src_ip: None,
                        dst_ip: None,
                        src_port: None,
                        dst_port: None,
                    };
                },
                _ => {
                    return PacketInfo {
                        timestamp,
                        length,
                        protocol: format!("Ethernet-{:?}", ethernet_packet.get_ethertype()),
                        src_ip: None,
                        dst_ip: None,
                        src_port: None,
                        dst_port: None,
                    };
                }
            }
        }
        
        // Fallback for unknown packet types
        PacketInfo {
            timestamp,
            length,
            protocol: "Unknown".to_string(),
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
        }
    }
}
