use std::collections::HashMap;
use crate::capture::PacketInfo;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Http,
    Https,
    Ssh,
    Dns,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Telnet,
    Tcp(u16),  // TCP with port number
    Udp(u16),  // UDP with port number
    Icmp,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    pub protocol_type: ProtocolType,
    pub description: String,
    pub is_encrypted: bool,
    pub default_port: Option<u16>,
    pub packet_count: u64,
    pub byte_count: u64,
}

pub struct ProtocolAnalyzer {
    protocol_stats: HashMap<ProtocolType, ProtocolInfo>,
    well_known_ports: HashMap<u16, ProtocolType>,
}

impl ProtocolAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = ProtocolAnalyzer {
            protocol_stats: HashMap::new(),
            well_known_ports: HashMap::new(),
        };
        
        analyzer.initialize_well_known_ports();
        analyzer
    }
    
    fn initialize_well_known_ports(&mut self) {
        // HTTP/HTTPS
        self.well_known_ports.insert(80, ProtocolType::Http);
        self.well_known_ports.insert(8080, ProtocolType::Http);
        self.well_known_ports.insert(443, ProtocolType::Https);
        self.well_known_ports.insert(8443, ProtocolType::Https);
        
        // SSH
        self.well_known_ports.insert(22, ProtocolType::Ssh);
        
        // DNS
        self.well_known_ports.insert(53, ProtocolType::Dns);
        
        // FTP
        self.well_known_ports.insert(21, ProtocolType::Ftp);
        self.well_known_ports.insert(20, ProtocolType::Ftp);
        
        // Email protocols
        self.well_known_ports.insert(25, ProtocolType::Smtp);
        self.well_known_ports.insert(587, ProtocolType::Smtp);
        self.well_known_ports.insert(110, ProtocolType::Pop3);
        self.well_known_ports.insert(995, ProtocolType::Pop3);
        self.well_known_ports.insert(143, ProtocolType::Imap);
        self.well_known_ports.insert(993, ProtocolType::Imap);
        
        // Telnet
        self.well_known_ports.insert(23, ProtocolType::Telnet);
    }
    
    pub fn analyze_packet(&mut self, packet: &PacketInfo) -> ProtocolType {
        let protocol_type = self.identify_protocol(packet);
        
        // Update statistics
        let info = self.protocol_stats.entry(protocol_type.clone()).or_insert_with(|| {
            ProtocolInfo {
                protocol_type: protocol_type.clone(),
                description: Self::get_protocol_description(&protocol_type),
                is_encrypted: Self::is_protocol_encrypted(&protocol_type),
                default_port: Self::get_default_port(&protocol_type),
                packet_count: 0,
                byte_count: 0,
            }
        });
        
        info.packet_count += 1;
        info.byte_count += packet.length as u64;
        
        protocol_type
    }
    
    fn identify_protocol(&self, packet: &PacketInfo) -> ProtocolType {
        match packet.protocol.as_str() {
            "TCP" => {
                if let Some(dst_port) = packet.dst_port {
                    if let Some(protocol) = self.well_known_ports.get(&dst_port) {
                        return protocol.clone();
                    }
                }
                if let Some(src_port) = packet.src_port {
                    if let Some(protocol) = self.well_known_ports.get(&src_port) {
                        return protocol.clone();
                    }
                }
                // Return TCP with port if available
                if let Some(port) = packet.dst_port.or(packet.src_port) {
                    ProtocolType::Tcp(port)
                } else {
                    ProtocolType::Unknown
                }
            },
            "UDP" => {
                if let Some(dst_port) = packet.dst_port {
                    if let Some(protocol) = self.well_known_ports.get(&dst_port) {
                        return protocol.clone();
                    }
                }
                if let Some(src_port) = packet.src_port {
                    if let Some(protocol) = self.well_known_ports.get(&src_port) {
                        return protocol.clone();
                    }
                }
                // Return UDP with port if available
                if let Some(port) = packet.dst_port.or(packet.src_port) {
                    ProtocolType::Udp(port)
                } else {
                    ProtocolType::Unknown
                }
            },
            "ICMP" => ProtocolType::Icmp,
            _ => ProtocolType::Unknown,
        }
    }
    
    fn get_protocol_description(protocol_type: &ProtocolType) -> String {
        match protocol_type {
            ProtocolType::Http => "Hypertext Transfer Protocol".to_string(),
            ProtocolType::Https => "HTTP Secure (TLS/SSL)".to_string(),
            ProtocolType::Ssh => "Secure Shell".to_string(),
            ProtocolType::Dns => "Domain Name System".to_string(),
            ProtocolType::Ftp => "File Transfer Protocol".to_string(),
            ProtocolType::Smtp => "Simple Mail Transfer Protocol".to_string(),
            ProtocolType::Pop3 => "Post Office Protocol v3".to_string(),
            ProtocolType::Imap => "Internet Message Access Protocol".to_string(),
            ProtocolType::Telnet => "Telnet Protocol".to_string(),
            ProtocolType::Tcp(port) => format!("TCP (port {})", port),
            ProtocolType::Udp(port) => format!("UDP (port {})", port),
            ProtocolType::Icmp => "Internet Control Message Protocol".to_string(),
            ProtocolType::Unknown => "Unknown Protocol".to_string(),
        }
    }
    
    fn is_protocol_encrypted(protocol_type: &ProtocolType) -> bool {
        matches!(protocol_type, 
            ProtocolType::Https | 
            ProtocolType::Ssh |
            ProtocolType::Pop3 |  // Assuming POP3S on port 995
            ProtocolType::Imap    // Assuming IMAPS on port 993
        )
    }
    
    fn get_default_port(protocol_type: &ProtocolType) -> Option<u16> {
        match protocol_type {
            ProtocolType::Http => Some(80),
            ProtocolType::Https => Some(443),
            ProtocolType::Ssh => Some(22),
            ProtocolType::Dns => Some(53),
            ProtocolType::Ftp => Some(21),
            ProtocolType::Smtp => Some(25),
            ProtocolType::Pop3 => Some(110),
            ProtocolType::Imap => Some(143),
            ProtocolType::Telnet => Some(23),
            ProtocolType::Tcp(port) => Some(*port),
            ProtocolType::Udp(port) => Some(*port),
            _ => None,
        }
    }
    
    pub fn get_protocol_statistics(&self) -> &HashMap<ProtocolType, ProtocolInfo> {
        &self.protocol_stats
    }
    
    pub fn get_top_protocols(&self, limit: usize) -> Vec<(&ProtocolType, &ProtocolInfo)> {
        let mut protocols: Vec<_> = self.protocol_stats.iter().collect();
        protocols.sort_by(|a, b| b.1.packet_count.cmp(&a.1.packet_count));
        protocols.into_iter().take(limit).collect()
    }
    
    pub fn get_total_packets(&self) -> u64 {
        self.protocol_stats.values().map(|info| info.packet_count).sum()
    }
    
    pub fn get_total_bytes(&self) -> u64 {
        self.protocol_stats.values().map(|info| info.byte_count).sum()
    }
    
    pub fn reset_statistics(&mut self) {
        self.protocol_stats.clear();
    }
    
    /// Advanced protocol detection based on packet content patterns
    pub fn deep_packet_inspection(&self, packet: &PacketInfo, _payload: Option<&[u8]>) -> ProtocolType {
        // For now, use the basic port-based identification
        // In the future, this could analyze packet payload for more accurate detection
        self.identify_protocol(packet)
    }
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "HTTP"),
            ProtocolType::Https => write!(f, "HTTPS"),
            ProtocolType::Ssh => write!(f, "SSH"),
            ProtocolType::Dns => write!(f, "DNS"),
            ProtocolType::Ftp => write!(f, "FTP"),
            ProtocolType::Smtp => write!(f, "SMTP"),
            ProtocolType::Pop3 => write!(f, "POP3"),
            ProtocolType::Imap => write!(f, "IMAP"),
            ProtocolType::Telnet => write!(f, "TELNET"),
            ProtocolType::Tcp(port) => write!(f, "TCP:{}", port),
            ProtocolType::Udp(port) => write!(f, "UDP:{}", port),
            ProtocolType::Icmp => write!(f, "ICMP"),
            ProtocolType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn test_protocol_identification() {
        let mut analyzer = ProtocolAnalyzer::new();
        
        // Test HTTP identification
        let http_packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 1024,
            protocol: "TCP".to_string(),
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: Some("192.168.1.2".to_string()),
            src_port: Some(12345),
            dst_port: Some(80),
        };
        
        let protocol = analyzer.analyze_packet(&http_packet);
        assert_eq!(protocol, ProtocolType::Http);
        
        // Test HTTPS identification
        let https_packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 512,
            protocol: "TCP".to_string(),
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: Some("192.168.1.2".to_string()),
            src_port: Some(54321),
            dst_port: Some(443),
        };
        
        let protocol = analyzer.analyze_packet(&https_packet);
        assert_eq!(protocol, ProtocolType::Https);
    }
    
    #[test]
    fn test_protocol_statistics() {
        let mut analyzer = ProtocolAnalyzer::new();
        
        let packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 100,
            protocol: "TCP".to_string(),
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: Some("192.168.1.2".to_string()),
            src_port: Some(12345),
            dst_port: Some(80),
        };
        
        // Analyze the same packet multiple times
        for _ in 0..5 {
            analyzer.analyze_packet(&packet);
        }
        
        let stats = analyzer.get_protocol_statistics();
        let http_stats = stats.get(&ProtocolType::Http).unwrap();
        
        assert_eq!(http_stats.packet_count, 5);
        assert_eq!(http_stats.byte_count, 500);
    }
}
