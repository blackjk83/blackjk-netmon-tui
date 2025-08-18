use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashSet;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    Log,
    LogAndBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleDirection {
    Inbound,
    Outbound,
    Bidirectional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleProtocol {
    TCP,
    UDP,
    ICMP,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub action: RuleAction,
    pub direction: RuleDirection,
    pub protocol: RuleProtocol,
    pub source_ips: Option<HashSet<IpAddr>>,
    pub destination_ips: Option<HashSet<IpAddr>>,
    pub source_ports: Option<HashSet<u16>>,
    pub destination_ports: Option<HashSet<u16>>,
    pub priority: u8, // 0-255, higher number = higher priority
    pub description: String,
    pub created_at: std::time::SystemTime,
    pub last_matched: Option<std::time::SystemTime>,
    pub match_count: u64,
}

impl FirewallRule {
    pub fn new(
        id: u32,
        name: String,
        action: RuleAction,
        direction: RuleDirection,
        protocol: RuleProtocol,
    ) -> Self {
        Self {
            id,
            name,
            enabled: true,
            action,
            direction,
            protocol,
            source_ips: None,
            destination_ips: None,
            source_ports: None,
            destination_ports: None,
            priority: 128, // Default medium priority
            description: String::new(),
            created_at: std::time::SystemTime::now(),
            last_matched: None,
            match_count: 0,
        }
    }
    
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ips.get_or_insert_with(HashSet::new).insert(ip);
        self
    }
    
    pub fn with_source_ips(mut self, ips: Vec<IpAddr>) -> Self {
        let set = self.source_ips.get_or_insert_with(HashSet::new);
        for ip in ips {
            set.insert(ip);
        }
        self
    }
    
    pub fn with_destination_ip(mut self, ip: IpAddr) -> Self {
        self.destination_ips.get_or_insert_with(HashSet::new).insert(ip);
        self
    }
    
    pub fn with_destination_ips(mut self, ips: Vec<IpAddr>) -> Self {
        let set = self.destination_ips.get_or_insert_with(HashSet::new);
        for ip in ips {
            set.insert(ip);
        }
        self
    }
    
    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_ports.get_or_insert_with(HashSet::new).insert(port);
        self
    }
    
    pub fn with_source_ports(mut self, ports: Vec<u16>) -> Self {
        let set = self.source_ports.get_or_insert_with(HashSet::new);
        for port in ports {
            set.insert(port);
        }
        self
    }
    
    pub fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_ports.get_or_insert_with(HashSet::new).insert(port);
        self
    }
    
    pub fn with_destination_ports(mut self, ports: Vec<u16>) -> Self {
        let set = self.destination_ports.get_or_insert_with(HashSet::new);
        for port in ports {
            set.insert(port);
        }
        self
    }
    
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
    
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }
    
    pub fn matches_packet(
        &self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: &RuleProtocol,
        direction: &RuleDirection,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        
        // Check protocol
        if self.protocol != RuleProtocol::Any && &self.protocol != protocol {
            return false;
        }
        
        // Check direction
        match (&self.direction, direction) {
            (RuleDirection::Bidirectional, _) => {},
            (dir1, dir2) if dir1 == dir2 => {},
            _ => return false,
        }
        
        // Check source IPs
        if let Some(ref allowed_ips) = self.source_ips {
            if !allowed_ips.contains(src_ip) {
                return false;
            }
        }
        
        // Check destination IPs
        if let Some(ref allowed_ips) = self.destination_ips {
            if !allowed_ips.contains(dst_ip) {
                return false;
            }
        }
        
        // Check source ports
        if let Some(ref allowed_ports) = self.source_ports {
            if !allowed_ports.contains(&src_port) {
                return false;
            }
        }
        
        // Check destination ports
        if let Some(ref allowed_ports) = self.destination_ports {
            if !allowed_ports.contains(&dst_port) {
                return false;
            }
        }
        
        true
    }
    
    pub fn record_match(&mut self) {
        self.last_matched = Some(std::time::SystemTime::now());
        self.match_count += 1;
    }
    
    pub fn get_age(&self) -> Duration {
        self.created_at.elapsed().unwrap_or(Duration::from_secs(0))
    }
    
    pub fn get_time_since_last_match(&self) -> Option<Duration> {
        self.last_matched?.elapsed().ok()
    }
}

use std::time::Duration;

impl Default for FirewallRule {
    fn default() -> Self {
        Self::new(
            0,
            "Default Rule".to_string(),
            RuleAction::Allow,
            RuleDirection::Bidirectional,
            RuleProtocol::Any,
        )
    }
}

// Predefined rule templates for common scenarios
pub struct RuleTemplates;

impl RuleTemplates {
    pub fn block_all_incoming() -> FirewallRule {
        FirewallRule::new(
            1,
            "Block All Incoming".to_string(),
            RuleAction::Block,
            RuleDirection::Inbound,
            RuleProtocol::Any,
        )
        .with_description("Block all incoming connections".to_string())
        .with_priority(200)
    }
    
    pub fn allow_ssh() -> FirewallRule {
        FirewallRule::new(
            2,
            "Allow SSH".to_string(),
            RuleAction::Allow,
            RuleDirection::Inbound,
            RuleProtocol::TCP,
        )
        .with_destination_port(22)
        .with_description("Allow SSH connections".to_string())
        .with_priority(250)
    }
    
    pub fn allow_http_https() -> FirewallRule {
        FirewallRule::new(
            3,
            "Allow HTTP/HTTPS".to_string(),
            RuleAction::Allow,
            RuleDirection::Inbound,
            RuleProtocol::TCP,
        )
        .with_destination_ports(vec![80, 443])
        .with_description("Allow HTTP and HTTPS connections".to_string())
        .with_priority(240)
    }
    
    pub fn block_suspicious_ports() -> FirewallRule {
        FirewallRule::new(
            4,
            "Block Suspicious Ports".to_string(),
            RuleAction::LogAndBlock,
            RuleDirection::Bidirectional,
            RuleProtocol::Any,
        )
        .with_destination_ports(vec![
            1433, 1521, 3306, 5432, // Database ports
            135, 139, 445,          // Windows SMB ports
            23, 21,                 // Telnet, FTP
        ])
        .with_description("Block commonly attacked ports".to_string())
        .with_priority(220)
    }
    
    pub fn allow_localhost() -> FirewallRule {
        FirewallRule::new(
            5,
            "Allow Localhost".to_string(),
            RuleAction::Allow,
            RuleDirection::Bidirectional,
            RuleProtocol::Any,
        )
        .with_source_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .with_destination_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .with_description("Allow all localhost traffic".to_string())
        .with_priority(255)
    }
    
    pub fn log_all_connections() -> FirewallRule {
        FirewallRule::new(
            6,
            "Log All Connections".to_string(),
            RuleAction::Log,
            RuleDirection::Bidirectional,
            RuleProtocol::Any,
        )
        .with_description("Log all network connections for monitoring".to_string())
        .with_priority(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_creation() {
        let rule = FirewallRule::new(
            1,
            "Test Rule".to_string(),
            RuleAction::Allow,
            RuleDirection::Inbound,
            RuleProtocol::TCP,
        );
        
        assert_eq!(rule.id, 1);
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.action, RuleAction::Allow);
        assert!(rule.enabled);
    }
    
    #[test]
    fn test_rule_matching() {
        let rule = FirewallRule::new(
            1,
            "SSH Rule".to_string(),
            RuleAction::Allow,
            RuleDirection::Inbound,
            RuleProtocol::TCP,
        )
        .with_destination_port(22);
        
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        assert!(rule.matches_packet(
            &src_ip,
            &dst_ip,
            12345,
            22,
            &RuleProtocol::TCP,
            &RuleDirection::Inbound
        ));
        
        assert!(!rule.matches_packet(
            &src_ip,
            &dst_ip,
            12345,
            80,
            &RuleProtocol::TCP,
            &RuleDirection::Inbound
        ));
    }
    
    #[test]
    fn test_rule_templates() {
        let ssh_rule = RuleTemplates::allow_ssh();
        assert_eq!(ssh_rule.action, RuleAction::Allow);
        assert_eq!(ssh_rule.protocol, RuleProtocol::TCP);
        assert!(ssh_rule.destination_ports.as_ref().unwrap().contains(&22));
        
        let block_rule = RuleTemplates::block_all_incoming();
        assert_eq!(block_rule.action, RuleAction::Block);
        assert_eq!(block_rule.direction, RuleDirection::Inbound);
    }
}
