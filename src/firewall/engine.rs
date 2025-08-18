use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use crate::firewall::rules::{FirewallRule, RuleAction, RuleDirection, RuleProtocol};
use crate::capture::PacketInfo;

#[derive(Debug, Clone)]
pub struct FirewallStats {
    pub total_packets_processed: u64,
    pub packets_allowed: u64,
    pub packets_blocked: u64,
    pub packets_logged: u64,
    pub rules_matched: u64,
    pub active_rules: usize,
    pub enabled_rules: usize,
    pub last_reset: SystemTime,
}

impl FirewallStats {
    pub fn new() -> Self {
        Self {
            total_packets_processed: 0,
            packets_allowed: 0,
            packets_blocked: 0,
            packets_logged: 0,
            rules_matched: 0,
            active_rules: 0,
            enabled_rules: 0,
            last_reset: SystemTime::now(),
        }
    }
    
    pub fn reset(&mut self) {
        *self = Self::new();
    }
    
    pub fn get_block_rate(&self) -> f64 {
        if self.total_packets_processed == 0 {
            0.0
        } else {
            (self.packets_blocked as f64 / self.total_packets_processed as f64) * 100.0
        }
    }
    
    pub fn get_allow_rate(&self) -> f64 {
        if self.total_packets_processed == 0 {
            0.0
        } else {
            (self.packets_allowed as f64 / self.total_packets_processed as f64) * 100.0
        }
    }
}

#[derive(Debug, Clone)]
pub struct FirewallEvent {
    pub timestamp: SystemTime,
    pub rule_id: u32,
    pub rule_name: String,
    pub action: RuleAction,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: RuleProtocol,
    pub direction: RuleDirection,
    pub packet_size: usize,
}

impl FirewallEvent {
    pub fn get_age(&self) -> Duration {
        self.timestamp.elapsed().unwrap_or(Duration::from_secs(0))
    }
    
    pub fn format_summary(&self) -> String {
        format!(
            "{:?} {} {}:{} → {}:{} ({})",
            self.action,
            self.protocol_str(),
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.rule_name
        )
    }
    
    fn protocol_str(&self) -> &str {
        match self.protocol {
            RuleProtocol::TCP => "TCP",
            RuleProtocol::UDP => "UDP",
            RuleProtocol::ICMP => "ICMP",
            RuleProtocol::Any => "ANY",
        }
    }
}

pub struct FirewallEngine {
    rules: Vec<FirewallRule>,
    stats: FirewallStats,
    recent_events: VecDeque<FirewallEvent>,
    max_events: usize,
    rule_counter: u32,
    enabled: bool,
}

impl FirewallEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            stats: FirewallStats::new(),
            recent_events: VecDeque::new(),
            max_events: 1000, // Keep last 1000 events
            rule_counter: 0,
            enabled: true,
        }
    }
    
    pub fn add_rule(&mut self, mut rule: FirewallRule) -> u32 {
        self.rule_counter += 1;
        rule.id = self.rule_counter;
        
        // Insert rule in priority order (higher priority first)
        let insert_pos = self.rules
            .iter()
            .position(|r| r.priority < rule.priority)
            .unwrap_or(self.rules.len());
        
        self.rules.insert(insert_pos, rule);
        self.update_stats();
        self.rule_counter
    }
    
    pub fn remove_rule(&mut self, rule_id: u32) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            self.rules.remove(pos);
            self.update_stats();
            true
        } else {
            false
        }
    }
    
    pub fn enable_rule(&mut self, rule_id: u32) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = true;
            self.update_stats();
            true
        } else {
            false
        }
    }
    
    pub fn disable_rule(&mut self, rule_id: u32) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == rule_id) {
            rule.enabled = false;
            self.update_stats();
            true
        } else {
            false
        }
    }
    
    pub fn get_rule(&self, rule_id: u32) -> Option<&FirewallRule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }
    
    pub fn get_rule_mut(&mut self, rule_id: u32) -> Option<&mut FirewallRule> {
        self.rules.iter_mut().find(|r| r.id == rule_id)
    }
    
    pub fn get_rules(&self) -> &[FirewallRule] {
        &self.rules
    }
    
    pub fn get_stats(&self) -> &FirewallStats {
        &self.stats
    }
    
    pub fn get_recent_events(&self) -> &VecDeque<FirewallEvent> {
        &self.recent_events
    }
    
    pub fn clear_events(&mut self) {
        self.recent_events.clear();
    }
    
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
    
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    pub fn process_packet(&mut self, packet: &PacketInfo) -> RuleAction {
        if !self.enabled {
            return RuleAction::Allow;
        }
        
        self.stats.total_packets_processed += 1;
        
        // Parse packet information
        let src_ip = match packet.src_ip.as_ref().and_then(|ip| ip.parse().ok()) {
            Some(ip) => ip,
            None => return RuleAction::Allow, // Can't parse IP, allow by default
        };
        
        let dst_ip = match packet.dst_ip.as_ref().and_then(|ip| ip.parse().ok()) {
            Some(ip) => ip,
            None => return RuleAction::Allow, // Can't parse IP, allow by default
        };
        
        let src_port = packet.src_port.unwrap_or(0);
        let dst_port = packet.dst_port.unwrap_or(0);
        
        let protocol = match packet.protocol.as_str() {
            "TCP" => RuleProtocol::TCP,
            "UDP" => RuleProtocol::UDP,
            "ICMP" => RuleProtocol::ICMP,
            _ => RuleProtocol::Any,
        };
        
        // Determine direction (simplified - in real implementation this would be more complex)
        let direction = if self.is_local_ip(&src_ip) {
            RuleDirection::Outbound
        } else {
            RuleDirection::Inbound
        };
        
        // Check rules in priority order
        for rule in &mut self.rules {
            if rule.matches_packet(&src_ip, &dst_ip, src_port, dst_port, &protocol, &direction) {
                rule.record_match();
                self.stats.rules_matched += 1;
                
                // Create event
                let event = FirewallEvent {
                    timestamp: SystemTime::now(),
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    action: rule.action.clone(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol: protocol.clone(),
                    direction: direction.clone(),
                    packet_size: packet.length,
                };
                
                // Add event to recent events
                self.recent_events.push_back(event);
                if self.recent_events.len() > self.max_events {
                    self.recent_events.pop_front();
                }
                
                // Update stats based on action
                match rule.action {
                    RuleAction::Allow => {
                        self.stats.packets_allowed += 1;
                        return RuleAction::Allow;
                    }
                    RuleAction::Block => {
                        self.stats.packets_blocked += 1;
                        return RuleAction::Block;
                    }
                    RuleAction::Log => {
                        self.stats.packets_logged += 1;
                        // Continue to next rule
                    }
                    RuleAction::LogAndBlock => {
                        self.stats.packets_logged += 1;
                        self.stats.packets_blocked += 1;
                        return RuleAction::LogAndBlock;
                    }
                }
            }
        }
        
        // No matching rule found, allow by default
        self.stats.packets_allowed += 1;
        RuleAction::Allow
    }
    
    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback() || 
                ipv4.is_private() ||
                ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254 // Link-local
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() ||
                (ipv6.segments()[0] & 0xfe00) == 0xfc00 || // Unique local
                (ipv6.segments()[0] & 0xffc0) == 0xfe80    // Link-local
            }
        }
    }
    
    fn update_stats(&mut self) {
        self.stats.active_rules = self.rules.len();
        self.stats.enabled_rules = self.rules.iter().filter(|r| r.enabled).count();
    }
    
    pub fn load_default_rules(&mut self) {
        use crate::firewall::rules::RuleTemplates;
        
        // Add default rules in order of priority
        self.add_rule(RuleTemplates::allow_localhost());
        self.add_rule(RuleTemplates::allow_ssh());
        self.add_rule(RuleTemplates::allow_http_https());
        self.add_rule(RuleTemplates::block_suspicious_ports());
        self.add_rule(RuleTemplates::log_all_connections());
    }
    
    pub fn export_rules(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.rules)
    }
    
    pub fn import_rules(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let imported_rules: Vec<FirewallRule> = serde_json::from_str(json)?;
        let count = imported_rules.len();
        
        for rule in imported_rules {
            self.add_rule(rule);
        }
        
        Ok(count)
    }
}

impl Default for FirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::rules::RuleTemplates;

    #[test]
    fn test_firewall_engine_creation() {
        let engine = FirewallEngine::new();
        assert_eq!(engine.rules.len(), 0);
        assert!(engine.enabled);
        assert_eq!(engine.stats.total_packets_processed, 0);
    }
    
    #[test]
    fn test_add_remove_rules() {
        let mut engine = FirewallEngine::new();
        
        let rule_id = engine.add_rule(RuleTemplates::allow_ssh());
        assert_eq!(engine.rules.len(), 1);
        assert_eq!(engine.stats.active_rules, 1);
        
        assert!(engine.remove_rule(rule_id));
        assert_eq!(engine.rules.len(), 0);
        assert_eq!(engine.stats.active_rules, 0);
        
        assert!(!engine.remove_rule(999)); // Non-existent rule
    }
    
    #[test]
    fn test_rule_priority_ordering() {
        let mut engine = FirewallEngine::new();
        
        // Add rules with different priorities
        let low_priority = FirewallRule::new(
            1, "Low".to_string(), RuleAction::Allow, 
            RuleDirection::Inbound, RuleProtocol::TCP
        ).with_priority(100);
        
        let high_priority = FirewallRule::new(
            2, "High".to_string(), RuleAction::Block, 
            RuleDirection::Inbound, RuleProtocol::TCP
        ).with_priority(200);
        
        engine.add_rule(low_priority);
        engine.add_rule(high_priority);
        
        // High priority rule should be first
        assert_eq!(engine.rules[0].priority, 200);
        assert_eq!(engine.rules[1].priority, 100);
    }
    
    #[test]
    fn test_packet_processing() {
        let mut engine = FirewallEngine::new();
        engine.add_rule(RuleTemplates::allow_ssh());
        
        let ssh_packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 64,
            protocol: "TCP".to_string(),
            src_ip: Some("192.168.1.100".to_string()),
            dst_ip: Some("192.168.1.1".to_string()),
            src_port: Some(12345),
            dst_port: Some(22),
        };
        
        let action = engine.process_packet(&ssh_packet);
        assert_eq!(action, RuleAction::Allow);
        assert_eq!(engine.stats.total_packets_processed, 1);
        assert_eq!(engine.stats.packets_allowed, 1);
    }
}
