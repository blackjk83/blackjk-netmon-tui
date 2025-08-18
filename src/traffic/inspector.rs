use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, Duration};
use crate::capture::PacketInfo;
use crate::analysis::protocols::ProtocolType;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowDirection {
    Inbound,
    Outbound,
    Internal,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TrafficFlow {
    pub flow_id: String,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub protocol: ProtocolType,
    pub direction: FlowDirection,
    pub start_time: SystemTime,
    pub last_seen: SystemTime,
    pub packet_count: u64,
    pub byte_count: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct TrafficEvent {
    pub timestamp: SystemTime,
    pub event_type: TrafficEventType,
    pub flow_id: String,
    pub description: String,
    pub severity: EventSeverity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrafficEventType {
    FlowStarted,
    FlowEnded,
    HighBandwidth,
    SuspiciousActivity,
    ProtocolAnomaly,
    ConnectionSpike,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

pub struct TrafficInspector {
    active_flows: HashMap<String, TrafficFlow>,
    flow_history: VecDeque<TrafficFlow>,
    traffic_events: VecDeque<TrafficEvent>,
    bandwidth_threshold: u64, // bytes per second
    packet_rate_threshold: u64, // packets per second
    flow_timeout: Duration,
    max_flows: usize,
    max_events: usize,
    local_networks: Vec<ipnetwork::IpNetwork>,
}

impl TrafficInspector {
    pub fn new() -> Self {
        let mut inspector = Self {
            active_flows: HashMap::new(),
            flow_history: VecDeque::new(),
            traffic_events: VecDeque::new(),
            bandwidth_threshold: 1_000_000, // 1 MB/s
            packet_rate_threshold: 1000, // 1000 pps
            flow_timeout: Duration::from_secs(300), // 5 minutes
            max_flows: 10000,
            max_events: 1000,
            local_networks: Vec::new(),
        };
        
        // Initialize common local networks
        inspector.add_local_network("127.0.0.0/8").ok(); // Loopback
        inspector.add_local_network("10.0.0.0/8").ok(); // Private Class A
        inspector.add_local_network("172.16.0.0/12").ok(); // Private Class B
        inspector.add_local_network("192.168.0.0/16").ok(); // Private Class C
        
        inspector
    }
    
    pub fn with_config(
        bandwidth_threshold: u64,
        packet_rate_threshold: u64,
        flow_timeout_secs: u64,
        max_flows: usize,
    ) -> Self {
        let mut inspector = Self::new();
        inspector.bandwidth_threshold = bandwidth_threshold;
        inspector.packet_rate_threshold = packet_rate_threshold;
        inspector.flow_timeout = Duration::from_secs(flow_timeout_secs);
        inspector.max_flows = max_flows;
        inspector
    }
    
    pub fn add_local_network(&mut self, network: &str) -> Result<(), Box<dyn std::error::Error>> {
        let network: ipnetwork::IpNetwork = network.parse()?;
        self.local_networks.push(network);
        Ok(())
    }
    
    pub fn inspect_packet(&mut self, packet: &PacketInfo, protocol: ProtocolType) {
        if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) = 
            (&packet.src_ip, &packet.dst_ip, packet.src_port, packet.dst_port) {
            
            if let (Ok(src_addr), Ok(dst_addr)) = (
                format!("{}:{}", src_ip, src_port).parse::<SocketAddr>(),
                format!("{}:{}", dst_ip, dst_port).parse::<SocketAddr>()
            ) {
                let flow_id = self.generate_flow_id(&src_addr, &dst_addr);
                let direction = self.determine_flow_direction(&src_addr, &dst_addr);
                let now = SystemTime::now();
                
                // Update or create flow
                // Check if flow exists or create new one
                let flow_exists = self.active_flows.contains_key(&flow_id);
                if !flow_exists {
                    let new_flow = TrafficFlow {
                        flow_id: flow_id.clone(),
                        src_addr,
                        dst_addr,
                        protocol: protocol.clone(),
                        direction,
                        start_time: now,
                        last_seen: now,
                        packet_count: 0,
                        byte_count: 0,
                        packets_per_second: 0.0,
                        bytes_per_second: 0.0,
                        is_active: true,
                    };
                    
                    self.active_flows.insert(flow_id.clone(), new_flow);
                    
                    // Generate flow started event
                    self.add_event(TrafficEvent {
                        timestamp: now,
                        event_type: TrafficEventType::FlowStarted,
                        flow_id: flow_id.clone(),
                        description: format!("New {} flow: {} -> {}", protocol, src_addr, dst_addr),
                        severity: EventSeverity::Info,
                    });
                }
                
                let flow = self.active_flows.get_mut(&flow_id).unwrap();
                
                // Update flow statistics
                flow.packet_count += 1;
                flow.byte_count += packet.length as u64;
                flow.last_seen = now;
                flow.protocol = protocol;
                
                // Calculate rates (simplified - using last update time)
                if let Ok(duration) = now.duration_since(flow.start_time) {
                    let seconds = duration.as_secs_f64();
                    if seconds > 0.0 {
                        flow.packets_per_second = flow.packet_count as f64 / seconds;
                        flow.bytes_per_second = flow.byte_count as f64 / seconds;
                        
                        // Check for high bandwidth events (moved outside to avoid borrow issues)
                        let should_alert = flow.bytes_per_second > self.bandwidth_threshold as f64;
                        if should_alert {
                            let bandwidth_mb = flow.bytes_per_second / 1_000_000.0;
                            let _ = flow; // Release borrow before calling add_event
                            self.add_event(TrafficEvent {
                                timestamp: now,
                                event_type: TrafficEventType::HighBandwidth,
                                flow_id: flow_id.clone(),
                                description: format!("High bandwidth detected: {:.2} MB/s", bandwidth_mb),
                                severity: EventSeverity::Warning,
                            });
                        }
                    }
                }
            }
        }
        
        // Cleanup old flows
        self.cleanup_expired_flows();
    }
    
    fn generate_flow_id(&self, src: &SocketAddr, dst: &SocketAddr) -> String {
        // Create consistent flow ID regardless of direction
        if src < dst {
            format!("{}:{}", src, dst)
        } else {
            format!("{}:{}", dst, src)
        }
    }
    
    fn determine_flow_direction(&self, src: &SocketAddr, dst: &SocketAddr) -> FlowDirection {
        let src_is_local = self.is_local_address(&src.ip());
        let dst_is_local = self.is_local_address(&dst.ip());
        
        match (src_is_local, dst_is_local) {
            (true, true) => FlowDirection::Internal,
            (true, false) => FlowDirection::Outbound,
            (false, true) => FlowDirection::Inbound,
            (false, false) => FlowDirection::Unknown,
        }
    }
    
    fn is_local_address(&self, addr: &IpAddr) -> bool {
        self.local_networks.iter().any(|network| network.contains(*addr))
    }
    
    fn cleanup_expired_flows(&mut self) {
        let now = SystemTime::now();
        let timeout = self.flow_timeout;
        
        // Move expired flows to history
        let expired_flows: Vec<_> = self.active_flows
            .iter()
            .filter(|(_, flow)| {
                now.duration_since(flow.last_seen).unwrap_or_default() > timeout
            })
            .map(|(id, _)| id.clone())
            .collect();
        
        for flow_id in expired_flows {
            if let Some(mut flow) = self.active_flows.remove(&flow_id) {
                flow.is_active = false;
                
                // Add flow ended event
                self.add_event(TrafficEvent {
                    timestamp: now,
                    event_type: TrafficEventType::FlowEnded,
                    flow_id: flow_id.clone(),
                    description: format!("Flow ended: {} ({}s duration)", 
                        flow_id, 
                        now.duration_since(flow.start_time).unwrap_or_default().as_secs()),
                    severity: EventSeverity::Info,
                });
                
                // Add to history
                self.flow_history.push_back(flow);
                if self.flow_history.len() > self.max_flows {
                    self.flow_history.pop_front();
                }
            }
        }
    }
    
    fn add_event(&mut self, event: TrafficEvent) {
        self.traffic_events.push_back(event);
        if self.traffic_events.len() > self.max_events {
            self.traffic_events.pop_front();
        }
    }
    
    pub fn get_active_flows(&self) -> &HashMap<String, TrafficFlow> {
        &self.active_flows
    }
    
    pub fn get_flows_by_direction(&self, direction: FlowDirection) -> Vec<&TrafficFlow> {
        self.active_flows
            .values()
            .filter(|flow| flow.direction == direction)
            .collect()
    }
    
    pub fn get_top_flows_by_bandwidth(&self, limit: usize) -> Vec<&TrafficFlow> {
        let mut flows: Vec<_> = self.active_flows.values().collect();
        flows.sort_by(|a, b| b.bytes_per_second.partial_cmp(&a.bytes_per_second).unwrap_or(std::cmp::Ordering::Equal));
        flows.into_iter().take(limit).collect()
    }
    
    pub fn get_top_flows_by_packets(&self, limit: usize) -> Vec<&TrafficFlow> {
        let mut flows: Vec<_> = self.active_flows.values().collect();
        flows.sort_by(|a, b| b.packets_per_second.partial_cmp(&a.packets_per_second).unwrap_or(std::cmp::Ordering::Equal));
        flows.into_iter().take(limit).collect()
    }
    
    pub fn get_recent_events(&self, limit: usize) -> Vec<&TrafficEvent> {
        self.traffic_events
            .iter()
            .rev()
            .take(limit)
            .collect()
    }
    
    pub fn get_events_by_severity(&self, severity: EventSeverity) -> Vec<&TrafficEvent> {
        self.traffic_events
            .iter()
            .filter(|event| event.severity == severity)
            .collect()
    }
    
    pub fn get_flow_statistics(&self) -> FlowStatistics {
        let total_flows = self.active_flows.len();
        let total_bandwidth: f64 = self.active_flows.values()
            .map(|flow| flow.bytes_per_second)
            .sum();
        let total_packet_rate: f64 = self.active_flows.values()
            .map(|flow| flow.packets_per_second)
            .sum();
        
        let flows_by_direction = [
            (FlowDirection::Inbound, self.get_flows_by_direction(FlowDirection::Inbound).len()),
            (FlowDirection::Outbound, self.get_flows_by_direction(FlowDirection::Outbound).len()),
            (FlowDirection::Internal, self.get_flows_by_direction(FlowDirection::Internal).len()),
        ];
        
        FlowStatistics {
            total_active_flows: total_flows,
            total_bandwidth_bps: total_bandwidth,
            total_packet_rate_pps: total_packet_rate,
            flows_by_direction: flows_by_direction.into_iter().collect(),
            recent_events_count: self.traffic_events.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowStatistics {
    pub total_active_flows: usize,
    pub total_bandwidth_bps: f64,
    pub total_packet_rate_pps: f64,
    pub flows_by_direction: HashMap<FlowDirection, usize>,
    pub recent_events_count: usize,
}

impl std::fmt::Display for FlowDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowDirection::Inbound => write!(f, "INBOUND"),
            FlowDirection::Outbound => write!(f, "OUTBOUND"),
            FlowDirection::Internal => write!(f, "INTERNAL"),
            FlowDirection::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSeverity::Info => write!(f, "INFO"),
            EventSeverity::Warning => write!(f, "WARN"),
            EventSeverity::Critical => write!(f, "CRIT"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_inspector_creation() {
        let inspector = TrafficInspector::new();
        assert_eq!(inspector.active_flows.len(), 0);
        assert!(inspector.local_networks.len() > 0);
    }
    
    #[test]
    fn test_flow_direction_detection() {
        let inspector = TrafficInspector::new();
        
        let local_addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let external_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        
        assert_eq!(
            inspector.determine_flow_direction(&local_addr, &external_addr),
            FlowDirection::Outbound
        );
        assert_eq!(
            inspector.determine_flow_direction(&external_addr, &local_addr),
            FlowDirection::Inbound
        );
    }
}
