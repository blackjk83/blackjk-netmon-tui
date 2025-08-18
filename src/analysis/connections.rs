use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, Duration};
use crate::capture::{PacketInfo, TcpConnection, TcpState};
use crate::analysis::protocols::{ProtocolType, ProtocolAnalyzer};

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Establishing,
    Established,
    Closing,
    Closed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: ProtocolType,
    pub state: ConnectionState,
    pub established_time: SystemTime,
    pub last_seen: SystemTime,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}

pub struct ConnectionTracker {
    active_connections: HashMap<String, ConnectionInfo>,
    protocol_analyzer: ProtocolAnalyzer,
    connection_timeout: Duration,
    max_connections: usize,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            active_connections: HashMap::new(),
            protocol_analyzer: ProtocolAnalyzer::new(),
            connection_timeout: Duration::from_secs(300), // 5 minutes timeout
            max_connections: 1000,
        }
    }
    
    pub fn with_config(timeout_secs: u64, max_connections: usize) -> Self {
        Self {
            active_connections: HashMap::new(),
            protocol_analyzer: ProtocolAnalyzer::new(),
            connection_timeout: Duration::from_secs(timeout_secs),
            max_connections,
        }
    }
    
    /// Update connections from /proc/net/tcp data
    pub fn update_from_proc(&mut self, tcp_connections: &[TcpConnection]) {
        let now = SystemTime::now();
        
        // Clear existing connections that are no longer in /proc
        let proc_keys: std::collections::HashSet<String> = tcp_connections
            .iter()
            .map(|conn| self.connection_key(&conn.local_addr, &conn.remote_addr))
            .collect();
        
        self.active_connections.retain(|key, _| proc_keys.contains(key));
        
        // Update or add connections from /proc data
        for tcp_conn in tcp_connections {
            let key = self.connection_key(&tcp_conn.local_addr, &tcp_conn.remote_addr);
            let protocol = self.identify_protocol_from_connection(tcp_conn);
            
            let conn_info = self.active_connections.entry(key).or_insert_with(|| {
                ConnectionInfo {
                    local_addr: tcp_conn.local_addr,
                    remote_addr: tcp_conn.remote_addr,
                    protocol: protocol.clone(),
                    state: Self::convert_tcp_state(&tcp_conn.state),
                    established_time: now,
                    last_seen: now,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    process_id: None,
                    process_name: None,
                }
            });
            
            // Update connection state and last seen time
            conn_info.state = Self::convert_tcp_state(&tcp_conn.state);
            conn_info.last_seen = now;
            conn_info.protocol = protocol;
        }
        
        // Clean up old connections
        self.cleanup_old_connections();
    }
    
    /// Track a packet and update connection information
    pub fn track_packet(&mut self, packet: &PacketInfo) {
        if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) = 
            (&packet.src_ip, &packet.dst_ip, packet.src_port, packet.dst_port) {
            
            // Parse addresses
            if let (Ok(src_addr), Ok(dst_addr)) = (
                format!("{}:{}", src_ip, src_port).parse::<SocketAddr>(),
                format!("{}:{}", dst_ip, dst_port).parse::<SocketAddr>()
            ) {
                let key = self.connection_key(&src_addr, &dst_addr);
                let protocol = self.protocol_analyzer.analyze_packet(packet);
                let now = SystemTime::now();
                
                let conn_info = self.active_connections.entry(key).or_insert_with(|| {
                    ConnectionInfo {
                        local_addr: src_addr,
                        remote_addr: dst_addr,
                        protocol: protocol.clone(),
                        state: ConnectionState::Established,
                        established_time: now,
                        last_seen: now,
                        bytes_sent: 0,
                        bytes_received: 0,
                        packets_sent: 0,
                        packets_received: 0,
                        process_id: None,
                        process_name: None,
                    }
                });
                
                // Update packet and byte counts
                conn_info.packets_sent += 1;
                conn_info.bytes_sent += packet.length as u64;
                conn_info.last_seen = now;
                conn_info.protocol = protocol;
            }
        }
    }
    
    fn connection_key(&self, addr1: &SocketAddr, addr2: &SocketAddr) -> String {
        // Create a consistent key regardless of direction
        if addr1 < addr2 {
            format!("{}:{}", addr1, addr2)
        } else {
            format!("{}:{}", addr2, addr1)
        }
    }
    
    fn identify_protocol_from_connection(&mut self, tcp_conn: &TcpConnection) -> ProtocolType {
        // Create a dummy packet info for protocol analysis
        let dummy_packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 0,
            protocol: "TCP".to_string(),
            src_ip: Some(tcp_conn.local_addr.ip().to_string()),
            dst_ip: Some(tcp_conn.remote_addr.ip().to_string()),
            src_port: Some(tcp_conn.local_addr.port()),
            dst_port: Some(tcp_conn.remote_addr.port()),
        };
        
        self.protocol_analyzer.analyze_packet(&dummy_packet)
    }
    
    fn convert_tcp_state(tcp_state: &TcpState) -> ConnectionState {
        match tcp_state {
            TcpState::Established => ConnectionState::Established,
            TcpState::SynSent | TcpState::SynRecv => ConnectionState::Establishing,
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::TimeWait | 
            TcpState::CloseWait | TcpState::LastAck | TcpState::Closing => ConnectionState::Closing,
            TcpState::Close => ConnectionState::Closed,
            TcpState::Listen => ConnectionState::Established, // Listening sockets are "active"
            TcpState::Unknown(_) => ConnectionState::Unknown,
        }
    }
    
    fn cleanup_old_connections(&mut self) {
        let now = SystemTime::now();
        let timeout = self.connection_timeout;
        
        self.active_connections.retain(|_, conn| {
            match now.duration_since(conn.last_seen) {
                Ok(duration) => duration < timeout,
                Err(_) => true, // Keep if we can't determine age
            }
        });
        
        // If we have too many connections, remove the oldest ones
        if self.active_connections.len() > self.max_connections {
            let mut connections: Vec<_> = self.active_connections.iter().collect();
            connections.sort_by_key(|(_, conn)| conn.last_seen);
            
            let to_remove = self.active_connections.len() - self.max_connections;
            let keys_to_remove: Vec<String> = connections.iter()
                .take(to_remove)
                .map(|(key, _)| (*key).clone())
                .collect();
            
            for key in keys_to_remove {
                self.active_connections.remove(&key);
            }
        }
    }
    
    pub fn get_active_connections(&self) -> &HashMap<String, ConnectionInfo> {
        &self.active_connections
    }
    
    pub fn get_connections_by_protocol(&self, protocol: &ProtocolType) -> Vec<&ConnectionInfo> {
        self.active_connections
            .values()
            .filter(|conn| &conn.protocol == protocol)
            .collect()
    }
    
    pub fn get_connections_by_state(&self, state: &ConnectionState) -> Vec<&ConnectionInfo> {
        self.active_connections
            .values()
            .filter(|conn| &conn.state == state)
            .collect()
    }
    
    pub fn get_connection_count(&self) -> usize {
        self.active_connections.len()
    }
    
    pub fn get_total_bytes_transferred(&self) -> (u64, u64) {
        let total_sent = self.active_connections.values()
            .map(|conn| conn.bytes_sent)
            .sum();
        let total_received = self.active_connections.values()
            .map(|conn| conn.bytes_received)
            .sum();
        (total_sent, total_received)
    }
    
    pub fn get_top_connections_by_traffic(&self, limit: usize) -> Vec<&ConnectionInfo> {
        let mut connections: Vec<_> = self.active_connections.values().collect();
        connections.sort_by_key(|conn| std::cmp::Reverse(conn.bytes_sent + conn.bytes_received));
        connections.into_iter().take(limit).collect()
    }
    
    pub fn get_protocol_analyzer(&self) -> &ProtocolAnalyzer {
        &self.protocol_analyzer
    }
    
    pub fn get_protocol_analyzer_mut(&mut self) -> &mut ProtocolAnalyzer {
        &mut self.protocol_analyzer
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Establishing => write!(f, "ESTABLISHING"),
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::Closed => write!(f, "CLOSED"),
            ConnectionState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_tracking() {
        let mut tracker = ConnectionTracker::new();
        
        let packet = PacketInfo {
            timestamp: SystemTime::now(),
            length: 1024,
            protocol: "TCP".to_string(),
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: Some("192.168.1.2".to_string()),
            src_port: Some(12345),
            dst_port: Some(80),
        };
        
        tracker.track_packet(&packet);
        
        assert_eq!(tracker.get_connection_count(), 1);
        let connections = tracker.get_active_connections();
        let conn = connections.values().next().unwrap();
        assert_eq!(conn.bytes_sent, 1024);
        assert_eq!(conn.packets_sent, 1);
    }
    
    #[test]
    fn test_tcp_state_conversion() {
        assert_eq!(
            ConnectionTracker::convert_tcp_state(&TcpState::Established),
            ConnectionState::Established
        );
        assert_eq!(
            ConnectionTracker::convert_tcp_state(&TcpState::Listen),
            ConnectionState::Established
        );
        assert_eq!(
            ConnectionTracker::convert_tcp_state(&TcpState::Close),
            ConnectionState::Closed
        );
    }
}
