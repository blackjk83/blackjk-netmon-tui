use std::collections::HashMap;
use std::time::{SystemTime, Duration, Instant};
use crate::capture::InterfaceStats;
use crate::analysis::protocols::{ProtocolType, ProtocolInfo};

#[derive(Debug, Clone)]
pub struct InterfaceMetrics {
    pub interface_name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_rate_bps: f64,  // bytes per second
    pub tx_rate_bps: f64,  // bytes per second
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct NetworkStatistics {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    pub active_connections: usize,
    pub protocol_distribution: HashMap<ProtocolType, ProtocolInfo>,
    pub top_protocols: Vec<(ProtocolType, u64)>, // (protocol, packet_count)
    pub interface_metrics: HashMap<String, InterfaceMetrics>,
    pub uptime: Duration,
    pub start_time: SystemTime,
}

pub struct StatisticsCollector {
    start_time: SystemTime,
    last_update: Instant,
    previous_stats: HashMap<String, InterfaceStats>,
    total_packets: u64,
    total_bytes: u64,
    packet_history: Vec<(Instant, u64)>, // (timestamp, packet_count)
    byte_history: Vec<(Instant, u64)>,   // (timestamp, byte_count)
    history_window: Duration,
}

impl StatisticsCollector {
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
            last_update: Instant::now(),
            previous_stats: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
            packet_history: Vec::new(),
            byte_history: Vec::new(),
            history_window: Duration::from_secs(60), // Keep 1 minute of history
        }
    }
    
    pub fn update_interface_stats(&mut self, interface_stats: &HashMap<String, InterfaceStats>) -> HashMap<String, InterfaceMetrics> {
        let now = Instant::now();
        let mut metrics = HashMap::new();
        
        for (interface_name, current_stats) in interface_stats {
            let mut interface_metrics = InterfaceMetrics {
                interface_name: interface_name.clone(),
                rx_bytes: current_stats.rx_bytes,
                tx_bytes: current_stats.tx_bytes,
                rx_packets: current_stats.rx_packets,
                tx_packets: current_stats.tx_packets,
                rx_errors: current_stats.rx_errors,
                tx_errors: current_stats.tx_errors,
                rx_dropped: current_stats.rx_dropped,
                tx_dropped: current_stats.tx_dropped,
                rx_rate_bps: 0.0,
                tx_rate_bps: 0.0,
                last_update: now,
            };
            
            // Calculate rates if we have previous data
            if let Some(previous_stats) = self.previous_stats.get(interface_name) {
                let time_diff = now.duration_since(self.last_update).as_secs_f64();
                if time_diff > 0.0 {
                    let rx_bytes_diff = current_stats.rx_bytes.saturating_sub(previous_stats.rx_bytes);
                    let tx_bytes_diff = current_stats.tx_bytes.saturating_sub(previous_stats.tx_bytes);
                    
                    interface_metrics.rx_rate_bps = rx_bytes_diff as f64 / time_diff;
                    interface_metrics.tx_rate_bps = tx_bytes_diff as f64 / time_diff;
                }
            }
            
            metrics.insert(interface_name.clone(), interface_metrics);
        }
        
        // Update previous stats for next calculation
        self.previous_stats = interface_stats.clone();
        self.last_update = now;
        
        metrics
    }
    
    pub fn update_packet_stats(&mut self, packets: u64, bytes: u64) {
        let now = Instant::now();
        
        self.total_packets = packets;
        self.total_bytes = bytes;
        
        // Add to history
        self.packet_history.push((now, packets));
        self.byte_history.push((now, bytes));
        
        // Clean old history
        self.cleanup_history();
    }
    
    fn cleanup_history(&mut self) {
        let cutoff = Instant::now() - self.history_window;
        
        self.packet_history.retain(|(timestamp, _)| *timestamp > cutoff);
        self.byte_history.retain(|(timestamp, _)| *timestamp > cutoff);
    }
    
    pub fn calculate_rates(&self) -> (f64, f64) {
        let now = Instant::now();
        let window_start = now - Duration::from_secs(10); // Calculate rate over last 10 seconds
        
        // Find packets/bytes at window start and now
        let packets_start = self.packet_history.iter()
            .find(|(timestamp, _)| *timestamp >= window_start)
            .map(|(_, count)| *count)
            .unwrap_or(0);
        
        let bytes_start = self.byte_history.iter()
            .find(|(timestamp, _)| *timestamp >= window_start)
            .map(|(_, count)| *count)
            .unwrap_or(0);
        
        let time_diff = 10.0; // 10 seconds
        let packets_per_second = (self.total_packets.saturating_sub(packets_start)) as f64 / time_diff;
        let bytes_per_second = (self.total_bytes.saturating_sub(bytes_start)) as f64 / time_diff;
        
        (packets_per_second, bytes_per_second)
    }
    
    pub fn generate_network_statistics(
        &self,
        protocol_stats: &HashMap<ProtocolType, ProtocolInfo>,
        interface_metrics: &HashMap<String, InterfaceMetrics>,
        active_connections: usize,
    ) -> NetworkStatistics {
        let (packets_per_second, bytes_per_second) = self.calculate_rates();
        let uptime = SystemTime::now().duration_since(self.start_time).unwrap_or_default();
        
        // Get top protocols by packet count
        let mut top_protocols: Vec<_> = protocol_stats.iter()
            .map(|(protocol, info)| (protocol.clone(), info.packet_count))
            .collect();
        top_protocols.sort_by(|a, b| b.1.cmp(&a.1));
        top_protocols.truncate(10); // Top 10 protocols
        
        NetworkStatistics {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            packets_per_second,
            bytes_per_second,
            active_connections,
            protocol_distribution: protocol_stats.clone(),
            top_protocols,
            interface_metrics: interface_metrics.clone(),
            uptime,
            start_time: self.start_time,
        }
    }
    
    pub fn get_bandwidth_utilization(&self, interface_metrics: &InterfaceMetrics, interface_speed_mbps: Option<u64>) -> Option<f64> {
        if let Some(speed_mbps) = interface_speed_mbps {
            let speed_bps = (speed_mbps * 1_000_000) as f64; // Convert Mbps to bps
            let total_rate = interface_metrics.rx_rate_bps + interface_metrics.tx_rate_bps;
            Some((total_rate / speed_bps) * 100.0) // Return as percentage
        } else {
            None
        }
    }
    
    pub fn get_error_rate(&self, interface_metrics: &InterfaceMetrics) -> f64 {
        let total_packets = interface_metrics.rx_packets + interface_metrics.tx_packets;
        let total_errors = interface_metrics.rx_errors + interface_metrics.tx_errors;
        
        if total_packets > 0 {
            (total_errors as f64 / total_packets as f64) * 100.0
        } else {
            0.0
        }
    }
    
    pub fn get_drop_rate(&self, interface_metrics: &InterfaceMetrics) -> f64 {
        let total_packets = interface_metrics.rx_packets + interface_metrics.tx_packets;
        let total_dropped = interface_metrics.rx_dropped + interface_metrics.tx_dropped;
        
        if total_packets > 0 {
            (total_dropped as f64 / total_packets as f64) * 100.0
        } else {
            0.0
        }
    }
    
    pub fn reset_statistics(&mut self) {
        self.start_time = SystemTime::now();
        self.last_update = Instant::now();
        self.previous_stats.clear();
        self.total_packets = 0;
        self.total_bytes = 0;
        self.packet_history.clear();
        self.byte_history.clear();
    }
}

impl InterfaceMetrics {
    pub fn get_total_rate_bps(&self) -> f64 {
        self.rx_rate_bps + self.tx_rate_bps
    }
    
    pub fn get_total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }
    
    pub fn get_total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }
    
    pub fn get_total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }
    
    pub fn get_total_dropped(&self) -> u64 {
        self.rx_dropped + self.tx_dropped
    }
}

impl NetworkStatistics {
    pub fn get_top_protocol(&self) -> Option<&ProtocolType> {
        self.top_protocols.first().map(|(protocol, _)| protocol)
    }
    
    pub fn get_protocol_percentage(&self, protocol: &ProtocolType) -> f64 {
        if let Some(info) = self.protocol_distribution.get(protocol) {
            if self.total_packets > 0 {
                (info.packet_count as f64 / self.total_packets as f64) * 100.0
            } else {
                0.0
            }
        } else {
            0.0
        }
    }
    
    pub fn get_total_interface_rate(&self) -> f64 {
        self.interface_metrics.values()
            .map(|metrics| metrics.get_total_rate_bps())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_statistics_collector() {
        let mut collector = StatisticsCollector::new();
        
        // Test packet stats update
        collector.update_packet_stats(100, 50000);
        assert_eq!(collector.total_packets, 100);
        assert_eq!(collector.total_bytes, 50000);
        
        // Test rate calculation (should be 0 initially)
        let (pps, bps) = collector.calculate_rates();
        assert!(pps >= 0.0);
        assert!(bps >= 0.0);
    }
    
    #[test]
    fn test_interface_metrics() {
        let metrics = InterfaceMetrics {
            interface_name: "eth0".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_packets: 10,
            tx_packets: 20,
            rx_errors: 1,
            tx_errors: 2,
            rx_dropped: 0,
            tx_dropped: 1,
            rx_rate_bps: 100.0,
            tx_rate_bps: 200.0,
            last_update: Instant::now(),
        };
        
        assert_eq!(metrics.get_total_bytes(), 3000);
        assert_eq!(metrics.get_total_packets(), 30);
        assert_eq!(metrics.get_total_errors(), 3);
        assert_eq!(metrics.get_total_dropped(), 1);
        assert_eq!(metrics.get_total_rate_bps(), 300.0);
    }
}
