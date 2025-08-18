use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration, Instant};
use crate::analysis::protocols::ProtocolType;
use crate::traffic::{TrafficFlow, FlowDirection};

#[derive(Debug, Clone)]
pub struct TrafficPattern {
    pub pattern_id: String,
    pub description: String,
    pub confidence: f64, // 0.0 to 1.0
    pub detected_at: SystemTime,
    pub pattern_type: PatternType,
    pub related_flows: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    BurstTraffic,
    SteadyStream,
    PeriodicSpikes,
    AnomalousActivity,
    DDoSPattern,
    PortScan,
    DataExfiltration,
}

#[derive(Debug, Clone)]
pub struct BandwidthAnalysis {
    pub total_bandwidth: f64, // bytes per second
    pub inbound_bandwidth: f64,
    pub outbound_bandwidth: f64,
    pub internal_bandwidth: f64,
    pub peak_bandwidth: f64,
    pub average_bandwidth: f64,
    pub bandwidth_utilization: f64, // percentage
    pub bandwidth_history: VecDeque<BandwidthSample>,
}

#[derive(Debug, Clone)]
pub struct BandwidthSample {
    pub timestamp: SystemTime,
    pub total_bps: f64,
    pub inbound_bps: f64,
    pub outbound_bps: f64,
    pub internal_bps: f64,
}

#[derive(Debug, Clone)]
pub struct ProtocolBreakdown {
    pub protocol_stats: HashMap<ProtocolType, ProtocolStats>,
    pub top_protocols: Vec<(ProtocolType, f64)>, // (protocol, percentage)
    pub total_flows: usize,
    pub total_bandwidth: f64,
}

#[derive(Debug, Clone)]
pub struct ProtocolStats {
    pub flow_count: usize,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub bandwidth_bps: f64,
    pub packet_rate_pps: f64,
    pub percentage_of_total: f64,
}

#[derive(Debug, Clone)]
pub struct GeographicAnalysis {
    pub country_stats: HashMap<String, CountryStats>,
    pub top_countries: Vec<(String, usize)>, // (country, connection_count)
    pub suspicious_regions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CountryStats {
    pub connection_count: usize,
    pub total_bandwidth: f64,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct TrafficAnalyzer {
    bandwidth_samples: VecDeque<BandwidthSample>,
    detected_patterns: VecDeque<TrafficPattern>,
    protocol_cache: HashMap<ProtocolType, ProtocolStats>,
    analysis_window: Duration,
    sample_interval: Duration,
    max_samples: usize,
    max_patterns: usize,
    last_analysis: Instant,
    
    // Thresholds for pattern detection
    burst_threshold: f64,
    anomaly_threshold: f64,
    ddos_threshold: usize,
}

impl TrafficAnalyzer {
    pub fn new() -> Self {
        Self {
            bandwidth_samples: VecDeque::new(),
            detected_patterns: VecDeque::new(),
            protocol_cache: HashMap::new(),
            analysis_window: Duration::from_secs(300), // 5 minutes
            sample_interval: Duration::from_secs(1),
            max_samples: 3600, // 1 hour at 1-second intervals
            max_patterns: 100,
            last_analysis: Instant::now(),
            burst_threshold: 10.0, // 10x average
            anomaly_threshold: 5.0, // 5x standard deviation
            ddos_threshold: 100, // 100+ flows from single source
        }
    }
    
    pub fn with_config(
        analysis_window_secs: u64,
        sample_interval_secs: u64,
        max_samples: usize,
        burst_threshold: f64,
    ) -> Self {
        let mut analyzer = Self::new();
        analyzer.analysis_window = Duration::from_secs(analysis_window_secs);
        analyzer.sample_interval = Duration::from_secs(sample_interval_secs);
        analyzer.max_samples = max_samples;
        analyzer.burst_threshold = burst_threshold;
        analyzer
    }
    
    pub fn analyze_traffic(&mut self, flows: &HashMap<String, TrafficFlow>) -> TrafficAnalysisResult {
        let now = Instant::now();
        
        // Only analyze if enough time has passed
        if now.duration_since(self.last_analysis) < self.sample_interval {
            return self.get_cached_analysis();
        }
        
        self.last_analysis = now;
        
        // Collect bandwidth sample
        let bandwidth_sample = self.collect_bandwidth_sample(flows);
        self.bandwidth_samples.push_back(bandwidth_sample.clone());
        
        // Maintain sample history
        while self.bandwidth_samples.len() > self.max_samples {
            self.bandwidth_samples.pop_front();
        }
        
        // Perform comprehensive analysis
        let bandwidth_analysis = self.analyze_bandwidth();
        let protocol_breakdown = self.analyze_protocols(flows);
        let detected_patterns = self.detect_patterns(flows);
        let geographic_analysis = self.analyze_geography(flows);
        
        // Update pattern cache
        for pattern in detected_patterns {
            self.detected_patterns.push_back(pattern);
            if self.detected_patterns.len() > self.max_patterns {
                self.detected_patterns.pop_front();
            }
        }
        
        TrafficAnalysisResult {
            bandwidth_analysis,
            protocol_breakdown,
            patterns: self.detected_patterns.iter().cloned().collect(),
            geographic_analysis,
            analysis_timestamp: SystemTime::now(),
        }
    }
    
    fn collect_bandwidth_sample(&self, flows: &HashMap<String, TrafficFlow>) -> BandwidthSample {
        let mut total_bps = 0.0;
        let mut inbound_bps = 0.0;
        let mut outbound_bps = 0.0;
        let mut internal_bps = 0.0;
        
        for flow in flows.values() {
            match flow.direction {
                FlowDirection::Inbound => inbound_bps += flow.bytes_per_second,
                FlowDirection::Outbound => outbound_bps += flow.bytes_per_second,
                FlowDirection::Internal => internal_bps += flow.bytes_per_second,
                FlowDirection::Unknown => total_bps += flow.bytes_per_second,
            }
        }
        
        total_bps = inbound_bps + outbound_bps + internal_bps;
        
        BandwidthSample {
            timestamp: SystemTime::now(),
            total_bps,
            inbound_bps,
            outbound_bps,
            internal_bps,
        }
    }
    
    fn analyze_bandwidth(&self) -> BandwidthAnalysis {
        if self.bandwidth_samples.is_empty() {
            return BandwidthAnalysis {
                total_bandwidth: 0.0,
                inbound_bandwidth: 0.0,
                outbound_bandwidth: 0.0,
                internal_bandwidth: 0.0,
                peak_bandwidth: 0.0,
                average_bandwidth: 0.0,
                bandwidth_utilization: 0.0,
                bandwidth_history: VecDeque::new(),
            };
        }
        
        let latest = self.bandwidth_samples.back().unwrap();
        let total_bandwidth = latest.total_bps;
        let inbound_bandwidth = latest.inbound_bps;
        let outbound_bandwidth = latest.outbound_bps;
        let internal_bandwidth = latest.internal_bps;
        
        // Calculate statistics over the analysis window
        let recent_samples: Vec<_> = self.bandwidth_samples
            .iter()
            .rev()
            .take(300) // Last 5 minutes at 1-second intervals
            .collect();
        
        let peak_bandwidth = recent_samples
            .iter()
            .map(|sample| sample.total_bps)
            .fold(0.0, f64::max);
        
        let average_bandwidth = if !recent_samples.is_empty() {
            recent_samples.iter().map(|sample| sample.total_bps).sum::<f64>() / recent_samples.len() as f64
        } else {
            0.0
        };
        
        // Assume 1 Gbps interface for utilization calculation
        let interface_capacity = 1_000_000_000.0; // 1 Gbps in bytes/sec
        let bandwidth_utilization = (total_bandwidth / interface_capacity * 100.0).min(100.0);
        
        BandwidthAnalysis {
            total_bandwidth,
            inbound_bandwidth,
            outbound_bandwidth,
            internal_bandwidth,
            peak_bandwidth,
            average_bandwidth,
            bandwidth_utilization,
            bandwidth_history: self.bandwidth_samples.clone(),
        }
    }
    
    fn analyze_protocols(&mut self, flows: &HashMap<String, TrafficFlow>) -> ProtocolBreakdown {
        let mut protocol_stats: HashMap<ProtocolType, ProtocolStats> = HashMap::new();
        let mut total_bandwidth = 0.0;
        let total_flows = flows.len();
        
        // Collect statistics for each protocol
        for flow in flows.values() {
            let stats = protocol_stats.entry(flow.protocol.clone()).or_insert(ProtocolStats {
                flow_count: 0,
                total_bytes: 0,
                total_packets: 0,
                bandwidth_bps: 0.0,
                packet_rate_pps: 0.0,
                percentage_of_total: 0.0,
            });
            
            stats.flow_count += 1;
            stats.total_bytes += flow.byte_count;
            stats.total_packets += flow.packet_count;
            stats.bandwidth_bps += flow.bytes_per_second;
            stats.packet_rate_pps += flow.packets_per_second;
            
            total_bandwidth += flow.bytes_per_second;
        }
        
        // Calculate percentages
        for stats in protocol_stats.values_mut() {
            stats.percentage_of_total = if total_bandwidth > 0.0 {
                (stats.bandwidth_bps / total_bandwidth) * 100.0
            } else {
                0.0
            };
        }
        
        // Create top protocols list
        let mut top_protocols: Vec<_> = protocol_stats
            .iter()
            .map(|(protocol, stats)| (protocol.clone(), stats.percentage_of_total))
            .collect();
        top_protocols.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Cache results
        self.protocol_cache = protocol_stats.clone();
        
        ProtocolBreakdown {
            protocol_stats,
            top_protocols,
            total_flows,
            total_bandwidth,
        }
    }
    
    fn detect_patterns(&self, flows: &HashMap<String, TrafficFlow>) -> Vec<TrafficPattern> {
        let mut patterns = Vec::new();
        let _now = SystemTime::now();
        
        // Detect burst traffic patterns
        if let Some(burst_pattern) = self.detect_burst_pattern() {
            patterns.push(burst_pattern);
        }
        
        // Detect DDoS patterns
        if let Some(ddos_pattern) = self.detect_ddos_pattern(flows) {
            patterns.push(ddos_pattern);
        }
        
        // Detect port scan patterns
        if let Some(scan_pattern) = self.detect_port_scan_pattern(flows) {
            patterns.push(scan_pattern);
        }
        
        // Detect anomalous activity
        if let Some(anomaly_pattern) = self.detect_anomaly_pattern() {
            patterns.push(anomaly_pattern);
        }
        
        patterns
    }
    
    fn detect_burst_pattern(&self) -> Option<TrafficPattern> {
        if self.bandwidth_samples.len() < 10 {
            return None;
        }
        
        let recent_samples: Vec<_> = self.bandwidth_samples.iter().rev().take(10).collect();
        let current_bps = recent_samples[0].total_bps;
        let avg_bps: f64 = recent_samples.iter().map(|s| s.total_bps).sum::<f64>() / recent_samples.len() as f64;
        
        if current_bps > avg_bps * self.burst_threshold {
            Some(TrafficPattern {
                pattern_id: format!("burst_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                description: format!("Traffic burst detected: {:.2} MB/s ({}x average)", 
                    current_bps / 1_000_000.0, 
                    current_bps / avg_bps.max(1.0)),
                confidence: 0.8,
                detected_at: SystemTime::now(),
                pattern_type: PatternType::BurstTraffic,
                related_flows: Vec::new(),
            })
        } else {
            None
        }
    }
    
    fn detect_ddos_pattern(&self, flows: &HashMap<String, TrafficFlow>) -> Option<TrafficPattern> {
        // Group flows by source IP
        let mut source_counts: HashMap<std::net::IpAddr, usize> = HashMap::new();
        
        for flow in flows.values() {
            *source_counts.entry(flow.src_addr.ip()).or_insert(0) += 1;
        }
        
        // Check for sources with excessive connections
        for (source_ip, count) in source_counts {
            if count > self.ddos_threshold {
                return Some(TrafficPattern {
                    pattern_id: format!("ddos_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                    description: format!("Potential DDoS from {}: {} connections", source_ip, count),
                    confidence: 0.9,
                    detected_at: SystemTime::now(),
                    pattern_type: PatternType::DDoSPattern,
                    related_flows: flows.values()
                        .filter(|flow| flow.src_addr.ip() == source_ip)
                        .map(|flow| flow.flow_id.clone())
                        .collect(),
                });
            }
        }
        
        None
    }
    
    fn detect_port_scan_pattern(&self, flows: &HashMap<String, TrafficFlow>) -> Option<TrafficPattern> {
        // Group by source IP and count unique destination ports
        let mut scan_detection: HashMap<std::net::IpAddr, std::collections::HashSet<u16>> = HashMap::new();
        
        for flow in flows.values() {
            scan_detection.entry(flow.src_addr.ip())
                .or_insert_with(std::collections::HashSet::new)
                .insert(flow.dst_addr.port());
        }
        
        // Check for sources connecting to many different ports
        for (source_ip, ports) in scan_detection {
            if ports.len() > 20 { // Threshold for port scan detection
                return Some(TrafficPattern {
                    pattern_id: format!("portscan_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                    description: format!("Port scan detected from {}: {} unique ports", source_ip, ports.len()),
                    confidence: 0.85,
                    detected_at: SystemTime::now(),
                    pattern_type: PatternType::PortScan,
                    related_flows: flows.values()
                        .filter(|flow| flow.src_addr.ip() == source_ip)
                        .map(|flow| flow.flow_id.clone())
                        .collect(),
                });
            }
        }
        
        None
    }
    
    fn detect_anomaly_pattern(&self) -> Option<TrafficPattern> {
        if self.bandwidth_samples.len() < 60 {
            return None;
        }
        
        let recent_samples: Vec<_> = self.bandwidth_samples.iter().rev().take(60).collect();
        let values: Vec<f64> = recent_samples.iter().map(|s| s.total_bps).collect();
        
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();
        
        let current_value = values[0];
        
        if (current_value - mean).abs() > std_dev * self.anomaly_threshold {
            Some(TrafficPattern {
                pattern_id: format!("anomaly_{}", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()),
                description: format!("Traffic anomaly detected: {:.2} MB/s ({:.1}σ from mean)", 
                    current_value / 1_000_000.0, 
                    (current_value - mean).abs() / std_dev.max(1.0)),
                confidence: 0.7,
                detected_at: SystemTime::now(),
                pattern_type: PatternType::AnomalousActivity,
                related_flows: Vec::new(),
            })
        } else {
            None
        }
    }
    
    fn analyze_geography(&self, _flows: &HashMap<String, TrafficFlow>) -> GeographicAnalysis {
        // Placeholder for geographic analysis
        // In a real implementation, this would use GeoIP databases
        GeographicAnalysis {
            country_stats: HashMap::new(),
            top_countries: Vec::new(),
            suspicious_regions: Vec::new(),
        }
    }
    
    fn get_cached_analysis(&self) -> TrafficAnalysisResult {
        TrafficAnalysisResult {
            bandwidth_analysis: BandwidthAnalysis {
                total_bandwidth: 0.0,
                inbound_bandwidth: 0.0,
                outbound_bandwidth: 0.0,
                internal_bandwidth: 0.0,
                peak_bandwidth: 0.0,
                average_bandwidth: 0.0,
                bandwidth_utilization: 0.0,
                bandwidth_history: VecDeque::new(),
            },
            protocol_breakdown: ProtocolBreakdown {
                protocol_stats: self.protocol_cache.clone(),
                top_protocols: Vec::new(),
                total_flows: 0,
                total_bandwidth: 0.0,
            },
            patterns: self.detected_patterns.iter().cloned().collect(),
            geographic_analysis: GeographicAnalysis {
                country_stats: HashMap::new(),
                top_countries: Vec::new(),
                suspicious_regions: Vec::new(),
            },
            analysis_timestamp: SystemTime::now(),
        }
    }
    
    pub fn get_pattern_history(&self) -> &VecDeque<TrafficPattern> {
        &self.detected_patterns
    }
    
    pub fn get_bandwidth_history(&self) -> &VecDeque<BandwidthSample> {
        &self.bandwidth_samples
    }
}

#[derive(Debug, Clone)]
pub struct TrafficAnalysisResult {
    pub bandwidth_analysis: BandwidthAnalysis,
    pub protocol_breakdown: ProtocolBreakdown,
    pub patterns: Vec<TrafficPattern>,
    pub geographic_analysis: GeographicAnalysis,
    pub analysis_timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_analyzer_creation() {
        let analyzer = TrafficAnalyzer::new();
        assert_eq!(analyzer.bandwidth_samples.len(), 0);
        assert_eq!(analyzer.detected_patterns.len(), 0);
    }
    
    #[test]
    fn test_bandwidth_sample_collection() {
        let analyzer = TrafficAnalyzer::new();
        let flows = HashMap::new();
        let sample = analyzer.collect_bandwidth_sample(&flows);
        assert_eq!(sample.total_bps, 0.0);
    }
}
