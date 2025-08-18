#[derive(Debug, Clone)]
pub struct AdvancedFeatures {
    pub firewall_enabled: bool,
    pub metrics_explorer_enabled: bool,
    pub fuzzy_search_enabled: bool,
    pub deep_packet_inspection: bool,
    pub historical_analysis: bool,
}

impl AdvancedFeatures {
    pub fn new() -> Self {
        Self {
            firewall_enabled: false,
            metrics_explorer_enabled: false,
            fuzzy_search_enabled: false,
            deep_packet_inspection: false,
            historical_analysis: false,
        }
    }
    
    pub fn from_cli_args(
        enable_firewall: bool,
        enable_metrics: bool,
        enable_search: bool,
        enable_all: bool,
    ) -> Self {
        Self {
            firewall_enabled: enable_firewall || enable_all,
            metrics_explorer_enabled: enable_metrics || enable_all,
            fuzzy_search_enabled: enable_search || enable_all,
            deep_packet_inspection: enable_all,
            historical_analysis: enable_metrics || enable_all,
        }
    }
    
    pub fn enable_firewall(&mut self) {
        self.firewall_enabled = true;
    }
    
    pub fn enable_metrics(&mut self) {
        self.metrics_explorer_enabled = true;
        self.historical_analysis = true;
    }
    
    pub fn enable_search(&mut self) {
        self.fuzzy_search_enabled = true;
    }
    
    pub fn disable_firewall(&mut self) {
        self.firewall_enabled = false;
    }
    
    pub fn disable_metrics(&mut self) {
        self.metrics_explorer_enabled = false;
        self.historical_analysis = false;
    }
    
    pub fn disable_search(&mut self) {
        self.fuzzy_search_enabled = false;
    }
    
    pub fn has_any_advanced_features(&self) -> bool {
        self.firewall_enabled || 
        self.metrics_explorer_enabled || 
        self.fuzzy_search_enabled ||
        self.deep_packet_inspection ||
        self.historical_analysis
    }
    
    pub fn get_enabled_features(&self) -> Vec<String> {
        let mut features = Vec::new();
        
        if self.firewall_enabled {
            features.push("Firewall".to_string());
        }
        if self.metrics_explorer_enabled {
            features.push("Metrics Explorer".to_string());
        }
        if self.fuzzy_search_enabled {
            features.push("Fuzzy Search".to_string());
        }
        if self.deep_packet_inspection {
            features.push("Deep Packet Inspection".to_string());
        }
        if self.historical_analysis {
            features.push("Historical Analysis".to_string());
        }
        
        features
    }
    
    pub fn get_memory_usage_estimate(&self) -> usize {
        let mut memory_kb = 0;
        
        if self.firewall_enabled {
            memory_kb += 512; // Firewall rules and state tracking
        }
        if self.metrics_explorer_enabled {
            memory_kb += 1024; // Historical data storage
        }
        if self.fuzzy_search_enabled {
            memory_kb += 256; // Search indices
        }
        if self.deep_packet_inspection {
            memory_kb += 2048; // Packet analysis buffers
        }
        if self.historical_analysis {
            memory_kb += 1536; // Time-series data
        }
        
        memory_kb
    }
}

impl Default for AdvancedFeatures {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advanced_features_default() {
        let features = AdvancedFeatures::new();
        assert!(!features.has_any_advanced_features());
        assert_eq!(features.get_enabled_features().len(), 0);
    }
    
    #[test]
    fn test_advanced_features_from_cli() {
        let features = AdvancedFeatures::from_cli_args(true, false, false, false);
        assert!(features.firewall_enabled);
        assert!(!features.metrics_explorer_enabled);
        assert!(!features.fuzzy_search_enabled);
    }
    
    #[test]
    fn test_enable_all_advanced() {
        let features = AdvancedFeatures::from_cli_args(false, false, false, true);
        assert!(features.has_any_advanced_features());
        assert!(features.firewall_enabled);
        assert!(features.metrics_explorer_enabled);
        assert!(features.fuzzy_search_enabled);
    }
}
