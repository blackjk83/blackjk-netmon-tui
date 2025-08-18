

/// Format bytes in human-readable format (B, KB, MB, GB, TB)
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Format bandwidth in bits per second
pub fn format_bandwidth(bytes_per_sec: f64) -> String {
    let bits_per_sec = bytes_per_sec * 8.0;
    const UNITS: &[&str] = &["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let mut rate = bits_per_sec;
    let mut unit_index = 0;
    
    while rate >= 1000.0 && unit_index < UNITS.len() - 1 {
        rate /= 1000.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{:.0} {}", rate, UNITS[unit_index])
    } else {
        format!("{:.2} {}", rate, UNITS[unit_index])
    }
}

/// Format duration in human-readable format
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}

/// Truncate string to specified length with ellipsis
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Format IP address for display (handle IPv4/IPv6)
pub fn format_ip_address(addr: &str) -> String {
    // Remove IPv6 brackets if present and truncate long addresses
    let cleaned = addr.trim_start_matches('[').trim_end_matches(']');
    
    if cleaned.contains(':') && cleaned.len() > 20 {
        // IPv6 address - show abbreviated form
        truncate_string(cleaned, 20)
    } else {
        cleaned.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_bandwidth() {
        assert_eq!(format_bandwidth(125.0), "1.00 Kbps");
        assert_eq!(format_bandwidth(125000.0), "1.00 Mbps");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
        assert_eq!(format_duration(90061), "1d 1h");
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hi", 2), "hi");
    }
}
