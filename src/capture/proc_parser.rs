use std::fs;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: TcpState,
    pub inode: u64,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

pub struct ProcNetParser;

impl ProcNetParser {
    /// Parse /proc/net/tcp for connection info - WORKS ON KERNEL 5.x
    pub fn get_tcp_connections() -> Result<Vec<TcpConnection>, std::io::Error> {
        let content = fs::read_to_string("/proc/net/tcp")?;
        let mut connections = Vec::new();
        
        for line in content.lines().skip(1) {
            if let Some(conn) = Self::parse_tcp_line(line) {
                connections.push(conn);
            }
        }
        Ok(connections)
    }
    
    /// Parse interface statistics - RELIABLE ON ALL KERNELS
    pub fn get_interface_stats(interface: &str) -> Result<InterfaceStats, std::io::Error> {
        let base_path = format!("/sys/class/net/{}/statistics", interface);
        
        let rx_bytes = Self::read_stat_file(&format!("{}/rx_bytes", base_path))?;
        let tx_bytes = Self::read_stat_file(&format!("{}/tx_bytes", base_path))?;
        let rx_packets = Self::read_stat_file(&format!("{}/rx_packets", base_path))?;
        let tx_packets = Self::read_stat_file(&format!("{}/tx_packets", base_path))?;
        let rx_errors = Self::read_stat_file(&format!("{}/rx_errors", base_path))?;
        let tx_errors = Self::read_stat_file(&format!("{}/tx_errors", base_path))?;
        let rx_dropped = Self::read_stat_file(&format!("{}/rx_dropped", base_path))?;
        let tx_dropped = Self::read_stat_file(&format!("{}/tx_dropped", base_path))?;
        
        Ok(InterfaceStats {
            interface: interface.to_string(),
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            rx_dropped,
            tx_dropped,
        })
    }
    
    /// Get all available network interfaces
    pub fn get_interfaces() -> Result<Vec<String>, std::io::Error> {
        let mut interfaces = Vec::new();
        
        for entry in fs::read_dir("/sys/class/net")? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                // Skip loopback and virtual interfaces for main monitoring
                if !name.starts_with("lo") && !name.starts_with("veth") {
                    interfaces.push(name.to_string());
                }
            }
        }
        
        interfaces.sort();
        Ok(interfaces)
    }
    
    /// Parse a single line from /proc/net/tcp
    fn parse_tcp_line(line: &str) -> Option<TcpConnection> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        
        // Parse local address (format: XXXXXXXX:XXXX)
        let local_addr = Self::parse_address(fields[1])?;
        
        // Parse remote address
        let remote_addr = Self::parse_address(fields[2])?;
        
        // Parse state
        let state_num = u8::from_str_radix(fields[3], 16).ok()?;
        let state = Self::parse_tcp_state(state_num);
        
        // Parse inode
        let inode = fields[9].parse().ok()?;
        
        // Parse UID
        let uid = fields[7].parse().ok()?;
        
        Some(TcpConnection {
            local_addr,
            remote_addr,
            state,
            inode,
            uid,
        })
    }
    
    /// Parse address from hex format (XXXXXXXX:XXXX)
    pub fn parse_address(addr_str: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            return None;
        }
        
        // Parse IP address (little-endian hex)
        let ip_hex = parts[0];
        if ip_hex.len() != 8 {
            return None;
        }
        
        let ip_bytes = (0..4)
            .map(|i| u8::from_str_radix(&ip_hex[i*2..i*2+2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .ok()?;
        
        // Convert from little-endian
        let ip = Ipv4Addr::new(ip_bytes[3], ip_bytes[2], ip_bytes[1], ip_bytes[0]);
        
        // Parse port (big-endian hex)
        let port = u16::from_str_radix(parts[1], 16).ok()?;
        
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
    
    /// Convert numeric TCP state to enum
    pub fn parse_tcp_state(state: u8) -> TcpState {
        match state {
            0x01 => TcpState::Established,
            0x02 => TcpState::SynSent,
            0x03 => TcpState::SynRecv,
            0x04 => TcpState::FinWait1,
            0x05 => TcpState::FinWait2,
            0x06 => TcpState::TimeWait,
            0x07 => TcpState::Close,
            0x08 => TcpState::CloseWait,
            0x09 => TcpState::LastAck,
            0x0A => TcpState::Listen,
            0x0B => TcpState::Closing,
            _ => TcpState::Unknown(state),
        }
    }
    
    /// Read a single statistic file and parse as u64
    fn read_stat_file(path: &str) -> Result<u64, std::io::Error> {
        let content = fs::read_to_string(path)?;
        content.trim().parse().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse stat file {}: {}", path, e)
            )
        })
    }
    
    /// Get UDP connections from /proc/net/udp
    pub fn get_udp_connections() -> Result<Vec<TcpConnection>, std::io::Error> {
        let content = fs::read_to_string("/proc/net/udp")?;
        let mut connections = Vec::new();
        
        for line in content.lines().skip(1) {
            if let Some(mut conn) = Self::parse_tcp_line(line) {
                // UDP connections don't have traditional states, mark as Listen
                conn.state = TcpState::Listen;
                connections.push(conn);
            }
        }
        Ok(connections)
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynRecv => write!(f, "SYN_RECV"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT2"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
            TcpState::Close => write!(f, "CLOSE"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::Unknown(state) => write!(f, "UNKNOWN({})", state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::Listen.to_string(), "LISTEN");
        assert_eq!(TcpState::Unknown(42).to_string(), "UNKNOWN(42)");
    }

    #[test]
    fn test_parse_tcp_state() {
        assert!(matches!(ProcNetParser::parse_tcp_state(0x01), TcpState::Established));
        assert!(matches!(ProcNetParser::parse_tcp_state(0x0A), TcpState::Listen));
        assert!(matches!(ProcNetParser::parse_tcp_state(0xFF), TcpState::Unknown(255)));
    }

    #[test]
    fn test_parse_address() {
        // Test parsing localhost:80 (0100007F:0050)
        if let Some(addr) = ProcNetParser::parse_address("0100007F:0050") {
            assert_eq!(addr.to_string(), "127.0.0.1:80");
        } else {
            panic!("Failed to parse valid address");
        }
    }
}
