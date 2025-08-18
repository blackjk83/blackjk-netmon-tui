use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Table, Row, Cell, Paragraph},
    style::{Color, Style, Modifier},
};
use std::collections::HashMap;
use crate::analysis::protocols::ProtocolType;
use crate::traffic::{TrafficFlow, FlowDirection};
use crate::utils::formatting::{format_bytes, format_duration};

#[derive(Clone)]
pub struct ProtocolOverview {
    pub protocol: ProtocolType,
    pub flow_count: usize,
    pub total_bandwidth: f64,
    pub client_count: usize,
    pub server_count: usize,
    pub top_clients: Vec<String>,
    pub top_servers: Vec<String>,
    pub percentage: f64,
}

#[derive(Clone)]
pub struct ConnectionSummary {
    pub client: String,
    pub server: String,
    pub protocol: ProtocolType,
    pub direction: FlowDirection,
    pub bandwidth: f64,
    pub packets: u64,
    pub duration: std::time::Duration,
    pub status: String,
}

pub struct ProtocolView {
    protocol_overviews: Vec<ProtocolOverview>,
    active_connections: Vec<ConnectionSummary>,
    selected_protocol: usize,
    selected_connection: usize,
    total_bandwidth: f64,
}

impl ProtocolView {
    pub fn new() -> Self {
        Self {
            protocol_overviews: Vec::new(),
            active_connections: Vec::new(),
            selected_protocol: 0,
            selected_connection: 0,
            total_bandwidth: 0.0,
        }
    }
    
    pub fn update_data(&mut self, flows: &HashMap<String, TrafficFlow>) {
        self.update_protocol_overviews(flows);
        self.update_active_connections(flows);
    }
    
    fn update_protocol_overviews(&mut self, flows: &HashMap<String, TrafficFlow>) {
        let mut protocol_stats: HashMap<ProtocolType, ProtocolStats> = HashMap::new();
        self.total_bandwidth = 0.0;
        
        // Collect statistics per protocol
        for flow in flows.values() {
            let stats = protocol_stats.entry(flow.protocol.clone()).or_insert(ProtocolStats {
                flow_count: 0,
                total_bandwidth: 0.0,
                clients: std::collections::HashSet::new(),
                servers: std::collections::HashSet::new(),
            });
            
            stats.flow_count += 1;
            stats.total_bandwidth += flow.bytes_per_second;
            self.total_bandwidth += flow.bytes_per_second;
            
            // Identify clients and servers based on flow direction
            match flow.direction {
                FlowDirection::Outbound => {
                    stats.clients.insert(flow.src_addr.ip().to_string());
                    stats.servers.insert(flow.dst_addr.ip().to_string());
                }
                FlowDirection::Inbound => {
                    stats.clients.insert(flow.dst_addr.ip().to_string());
                    stats.servers.insert(flow.src_addr.ip().to_string());
                }
                FlowDirection::Internal => {
                    // For internal traffic, consider lower port as server
                    if flow.src_addr.port() < flow.dst_addr.port() {
                        stats.servers.insert(flow.src_addr.ip().to_string());
                        stats.clients.insert(flow.dst_addr.ip().to_string());
                    } else {
                        stats.clients.insert(flow.src_addr.ip().to_string());
                        stats.servers.insert(flow.dst_addr.ip().to_string());
                    }
                }
                FlowDirection::Unknown => {
                    stats.clients.insert(flow.src_addr.ip().to_string());
                    stats.servers.insert(flow.dst_addr.ip().to_string());
                }
            }
        }
        
        // Convert to protocol overviews
        self.protocol_overviews = protocol_stats
            .into_iter()
            .map(|(protocol, stats)| {
                let percentage = if self.total_bandwidth > 0.0 {
                    (stats.total_bandwidth / self.total_bandwidth) * 100.0
                } else {
                    0.0
                };
                
                let mut top_clients: Vec<String> = stats.clients.into_iter().collect();
                let mut top_servers: Vec<String> = stats.servers.into_iter().collect();
                top_clients.sort();
                top_servers.sort();
                
                ProtocolOverview {
                    protocol,
                    flow_count: stats.flow_count,
                    total_bandwidth: stats.total_bandwidth,
                    client_count: top_clients.len(),
                    server_count: top_servers.len(),
                    top_clients: top_clients.into_iter().take(5).collect(),
                    top_servers: top_servers.into_iter().take(5).collect(),
                    percentage,
                }
            })
            .collect();
        
        // Sort by bandwidth (highest first)
        self.protocol_overviews.sort_by(|a, b| b.total_bandwidth.partial_cmp(&a.total_bandwidth).unwrap_or(std::cmp::Ordering::Equal));
        
        // Reset selection if needed
        if self.selected_protocol >= self.protocol_overviews.len() && !self.protocol_overviews.is_empty() {
            self.selected_protocol = 0;
        }
    }
    
    fn update_active_connections(&mut self, flows: &HashMap<String, TrafficFlow>) {
        self.active_connections = flows
            .values()
            .filter(|flow| flow.is_active)
            .map(|flow| {
                let (client, server) = match flow.direction {
                    FlowDirection::Outbound => (flow.src_addr.to_string(), flow.dst_addr.to_string()),
                    FlowDirection::Inbound => (flow.dst_addr.to_string(), flow.src_addr.to_string()),
                    FlowDirection::Internal => {
                        if flow.src_addr.port() < flow.dst_addr.port() {
                            (flow.dst_addr.to_string(), flow.src_addr.to_string())
                        } else {
                            (flow.src_addr.to_string(), flow.dst_addr.to_string())
                        }
                    }
                    FlowDirection::Unknown => (flow.src_addr.to_string(), flow.dst_addr.to_string()),
                };
                
                let status = if flow.bytes_per_second > 1_000_000.0 {
                    "HIGH TRAFFIC".to_string()
                } else if flow.bytes_per_second > 100_000.0 {
                    "ACTIVE".to_string()
                } else {
                    "IDLE".to_string()
                };
                
                ConnectionSummary {
                    client,
                    server,
                    protocol: flow.protocol.clone(),
                    direction: flow.direction.clone(),
                    bandwidth: flow.bytes_per_second,
                    packets: flow.packet_count,
                    duration: std::time::SystemTime::now()
                        .duration_since(flow.start_time)
                        .unwrap_or_default(),
                    status,
                }
            })
            .collect();
        
        // Sort by bandwidth (highest first)
        self.active_connections.sort_by(|a, b| b.bandwidth.partial_cmp(&a.bandwidth).unwrap_or(std::cmp::Ordering::Equal));
        
        // Reset selection if needed
        if self.selected_connection >= self.active_connections.len() && !self.active_connections.is_empty() {
            self.selected_connection = 0;
        }
    }
    
    pub fn next_protocol(&mut self) {
        if !self.protocol_overviews.is_empty() {
            self.selected_protocol = (self.selected_protocol + 1) % self.protocol_overviews.len();
        }
    }
    
    pub fn previous_protocol(&mut self) {
        if !self.protocol_overviews.is_empty() {
            self.selected_protocol = if self.selected_protocol == 0 {
                self.protocol_overviews.len() - 1
            } else {
                self.selected_protocol - 1
            };
        }
    }
    
    pub fn next_connection(&mut self) {
        if !self.active_connections.is_empty() {
            self.selected_connection = (self.selected_connection + 1) % self.active_connections.len();
        }
    }
    
    pub fn previous_connection(&mut self) {
        if !self.active_connections.is_empty() {
            self.selected_connection = if self.selected_connection == 0 {
                self.active_connections.len() - 1
            } else {
                self.selected_connection - 1
            };
        }
    }
    
    pub fn render(&mut self, area: Rect, frame: &mut Frame) {
        // Create layout: Protocol overview (left) | Active connections (right)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        
        self.render_protocol_overview(chunks[0], frame);
        self.render_active_connections(chunks[1], frame);
    }
    
    fn render_protocol_overview(&self, area: Rect, frame: &mut Frame) {
        if self.protocol_overviews.is_empty() {
            let block = Block::default()
                .title("Protocol Overview")
                .borders(Borders::ALL);
            frame.render_widget(block, area);
            return;
        }
        
        let items: Vec<ListItem> = self.protocol_overviews
            .iter()
            .enumerate()
            .map(|(i, overview)| {
                let protocol_name = format!("{:?}", overview.protocol);
                let bandwidth_str = format!("{}/s", format_bytes(overview.total_bandwidth as u64));
                
                let color = match overview.protocol {
                    ProtocolType::Http => Color::Green,
                    ProtocolType::Https => Color::Blue,
                    ProtocolType::Dns => Color::Yellow,
                    ProtocolType::Ssh => Color::Magenta,
                    ProtocolType::Ftp => Color::Cyan,
                    ProtocolType::Smtp => Color::Red,
                    _ => Color::White,
                };
                
                let style = if i == self.selected_protocol {
                    Style::default().bg(Color::DarkGray).fg(color).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color)
                };
                
                let text = format!(
                    "{:<8} │ {:>3} flows │ {:>10} │ {:.1}% │ {}↔{}",
                    protocol_name,
                    overview.flow_count,
                    bandwidth_str,
                    overview.percentage,
                    overview.client_count,
                    overview.server_count
                );
                
                ListItem::new(text).style(style)
            })
            .collect();
        
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Protocol Overview (↑↓ to navigate)")
                    .borders(Borders::ALL)
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");
        
        frame.render_widget(list, area);
    }
    
    fn render_active_connections(&self, area: Rect, frame: &mut Frame) {
        // Split into connections table and details
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(area);
        
        self.render_connections_table(chunks[0], frame);
        self.render_connection_details(chunks[1], frame);
    }
    
    fn render_connections_table(&self, area: Rect, frame: &mut Frame) {
        if self.active_connections.is_empty() {
            let block = Block::default()
                .title("Active Connections")
                .borders(Borders::ALL);
            frame.render_widget(block, area);
            return;
        }
        
        let header_cells = ["Client", "Server", "Protocol", "Status", "Bandwidth"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        
        let header = Row::new(header_cells).height(1).bottom_margin(1);
        
        let rows = self.active_connections
            .iter()
            .take(area.height.saturating_sub(3) as usize) // Account for header and borders
            .enumerate()
            .map(|(i, conn)| {
                let bandwidth_str = format!("{}/s", format_bytes(conn.bandwidth as u64));
                let protocol_str = format!("{:?}", conn.protocol);
                
                let status_color = match conn.status.as_str() {
                    "HIGH TRAFFIC" => Color::Red,
                    "ACTIVE" => Color::Green,
                    "IDLE" => Color::Gray,
                    _ => Color::White,
                };
                
                let style = if i == self.selected_connection {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else {
                    Style::default().fg(Color::White)
                };
                
                Row::new(vec![
                    Cell::from(conn.client.clone()),
                    Cell::from(conn.server.clone()),
                    Cell::from(protocol_str),
                    Cell::from(conn.status.clone()).style(Style::default().fg(status_color)),
                    Cell::from(bandwidth_str),
                ]).style(style)
            });
        
        let widths = [
            Constraint::Length(20), // Client
            Constraint::Length(20), // Server
            Constraint::Length(8),  // Protocol
            Constraint::Length(12), // Status
            Constraint::Length(12), // Bandwidth
        ];
        
        let table = Table::new(rows)
            .widths(&widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Active Connections (Tab to navigate)")
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");
        
        frame.render_widget(table, area);
    }
    
    fn render_connection_details(&self, area: Rect, frame: &mut Frame) {
        let content = if let Some(conn) = self.active_connections.get(self.selected_connection) {
            let duration_str = format_duration(conn.duration.as_secs());
            format!(
                "Selected Connection Details:\n\
                 Client: {} → Server: {}\n\
                 Protocol: {:?} | Direction: {}\n\
                 Bandwidth: {}/s | Packets: {}\n\
                 Duration: {} | Status: {}",
                conn.client,
                conn.server,
                conn.protocol,
                conn.direction,
                format_bytes(conn.bandwidth as u64),
                conn.packets,
                duration_str,
                conn.status
            )
        } else {
            "No connection selected".to_string()
        };
        
        let paragraph = Paragraph::new(content)
            .block(
                Block::default()
                    .title("Connection Details")
                    .borders(Borders::ALL)
            )
            .style(Style::default().fg(Color::White))
            .wrap(ratatui::widgets::Wrap { trim: true });
        
        frame.render_widget(paragraph, area);
    }
}

struct ProtocolStats {
    flow_count: usize,
    total_bandwidth: f64,
    clients: std::collections::HashSet<String>,
    servers: std::collections::HashSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_view_creation() {
        let view = ProtocolView::new();
        assert_eq!(view.protocol_overviews.len(), 0);
        assert_eq!(view.active_connections.len(), 0);
    }
}
