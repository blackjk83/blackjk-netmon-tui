use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, Table, Row, Cell, Paragraph, Gauge},
    style::{Color, Style, Modifier},
};
use crate::traffic::{TrafficFlow, TrafficEvent, FlowDirection};
use crate::traffic::inspector::EventSeverity;

use crate::utils::formatting::{format_bytes, format_duration};

pub struct FlowTable {
    flows: Vec<FlowTableRow>,
    selected: usize,
    scroll_offset: usize,
}

#[derive(Clone)]
pub struct FlowTableRow {
    pub flow_id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub protocol: String,
    pub direction: FlowDirection,
    pub bandwidth: f64,
    pub packets: u64,
    pub bytes: u64,
    pub duration: std::time::Duration,
    pub active: bool,
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            flows: Vec::new(),
            selected: 0,
            scroll_offset: 0,
        }
    }
    
    pub fn update_flows(&mut self, flows: &std::collections::HashMap<String, TrafficFlow>) {
        self.flows = flows
            .values()
            .map(|flow| FlowTableRow {
                flow_id: flow.flow_id.clone(),
                src_addr: flow.src_addr.to_string(),
                dst_addr: flow.dst_addr.to_string(),
                protocol: format!("{:?}", flow.protocol),
                direction: flow.direction.clone(),
                bandwidth: flow.bytes_per_second,
                packets: flow.packet_count,
                bytes: flow.byte_count,
                duration: std::time::SystemTime::now()
                    .duration_since(flow.start_time)
                    .unwrap_or_default(),
                active: flow.is_active,
            })
            .collect();
        
        // Sort by bandwidth (highest first)
        self.flows.sort_by(|a, b| b.bandwidth.partial_cmp(&a.bandwidth).unwrap_or(std::cmp::Ordering::Equal));
        
        // Reset selection if needed
        if self.selected >= self.flows.len() && !self.flows.is_empty() {
            self.selected = self.flows.len() - 1;
        }
    }
    
    pub fn next(&mut self) {
        if !self.flows.is_empty() {
            self.selected = (self.selected + 1) % self.flows.len();
        }
    }
    
    pub fn previous(&mut self) {
        if !self.flows.is_empty() {
            self.selected = if self.selected == 0 {
                self.flows.len() - 1
            } else {
                self.selected - 1
            };
        }
    }
    
    pub fn render(&mut self, area: Rect, frame: &mut Frame) {
        let header_cells = ["Source", "Destination", "Protocol", "Dir", "Bandwidth", "Packets", "Duration"]
            .iter()
            .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        
        let header = Row::new(header_cells).height(1).bottom_margin(1);
        
        let visible_height = area.height.saturating_sub(3) as usize; // Account for header and borders
        
        // Adjust scroll offset
        if self.selected >= self.scroll_offset + visible_height {
            self.scroll_offset = self.selected.saturating_sub(visible_height - 1);
        } else if self.selected < self.scroll_offset {
            self.scroll_offset = self.selected;
        }
        
        let rows = self.flows
            .iter()
            .skip(self.scroll_offset)
            .take(visible_height)
            .enumerate()
            .map(|(i, flow)| {
                let direction_symbol = match flow.direction {
                    FlowDirection::Inbound => "←",
                    FlowDirection::Outbound => "→",
                    FlowDirection::Internal => "↔",
                    FlowDirection::Unknown => "?",
                };
                
                let bandwidth_str = format!("{}/s", format_bytes(flow.bandwidth as u64));
                let duration_str = format_duration(flow.duration.as_secs());
                
                let style = if self.scroll_offset + i == self.selected {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else if flow.active {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                
                Row::new(vec![
                    Cell::from(flow.src_addr.clone()),
                    Cell::from(flow.dst_addr.clone()),
                    Cell::from(flow.protocol.clone()),
                    Cell::from(direction_symbol),
                    Cell::from(bandwidth_str),
                    Cell::from(flow.packets.to_string()),
                    Cell::from(duration_str),
                ]).style(style)
            });
        
        let widths = [
            Constraint::Length(20), // Source
            Constraint::Length(20), // Destination
            Constraint::Length(8),  // Protocol
            Constraint::Length(3),  // Direction
            Constraint::Length(12), // Bandwidth
            Constraint::Length(10), // Packets
            Constraint::Length(10), // Duration
        ];
        
        let table = Table::new(rows)
            .widths(&widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!("Traffic Flows ({}/{})", self.flows.len(), self.flows.len()))
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");
        
        frame.render_widget(table, area);
    }
}

pub struct EventList {
    events: Vec<EventListItem>,
    max_events: usize,
}

#[derive(Clone)]
pub struct EventListItem {
    pub timestamp: String,
    pub severity: EventSeverity,
    pub event_type: String,
    pub description: String,
}

impl EventList {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Vec::new(),
            max_events,
        }
    }
    
    pub fn add_events(&mut self, events: &[TrafficEvent]) {
        for event in events {
            let timestamp = format!("{:02}:{:02}:{:02}", 
                event.timestamp.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() % 86400 / 3600,
                event.timestamp.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() % 3600 / 60,
                event.timestamp.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() % 60);
            
            self.events.push(EventListItem {
                timestamp,
                severity: event.severity.clone(),
                event_type: format!("{:?}", event.event_type),
                description: event.description.clone(),
            });
        }
        
        // Keep only recent events
        if self.events.len() > self.max_events {
            self.events.drain(0..self.events.len() - self.max_events);
        }
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        let items: Vec<ListItem> = self.events
            .iter()
            .rev() // Show newest first
            .take(area.height.saturating_sub(2) as usize)
            .map(|event| {
                let severity_color = match event.severity {
                    EventSeverity::Info => Color::Green,
                    EventSeverity::Warning => Color::Yellow,
                    EventSeverity::Critical => Color::Red,
                };
                
                let text = format!("[{}] {} - {}", 
                    event.timestamp, 
                    event.event_type, 
                    event.description);
                
                ListItem::new(text).style(Style::default().fg(severity_color))
            })
            .collect();
        
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Traffic Events")
                    .borders(Borders::ALL)
            )
            .style(Style::default().fg(Color::White));
        
        frame.render_widget(list, area);
    }
}

pub struct StatsPanel {
    stats: PanelStats,
}

#[derive(Clone, Default)]
pub struct PanelStats {
    pub total_flows: usize,
    pub active_connections: usize,
    pub total_bandwidth: f64,
    pub packet_rate: f64,
    pub top_protocol: String,
    pub threat_level: String,
    pub uptime: std::time::Duration,
}

impl StatsPanel {
    pub fn new() -> Self {
        Self {
            stats: PanelStats::default(),
        }
    }
    
    pub fn update_stats(&mut self, stats: PanelStats) {
        self.stats = stats;
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        let bandwidth_mb = self.stats.total_bandwidth / 1_000_000.0;
        let uptime_str = format_duration(self.stats.uptime.as_secs());
        
        let content = format!(
            "Active Flows: {}\n\
             Connections: {}\n\
             Bandwidth: {:.2} MB/s\n\
             Packet Rate: {:.0} pps\n\
             Top Protocol: {}\n\
             Threat Level: {}\n\
             Uptime: {}",
            self.stats.total_flows,
            self.stats.active_connections,
            bandwidth_mb,
            self.stats.packet_rate,
            self.stats.top_protocol,
            self.stats.threat_level,
            uptime_str
        );
        
        let paragraph = Paragraph::new(content)
            .block(
                Block::default()
                    .title("System Statistics")
                    .borders(Borders::ALL)
            )
            .style(Style::default().fg(Color::White))
            .wrap(ratatui::widgets::Wrap { trim: true });
        
        frame.render_widget(paragraph, area);
    }
}

pub struct AlertPanel {
    alerts: Vec<AlertItem>,
    max_alerts: usize,
}

#[derive(Clone)]
pub struct AlertItem {
    pub severity: EventSeverity,
    pub title: String,
    pub message: String,
    pub timestamp: std::time::SystemTime,
}

impl AlertPanel {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: Vec::new(),
            max_alerts,
        }
    }
    
    pub fn add_alert(&mut self, severity: EventSeverity, title: String, message: String) {
        self.alerts.push(AlertItem {
            severity,
            title,
            message,
            timestamp: std::time::SystemTime::now(),
        });
        
        // Keep only recent alerts
        if self.alerts.len() > self.max_alerts {
            self.alerts.remove(0);
        }
    }
    
    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        if self.alerts.is_empty() {
            let block = Block::default()
                .title("Alerts")
                .borders(Borders::ALL);
            frame.render_widget(block, area);
            return;
        }
        
        let items: Vec<ListItem> = self.alerts
            .iter()
            .rev() // Show newest first
            .take(area.height.saturating_sub(2) as usize)
            .map(|alert| {
                let severity_symbol = match alert.severity {
                    EventSeverity::Info => "ℹ",
                    EventSeverity::Warning => "⚠",
                    EventSeverity::Critical => "🚨",
                };
                
                let severity_color = match alert.severity {
                    EventSeverity::Info => Color::Blue,
                    EventSeverity::Warning => Color::Yellow,
                    EventSeverity::Critical => Color::Red,
                };
                
                let text = format!("{} {} - {}", 
                    severity_symbol, 
                    alert.title, 
                    alert.message);
                
                ListItem::new(text).style(Style::default().fg(severity_color))
            })
            .collect();
        
        let list = List::new(items)
            .block(
                Block::default()
                    .title(format!("Alerts ({})", self.alerts.len()))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
            )
            .style(Style::default().fg(Color::White));
        
        frame.render_widget(list, area);
    }
}

pub struct BandwidthGauge {
    current_bandwidth: f64,
    max_bandwidth: f64,
    label: String,
}

impl BandwidthGauge {
    pub fn new(label: String, max_bandwidth: f64) -> Self {
        Self {
            current_bandwidth: 0.0,
            max_bandwidth,
            label,
        }
    }
    
    pub fn update(&mut self, bandwidth: f64) {
        self.current_bandwidth = bandwidth;
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        let ratio = (self.current_bandwidth / self.max_bandwidth).min(1.0);
        let percentage = (ratio * 100.0) as u16;
        
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(format!("{} ({:.2} MB/s)", self.label, self.current_bandwidth / 1_000_000.0))
                    .borders(Borders::ALL)
            )
            .gauge_style(Style::default().fg(Color::Cyan))
            .percent(percentage);
        
        frame.render_widget(gauge, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_table_creation() {
        let table = FlowTable::new();
        assert_eq!(table.flows.len(), 0);
        assert_eq!(table.selected, 0);
    }
    
    #[test]
    fn test_event_list_creation() {
        let list = EventList::new(100);
        assert_eq!(list.events.len(), 0);
        assert_eq!(list.max_events, 100);
    }
}
