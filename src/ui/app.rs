use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row, Cell},
    layout::{Layout, Constraint, Direction, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    Terminal, Frame,
};
use crossterm::{
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    ExecutableCommand,
};
use std::io;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use crate::capture::{PcapEngine, PacketInfo, ProcNetParser, TcpConnection, InterfaceStats};
use crate::analysis::{ConnectionTracker, StatisticsCollector, NetworkStatistics};
use crate::ui::protocol_view::ProtocolView;
use crate::traffic::{TrafficInspector, TrafficAnalyzer};
use crate::config::AdvancedFeatures;
use crate::firewall::{FirewallEngine, FirewallView};

pub struct App {
    pub should_quit: bool,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub current_connections: Vec<TcpConnection>,
    pub recent_packets: Vec<PacketInfo>,
    pub interface_stats: Option<InterfaceStats>,
    pub selected_tab: usize,
    pub last_update: Instant,
    pub capture_engine: Option<PcapEngine>,
    pub interface: String,
    // Phase 2 enhancements
    pub connection_tracker: ConnectionTracker,
    pub statistics_collector: StatisticsCollector,
    pub network_statistics: Option<NetworkStatistics>,
    pub interface_metrics: HashMap<String, crate::analysis::InterfaceMetrics>,
    // Phase 3 enhancements
    // Phase 3: Traffic inspection and analysis
    pub traffic_inspector: TrafficInspector,
    pub traffic_analyzer: TrafficAnalyzer,
    pub protocol_view: ProtocolView,
    
    // Advanced features (opt-in)
    pub advanced_features: AdvancedFeatures,
    pub firewall_engine: Option<FirewallEngine>,
    pub firewall_view: Option<FirewallView>,
}

impl App {
    pub fn new() -> App {
        Self::with_advanced_features(AdvancedFeatures::new())
    }
    
    pub fn with_advanced_features(advanced_features: AdvancedFeatures) -> App {
        App {
            should_quit: false,
            packets_captured: 0,
            bytes_captured: 0,
            current_connections: Vec::new(),
            recent_packets: Vec::new(),
            interface_stats: None,
            selected_tab: 0,
            last_update: Instant::now(),
            capture_engine: None,
            interface: "any".to_string(),
            // Phase 2 enhancements
            connection_tracker: ConnectionTracker::new(),
            statistics_collector: StatisticsCollector::new(),
            network_statistics: None,
            interface_metrics: HashMap::new(),
            // Phase 3 enhancements
            protocol_view: ProtocolView::new(),
            traffic_inspector: TrafficInspector::new(),
            traffic_analyzer: TrafficAnalyzer::new(),
            advanced_features: advanced_features.clone(),
            firewall_engine: if advanced_features.firewall_enabled {
                let mut engine = FirewallEngine::new();
                engine.load_default_rules();
                Some(engine)
            } else {
                None
            },
            firewall_view: if advanced_features.firewall_enabled {
                Some(FirewallView::new())
            } else {
                None
            },
        }
    }
    
    pub fn initialize_capture(&mut self, interface: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
        match PcapEngine::new(interface.clone()) {
            Ok(mut engine) => {
                engine.start_capture()?;
                self.interface = interface.unwrap_or_else(|| "any".to_string());
                self.capture_engine = Some(engine);
                Ok(())
            },
            Err(e) => {
                // Graceful fallback - continue without packet capture
                eprintln!("Warning: Packet capture unavailable: {}", e);
                eprintln!("Continuing with connection monitoring only...");
                self.interface = interface.unwrap_or_else(|| "eth0".to_string());
                Ok(())
            }
        }
    }
    
    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // CRITICAL: Proper terminal setup for Rocky Linux
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        stdout.execute(EnableMouseCapture)?;
        
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Main application loop
        loop {
            // Update data periodically
            if self.last_update.elapsed() >= Duration::from_millis(1000) {
                self.update_data();
                self.last_update = Instant::now();
            }
            
            terminal.draw(|f| self.draw(f))?;
            
            if self.should_quit {
                break;
            }
            
            // Handle events
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => self.should_quit = true,
                        KeyCode::Tab => {
                            let max_tabs = if self.advanced_features.firewall_enabled { 5 } else { 4 };
                            self.selected_tab = (self.selected_tab + 1) % max_tabs;
                        },
                        KeyCode::Char('1') => self.selected_tab = 0,
                        KeyCode::Char('2') => self.selected_tab = 1,
                        KeyCode::Char('3') => self.selected_tab = 2,
                        KeyCode::Char('4') => self.selected_tab = 3,
                        KeyCode::Char('5') => {
                            if self.advanced_features.firewall_enabled {
                                self.selected_tab = 4;
                            }
                        },
                        // Handle arrow keys for Protocol View and Firewall navigation
                        KeyCode::Up => {
                            if self.selected_tab == 3 {
                                self.protocol_view.previous_protocol();
                            } else if self.selected_tab == 4 && self.firewall_view.is_some() && self.firewall_engine.is_some() {
                                if let (Some(ref mut view), Some(ref mut engine)) = (&mut self.firewall_view, &mut self.firewall_engine) {
                                    view.handle_key(KeyCode::Up, engine);
                                }
                            }
                        },
                        KeyCode::Down => {
                            if self.selected_tab == 3 {
                                self.protocol_view.next_protocol();
                            } else if self.selected_tab == 4 && self.firewall_view.is_some() && self.firewall_engine.is_some() {
                                if let (Some(ref mut view), Some(ref mut engine)) = (&mut self.firewall_view, &mut self.firewall_engine) {
                                    view.handle_key(KeyCode::Down, engine);
                                }
                            }
                        },
                        KeyCode::Left => {
                            if self.selected_tab == 3 {
                                self.protocol_view.previous_connection();
                            } else if self.selected_tab == 4 && self.firewall_view.is_some() && self.firewall_engine.is_some() {
                                if let (Some(ref mut view), Some(ref mut engine)) = (&mut self.firewall_view, &mut self.firewall_engine) {
                                    view.handle_key(KeyCode::Left, engine);
                                }
                            }
                        },
                        KeyCode::Right => {
                            if self.selected_tab == 3 {
                                self.protocol_view.next_connection();
                            } else if self.selected_tab == 4 && self.firewall_view.is_some() && self.firewall_engine.is_some() {
                                if let (Some(ref mut view), Some(ref mut engine)) = (&mut self.firewall_view, &mut self.firewall_engine) {
                                    view.handle_key(KeyCode::Right, engine);
                                }
                            }
                        },
                        // Handle other firewall keys
                        key if self.selected_tab == 4 && self.firewall_view.is_some() && self.firewall_engine.is_some() => {
                            if let (Some(ref mut view), Some(ref mut engine)) = (&mut self.firewall_view, &mut self.firewall_engine) {
                                view.handle_key(key, engine);
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
        
        // Cleanup
        disable_raw_mode()?;
        io::stdout().execute(LeaveAlternateScreen)?;
        io::stdout().execute(DisableMouseCapture)?;
        Ok(())
    }
    
    fn update_data(&mut self) {
        // Update packet capture if available
        if let Some(ref mut engine) = self.capture_engine {
            // Try to get new packets
            for _ in 0..10 { // Limit to 10 packets per update to avoid blocking
                match engine.get_next_packet() {
                    Ok(Some(packet)) => {
                        self.packets_captured += 1;
                        self.bytes_captured += packet.length as u64;
                        
                        // Phase 2: Track packet with connection tracker
                        self.connection_tracker.track_packet(&packet);
                        
                        // Phase 3: Inspect packet with traffic inspector
                        let protocol = self.connection_tracker.get_protocol_analyzer().identify_protocol(&packet);
                        self.traffic_inspector.inspect_packet(&packet, protocol);
                        
                        // Keep only recent packets (last 100)
                        self.recent_packets.push(packet);
                        if self.recent_packets.len() > 100 {
                            self.recent_packets.remove(0);
                        }
                    },
                    Ok(None) => break, // No more packets available
                    Err(_) => break,   // Error occurred
                }
            }
            
            // Update statistics from engine
            let stats = engine.get_statistics();
            self.packets_captured = stats.packets_captured;
            self.bytes_captured = stats.bytes_captured;
        }
        
        // Update connection information using /proc fallback
        if let Ok(connections) = ProcNetParser::get_tcp_connections() {
            self.current_connections = connections.clone();
            // Phase 2: Update connection tracker with /proc data
            self.connection_tracker.update_from_proc(&connections);
            
            // Phase 3: Feed connection data to traffic inspector for Protocol View
            for conn in &connections {
                // Create a synthetic packet info from connection data for traffic inspection
                let packet = PacketInfo {
                    timestamp: std::time::SystemTime::now(),
                    length: 0, // We don't have packet length from /proc
                    protocol: "TCP".to_string(),
                    src_ip: Some(conn.local_addr.ip().to_string()),
                    dst_ip: Some(conn.remote_addr.ip().to_string()),
                    src_port: Some(conn.local_addr.port()),
                    dst_port: Some(conn.remote_addr.port()),
                };
                
                let protocol = self.connection_tracker.get_protocol_analyzer().identify_protocol(&packet);
                self.traffic_inspector.inspect_packet(&packet, protocol);
                
                // Process packet through firewall if enabled
                if let Some(ref mut firewall_engine) = self.firewall_engine {
                    firewall_engine.process_packet(&packet);
                }
            }
        }
        
        // Phase 2: Update interface statistics and metrics
        let mut interface_stats_map = HashMap::new();
        if let Ok(stats) = ProcNetParser::get_interface_stats(&self.interface) {
            self.interface_stats = Some(stats.clone());
            interface_stats_map.insert(self.interface.clone(), stats);
        }
        
        // Update interface metrics with rate calculations
        self.interface_metrics = self.statistics_collector.update_interface_stats(&interface_stats_map);
        
        // Update packet/byte statistics
        self.statistics_collector.update_packet_stats(self.packets_captured, self.bytes_captured);
        
        // Generate comprehensive network statistics
        let protocol_stats = self.connection_tracker.get_protocol_analyzer().get_protocol_statistics();
        let active_connections = self.connection_tracker.get_connection_count();
        
        self.network_statistics = Some(self.statistics_collector.generate_network_statistics(
            protocol_stats,
            &self.interface_metrics,
            active_connections,
        ));
        
        // Phase 3: Update traffic analysis and protocol view
        let active_flows = self.traffic_inspector.get_active_flows();
        let _traffic_analysis = self.traffic_analyzer.analyze_traffic(active_flows);
        
        // Always update protocol view with latest data
        self.protocol_view.update_data(active_flows);
        
        // Force cleanup of expired flows to ensure fresh data
        // This is handled internally by the traffic inspector
    }
    
    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(0),     // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(f.size());
        
        // Draw header
        self.draw_header(f, chunks[0]);
        
        // Draw main content based on selected tab
        match self.selected_tab {
            0 => self.draw_dashboard(f, chunks[1]),
            1 => self.draw_connections(f, chunks[1]),
            2 => self.draw_packets(f, chunks[1]),
            3 => self.protocol_view.render(chunks[1], f),
            4 if self.advanced_features.firewall_enabled => {
                if let (Some(ref mut view), Some(ref engine)) = (&mut self.firewall_view, &self.firewall_engine) {
                    view.render(f, chunks[1], engine);
                } else {
                    self.draw_dashboard(f, chunks[1]);
                }
            },
            _ => self.draw_dashboard(f, chunks[1]),
        }
        
        // Draw footer
        self.draw_footer(f, chunks[2]);
    }
    
    fn draw_header(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let mut tabs = vec!["Dashboard", "Connections", "Packets", "Protocols"];
        if self.advanced_features.firewall_enabled {
            tabs.push("Firewall");
        }
        let selected_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let normal_style = Style::default().fg(Color::White);
        
        let tab_titles: Vec<Line> = tabs.iter().enumerate().map(|(i, &tab)| {
            let style = if i == self.selected_tab { selected_style } else { normal_style };
            Line::from(Span::styled(format!(" {} ", tab), style))
        }).collect();
        
        let header = Paragraph::new(tab_titles)
            .block(Block::default().borders(Borders::ALL).title("Network Monitor - Enhanced Protocol View"))
            .alignment(Alignment::Center);
        
        f.render_widget(header, area);
    }
    
    fn draw_dashboard(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Stats
                Constraint::Length(6),  // Interface info
                Constraint::Min(0),     // Connection summary
            ])
            .split(area);
        
        // Draw packet statistics
        let stats_text = format!(
            "Packets: {} | Bytes: {} | Connections: {} | Interface: {}",
            self.packets_captured,
            self.format_bytes(self.bytes_captured),
            self.current_connections.len(),
            self.interface
        );
        
        let stats = Paragraph::new(stats_text)
            .block(Block::default().borders(Borders::ALL).title("Statistics"))
            .alignment(Alignment::Center);
        
        f.render_widget(stats, chunks[0]);
        
        // Draw interface statistics if available
        if let Some(ref stats) = self.interface_stats {
            let interface_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[1]);
            
            let rx_info = format!(
                "RX Bytes: {}\nRX Packets: {}\nRX Errors: {}\nRX Dropped: {}",
                self.format_bytes(stats.rx_bytes),
                stats.rx_packets,
                stats.rx_errors,
                stats.rx_dropped
            );
            
            let tx_info = format!(
                "TX Bytes: {}\nTX Packets: {}\nTX Errors: {}\nTX Dropped: {}",
                self.format_bytes(stats.tx_bytes),
                stats.tx_packets,
                stats.tx_errors,
                stats.tx_dropped
            );
            
            let rx_widget = Paragraph::new(rx_info)
                .block(Block::default().borders(Borders::ALL).title("Receive"));
            let tx_widget = Paragraph::new(tx_info)
                .block(Block::default().borders(Borders::ALL).title("Transmit"));
            
            f.render_widget(rx_widget, interface_chunks[0]);
            f.render_widget(tx_widget, interface_chunks[1]);
        }
        
        // Draw connection summary
        self.draw_connection_summary(f, chunks[2]);
    }
    
    fn draw_connections(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let rows: Vec<Row> = self.current_connections.iter().take(20).map(|conn| {
            Row::new(vec![
                Cell::from(conn.local_addr.to_string()),
                Cell::from(conn.remote_addr.to_string()),
                Cell::from(conn.state.to_string()),
                Cell::from(conn.uid.to_string()),
            ])
        }).collect();
        
        let table = Table::new(rows)
        .widths(&[
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .header(Row::new(vec!["Local Address", "Remote Address", "State", "UID"])
            .style(Style::default().fg(Color::Yellow)))
        .block(Block::default().borders(Borders::ALL).title("Active Connections"));
        
        f.render_widget(table, area);
    }
    
    fn draw_packets(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self.recent_packets.iter().rev().take(20).map(|packet| {
            let content = format!(
                "{} {} -> {} ({}B)",
                packet.protocol,
                packet.src_ip.as_deref().unwrap_or("?"),
                packet.dst_ip.as_deref().unwrap_or("?"),
                packet.length
            );
            ListItem::new(content)
        }).collect();
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Recent Packets"));
        
        f.render_widget(list, area);
    }
    
    fn draw_connection_summary(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let mut state_counts = std::collections::HashMap::new();
        for conn in &self.current_connections {
            *state_counts.entry(conn.state.to_string()).or_insert(0) += 1;
        }
        
        let items: Vec<ListItem> = state_counts.iter().map(|(state, count)| {
            ListItem::new(format!("{}: {}", state, count))
        }).collect();
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Connection States"));
        
        f.render_widget(list, area);
    }
    
    fn draw_footer(&self, f: &mut Frame, area: ratatui::layout::Rect) {
        let footer_text = "Press 'q' to quit | Tab/1-4 to switch tabs | Monitoring interface: ";
        let footer = Paragraph::new(format!("{}{}", footer_text, self.interface))
            .block(Block::default().borders(Borders::ALL))
            .alignment(Alignment::Center);
        
        f.render_widget(footer, area);
    }
    
    fn format_bytes(&self, bytes: u64) -> String {
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
}
