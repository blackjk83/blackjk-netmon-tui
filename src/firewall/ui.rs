use ratatui::{
    widgets::{Block, Borders, List, ListItem, Paragraph, Gauge},
    layout::{Layout, Constraint, Direction, Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    Frame,
};
use crate::firewall::{FirewallEngine, RuleAction, RuleDirection, RuleProtocol};

pub struct FirewallView {
    selected_rule: usize,
    selected_event: usize,
    show_rule_editor: bool,
    show_stats: bool,
    _scroll_offset: usize,
}

impl FirewallView {
    pub fn new() -> Self {
        Self {
            selected_rule: 0,
            selected_event: 0,
            show_rule_editor: false,
            show_stats: true,
            _scroll_offset: 0,
        }
    }
    
    pub fn handle_key(&mut self, key: crossterm::event::KeyCode, engine: &mut FirewallEngine) {
        match key {
            crossterm::event::KeyCode::Up => {
                if self.selected_rule > 0 {
                    self.selected_rule -= 1;
                }
            }
            crossterm::event::KeyCode::Down => {
                if self.selected_rule < engine.get_rules().len().saturating_sub(1) {
                    self.selected_rule += 1;
                }
            }
            crossterm::event::KeyCode::Left => {
                if self.selected_event > 0 {
                    self.selected_event -= 1;
                }
            }
            crossterm::event::KeyCode::Right => {
                if self.selected_event < engine.get_recent_events().len().saturating_sub(1) {
                    self.selected_event += 1;
                }
            }
            crossterm::event::KeyCode::Enter => {
                // Toggle rule enabled/disabled
                if let Some(rule) = engine.get_rules().get(self.selected_rule) {
                    let rule_id = rule.id;
                    if rule.enabled {
                        engine.disable_rule(rule_id);
                    } else {
                        engine.enable_rule(rule_id);
                    }
                }
            }
            crossterm::event::KeyCode::Delete => {
                // Delete selected rule
                if let Some(rule) = engine.get_rules().get(self.selected_rule) {
                    let rule_id = rule.id;
                    engine.remove_rule(rule_id);
                    if self.selected_rule > 0 {
                        self.selected_rule -= 1;
                    }
                }
            }
            crossterm::event::KeyCode::Char('s') => {
                self.show_stats = !self.show_stats;
            }
            crossterm::event::KeyCode::Char('e') => {
                self.show_rule_editor = !self.show_rule_editor;
            }
            crossterm::event::KeyCode::Char('c') => {
                engine.clear_events();
            }
            crossterm::event::KeyCode::Char('r') => {
                engine.reset_stats();
            }
            crossterm::event::KeyCode::Char('d') => {
                engine.load_default_rules();
            }
            crossterm::event::KeyCode::Char('t') => {
                engine.set_enabled(!engine.is_enabled());
            }
            _ => {}
        }
    }
    
    pub fn render(&mut self, f: &mut Frame, area: Rect, engine: &FirewallEngine) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(10),    // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        // Header
        self.render_header(f, chunks[0], engine);
        
        // Main content
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(60), // Rules panel
                Constraint::Percentage(40), // Events/Stats panel
            ])
            .split(chunks[1]);
        
        self.render_rules_panel(f, main_chunks[0], engine);
        
        if self.show_stats {
            self.render_stats_panel(f, main_chunks[1], engine);
        } else {
            self.render_events_panel(f, main_chunks[1], engine);
        }
        
        // Footer
        self.render_footer(f, chunks[2]);
    }
    
    fn render_header(&self, f: &mut Frame, area: Rect, engine: &FirewallEngine) {
        let status = if engine.is_enabled() { "ACTIVE" } else { "DISABLED" };
        let status_color = if engine.is_enabled() { Color::Green } else { Color::Red };
        
        let stats = engine.get_stats();
        let header_text = format!(
            "Firewall: {} | Rules: {}/{} | Processed: {} | Blocked: {} ({:.1}%)",
            status,
            stats.enabled_rules,
            stats.active_rules,
            stats.total_packets_processed,
            stats.packets_blocked,
            stats.get_block_rate()
        );
        
        let header = Paragraph::new(header_text)
            .block(Block::default().borders(Borders::ALL).title("Firewall Status"))
            .style(Style::default().fg(status_color))
            .alignment(Alignment::Center);
        
        f.render_widget(header, area);
    }
    
    fn render_rules_panel(&self, f: &mut Frame, area: Rect, engine: &FirewallEngine) {
        let rules = engine.get_rules();
        
        let items: Vec<ListItem> = rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                let status = if rule.enabled { "✓" } else { "✗" };
                let action_color = match rule.action {
                    RuleAction::Allow => Color::Green,
                    RuleAction::Block => Color::Red,
                    RuleAction::Log => Color::Yellow,
                    RuleAction::LogAndBlock => Color::Magenta,
                };
                
                let direction_symbol = match rule.direction {
                    RuleDirection::Inbound => "←",
                    RuleDirection::Outbound => "→",
                    RuleDirection::Bidirectional => "↔",
                };
                
                let protocol_str = match rule.protocol {
                    RuleProtocol::TCP => "TCP",
                    RuleProtocol::UDP => "UDP",
                    RuleProtocol::ICMP => "ICMP",
                    RuleProtocol::Any => "ANY",
                };
                
                let line = Line::from(vec![
                    Span::styled(status, Style::default().fg(if rule.enabled { Color::Green } else { Color::Red })),
                    Span::raw(" "),
                    Span::styled(format!("{:?}", rule.action), Style::default().fg(action_color)),
                    Span::raw(" "),
                    Span::raw(direction_symbol),
                    Span::raw(" "),
                    Span::styled(protocol_str, Style::default().fg(Color::Cyan)),
                    Span::raw(" "),
                    Span::styled(&rule.name, Style::default().fg(Color::White)),
                    Span::raw(format!(" ({})", rule.match_count)),
                ]);
                
                let mut item = ListItem::new(line);
                if i == self.selected_rule {
                    item = item.style(Style::default().bg(Color::DarkGray));
                }
                item
            })
            .collect();
        
        let rules_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Firewall Rules (↑↓ to navigate, Enter to toggle, Del to remove)"))
            .highlight_style(Style::default().bg(Color::DarkGray));
        
        f.render_widget(rules_list, area);
    }
    
    fn render_events_panel(&self, f: &mut Frame, area: Rect, engine: &FirewallEngine) {
        let events = engine.get_recent_events();
        
        let items: Vec<ListItem> = events
            .iter()
            .rev() // Show most recent first
            .take(area.height as usize - 2) // Account for borders
            .enumerate()
            .map(|(i, event)| {
                let action_color = match event.action {
                    RuleAction::Allow => Color::Green,
                    RuleAction::Block => Color::Red,
                    RuleAction::Log => Color::Yellow,
                    RuleAction::LogAndBlock => Color::Magenta,
                };
                
                let age = event.get_age();
                let age_str = if age.as_secs() < 60 {
                    format!("{}s", age.as_secs())
                } else if age.as_secs() < 3600 {
                    format!("{}m", age.as_secs() / 60)
                } else {
                    format!("{}h", age.as_secs() / 3600)
                };
                
                let line = Line::from(vec![
                    Span::styled(format!("{:?}", event.action), Style::default().fg(action_color)),
                    Span::raw(" "),
                    Span::styled(format!("{}:{}", event.src_ip, event.src_port), Style::default().fg(Color::Cyan)),
                    Span::raw(" → "),
                    Span::styled(format!("{}:{}", event.dst_ip, event.dst_port), Style::default().fg(Color::Yellow)),
                    Span::raw(" "),
                    Span::styled(age_str, Style::default().fg(Color::Gray)),
                ]);
                
                let mut item = ListItem::new(line);
                if i == self.selected_event {
                    item = item.style(Style::default().bg(Color::DarkGray));
                }
                item
            })
            .collect();
        
        let events_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Recent Events (←→ to navigate, 'c' to clear)"))
            .highlight_style(Style::default().bg(Color::DarkGray));
        
        f.render_widget(events_list, area);
    }
    
    fn render_stats_panel(&self, f: &mut Frame, area: Rect, engine: &FirewallEngine) {
        let stats = engine.get_stats();
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Stats text
                Constraint::Min(4),     // Gauges
            ])
            .split(area);
        
        // Stats text
        let stats_text = format!(
            "Total Processed: {}\nAllowed: {}\nBlocked: {}\nLogged: {}\nRules Matched: {}\nActive Rules: {}\nEnabled Rules: {}",
            stats.total_packets_processed,
            stats.packets_allowed,
            stats.packets_blocked,
            stats.packets_logged,
            stats.rules_matched,
            stats.active_rules,
            stats.enabled_rules
        );
        
        let stats_paragraph = Paragraph::new(stats_text)
            .block(Block::default().borders(Borders::ALL).title("Statistics ('s' to toggle, 'r' to reset)"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(stats_paragraph, chunks[0]);
        
        // Gauges
        let gauge_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(chunks[1]);
        
        let block_rate = stats.get_block_rate();
        let allow_rate = stats.get_allow_rate();
        
        let block_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Block Rate"))
            .gauge_style(Style::default().fg(Color::Red))
            .percent(block_rate as u16)
            .label(format!("{:.1}%", block_rate));
        
        let allow_gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title("Allow Rate"))
            .gauge_style(Style::default().fg(Color::Green))
            .percent(allow_rate as u16)
            .label(format!("{:.1}%", allow_rate));
        
        f.render_widget(block_gauge, gauge_chunks[0]);
        f.render_widget(allow_gauge, gauge_chunks[1]);
    }
    
    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let footer_text = if self.show_stats {
            "Keys: ↑↓ Rules | Enter Toggle | Del Remove | 's' Events | 'e' Editor | 'd' Defaults | 't' Toggle Firewall | 'c' Clear | 'r' Reset"
        } else {
            "Keys: ↑↓ Rules | ←→ Events | Enter Toggle | Del Remove | 's' Stats | 'e' Editor | 'd' Defaults | 't' Toggle Firewall | 'c' Clear"
        };
        
        let footer = Paragraph::new(footer_text)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);
        
        f.render_widget(footer, area);
    }
    
    pub fn get_selected_rule(&self) -> usize {
        self.selected_rule
    }
    
    pub fn get_selected_event(&self) -> usize {
        self.selected_event
    }
    
    pub fn set_selected_rule(&mut self, index: usize) {
        self.selected_rule = index;
    }
    
    pub fn toggle_stats_view(&mut self) {
        self.show_stats = !self.show_stats;
    }
    
    pub fn toggle_rule_editor(&mut self) {
        self.show_rule_editor = !self.show_rule_editor;
    }
}

impl Default for FirewallView {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_view_creation() {
        let view = FirewallView::new();
        assert_eq!(view.selected_rule, 0);
        assert_eq!(view.selected_event, 0);
        assert!(!view.show_rule_editor);
        assert!(view.show_stats);
    }
    
    #[test]
    fn test_navigation() {
        let mut view = FirewallView::new();
        let mut engine = FirewallEngine::new();
        engine.load_default_rules();
        
        // Test rule navigation
        view.handle_key(crossterm::event::KeyCode::Down, &mut engine);
        assert_eq!(view.selected_rule, 1);
        
        view.handle_key(crossterm::event::KeyCode::Up, &mut engine);
        assert_eq!(view.selected_rule, 0);
        
        // Test toggle stats
        view.handle_key(crossterm::event::KeyCode::Char('s'), &mut engine);
        assert!(!view.show_stats);
    }
}
