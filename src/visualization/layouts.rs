use ratatui::prelude::*;

pub struct DashboardLayout;
pub struct TrafficLayout;
pub struct AnalysisLayout;

impl DashboardLayout {
    pub fn create_layout(area: Rect) -> Vec<Rect> {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(10),    // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(70), // Main dashboard
                Constraint::Percentage(30), // Side panel
            ])
            .split(main_chunks[1]);
        
        let main_sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(40), // Top section (bandwidth chart)
                Constraint::Percentage(30), // Middle section (protocol breakdown)
                Constraint::Percentage(30), // Bottom section (top flows)
            ])
            .split(content_chunks[0]);
        
        let side_sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50), // Stats panel
                Constraint::Percentage(50), // Alerts panel
            ])
            .split(content_chunks[1]);
        
        vec![
            main_chunks[0],   // Header
            main_sections[0], // Bandwidth chart
            main_sections[1], // Protocol breakdown
            main_sections[2], // Top flows
            side_sections[0], // Stats panel
            side_sections[1], // Alerts panel
            main_chunks[2],   // Footer
        ]
    }
}

impl TrafficLayout {
    pub fn create_layout(area: Rect) -> Vec<Rect> {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(10),    // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(60), // Flow table
                Constraint::Percentage(40), // Events and details
            ])
            .split(main_chunks[1]);
        
        let right_sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60), // Events list
                Constraint::Percentage(40), // Flow details
            ])
            .split(content_chunks[1]);
        
        vec![
            main_chunks[0],   // Header
            content_chunks[0], // Flow table
            right_sections[0], // Events list
            right_sections[1], // Flow details
            main_chunks[2],   // Footer
        ]
    }
}

impl AnalysisLayout {
    pub fn create_layout(area: Rect) -> Vec<Rect> {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(10),    // Main content
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        let content_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50), // Top row (charts)
                Constraint::Percentage(50), // Bottom row (analysis)
            ])
            .split(main_chunks[1]);
        
        let top_sections = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Bandwidth analysis
                Constraint::Percentage(50), // Protocol analysis
            ])
            .split(content_chunks[0]);
        
        let bottom_sections = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Pattern detection
                Constraint::Percentage(50), // Geographic analysis
            ])
            .split(content_chunks[1]);
        
        vec![
            main_chunks[0],    // Header
            top_sections[0],   // Bandwidth analysis
            top_sections[1],   // Protocol analysis
            bottom_sections[0], // Pattern detection
            bottom_sections[1], // Geographic analysis
            main_chunks[2],    // Footer
        ]
    }
}

pub struct ResponsiveLayout;

impl ResponsiveLayout {
    pub fn adapt_for_size(area: Rect, layout_type: LayoutType) -> Vec<Rect> {
        match layout_type {
            LayoutType::Dashboard => {
                if area.width < 100 || area.height < 25 {
                    // Compact layout for small terminals
                    Self::create_compact_dashboard(area)
                } else {
                    DashboardLayout::create_layout(area)
                }
            }
            LayoutType::Traffic => {
                if area.width < 80 {
                    // Single column for narrow terminals
                    Self::create_narrow_traffic(area)
                } else {
                    TrafficLayout::create_layout(area)
                }
            }
            LayoutType::Analysis => {
                if area.width < 120 || area.height < 30 {
                    // Simplified analysis for small screens
                    Self::create_simple_analysis(area)
                } else {
                    AnalysisLayout::create_layout(area)
                }
            }
        }
    }
    
    fn create_compact_dashboard(area: Rect) -> Vec<Rect> {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(8),     // Stats only
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        vec![chunks[0], chunks[1], chunks[2]]
    }
    
    fn create_narrow_traffic(area: Rect) -> Vec<Rect> {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Percentage(70), // Flow table
                Constraint::Percentage(30), // Events
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        vec![chunks[0], chunks[1], chunks[2], chunks[3]]
    }
    
    fn create_simple_analysis(area: Rect) -> Vec<Rect> {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Percentage(50), // Single chart
                Constraint::Percentage(50), // Analysis text
                Constraint::Length(3),  // Footer
            ])
            .split(area);
        
        vec![chunks[0], chunks[1], chunks[2], chunks[3]]
    }
}

#[derive(Clone, Copy)]
pub enum LayoutType {
    Dashboard,
    Traffic,
    Analysis,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_layout() {
        let area = Rect::new(0, 0, 100, 30);
        let layout = DashboardLayout::create_layout(area);
        assert_eq!(layout.len(), 7); // Header + 4 main sections + 2 side sections + footer
    }
    
    #[test]
    fn test_responsive_layout() {
        let small_area = Rect::new(0, 0, 50, 15);
        let layout = ResponsiveLayout::adapt_for_size(small_area, LayoutType::Dashboard);
        assert!(layout.len() <= 3); // Should be compact
    }
}
