use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Chart, Dataset, GraphType, Axis},
    symbols,
    style::{Color, Style},
};
use std::collections::VecDeque;
use crate::traffic::{TrafficFlow, FlowDirection};

use crate::analysis::protocols::ProtocolType;

pub struct BandwidthChart {
    data_points: VecDeque<(f64, f64)>, // (time, bandwidth)
    max_points: usize,
    time_window: f64, // seconds
}

impl BandwidthChart {
    pub fn new(max_points: usize, time_window: f64) -> Self {
        Self {
            data_points: VecDeque::new(),
            max_points,
            time_window,
        }
    }
    
    pub fn add_sample(&mut self, timestamp: f64, bandwidth: f64) {
        self.data_points.push_back((timestamp, bandwidth));
        
        // Remove old data points outside time window
        let cutoff_time = timestamp - self.time_window;
        while let Some(&(time, _)) = self.data_points.front() {
            if time < cutoff_time {
                self.data_points.pop_front();
            } else {
                break;
            }
        }
        
        // Limit total points
        while self.data_points.len() > self.max_points {
            self.data_points.pop_front();
        }
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        if self.data_points.is_empty() {
            return;
        }
        
        let data_points: Vec<(f64, f64)> = self.data_points.iter().cloned().collect();
        let datasets = vec![
            Dataset::default()
                .name("Bandwidth")
                .marker(symbols::Marker::Braille)
                .style(Style::default().fg(Color::Cyan))
                .graph_type(GraphType::Line)
                .data(&data_points),
        ];
        
        let (min_time, max_time) = if let (Some(&(min_t, _)), Some(&(max_t, _))) = 
            (self.data_points.front(), self.data_points.back()) {
            (min_t, max_t)
        } else {
            (0.0, 60.0)
        };
        
        let max_bandwidth = self.data_points.iter()
            .map(|(_, bw)| *bw)
            .fold(0.0, f64::max)
            .max(1.0); // Minimum scale
        
        let chart = Chart::new(datasets)
            .block(
                Block::default()
                    .title("Bandwidth Over Time")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::White)),
            )
            .x_axis(
                Axis::default()
                    .title("Time (s)")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_time, max_time])
                    .labels(vec![
                        format!("{:.0}", min_time).into(),
                        format!("{:.0}", (min_time + max_time) / 2.0).into(),
                        format!("{:.0}", max_time).into(),
                    ]),
            )
            .y_axis(
                Axis::default()
                    .title("Bandwidth (MB/s)")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([0.0, max_bandwidth / 1_000_000.0])
                    .labels(vec![
                        "0".into(),
                        format!("{:.1}", max_bandwidth / 2_000_000.0).into(),
                        format!("{:.1}", max_bandwidth / 1_000_000.0).into(),
                    ]),
            );
        
        frame.render_widget(chart, area);
    }
}

pub struct ProtocolChart {
    protocol_data: Vec<(String, f64)>, // (protocol_name, percentage)
}

impl ProtocolChart {
    pub fn new() -> Self {
        Self {
            protocol_data: Vec::new(),
        }
    }
    
    pub fn update_data(&mut self, protocols: Vec<(ProtocolType, f64)>) {
        self.protocol_data = protocols
            .into_iter()
            .map(|(proto, pct)| (format!("{:?}", proto), pct))
            .collect();
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        use ratatui::widgets::{BarChart, Bar};
        
        if self.protocol_data.is_empty() {
            let block = Block::default()
                .title("Protocol Distribution")
                .borders(Borders::ALL);
            frame.render_widget(block, area);
            return;
        }
        
        let _bars: Vec<Bar> = self.protocol_data
            .iter()
            .take(10) // Show top 10 protocols
            .enumerate()
            .map(|(i, (name, value))| {
                let color = match i % 6 {
                    0 => Color::Red,
                    1 => Color::Green,
                    2 => Color::Yellow,
                    3 => Color::Blue,
                    4 => Color::Magenta,
                    5 => Color::Cyan,
                    _ => Color::White,
                };
                Bar::default()
                    .label(name.clone().into())
                    .value(*value as u64)
                    .style(Style::default().fg(color))
            })
            .collect();
        
        let data: Vec<(&str, u64)> = self.protocol_data
            .iter()
            .take(10)
            .map(|(name, value)| (name.as_str(), *value as u64))
            .collect();
        
        let chart = BarChart::default()
            .block(
                Block::default()
                    .title("Protocol Distribution (%)")
                    .borders(Borders::ALL),
            )
            .data(&data)
            .bar_width(3)
            .bar_style(Style::default().fg(Color::Yellow))
            .value_style(Style::default().fg(Color::Black).bg(Color::Yellow));
        
        frame.render_widget(chart, area);
    }
}

pub struct FlowChart {
    flow_data: Vec<FlowVisualization>,
}

#[derive(Clone)]
pub struct FlowVisualization {
    pub flow_id: String,
    pub src: String,
    pub dst: String,
    pub direction: FlowDirection,
    pub bandwidth: f64,
    pub protocol: ProtocolType,
    pub active: bool,
}

impl FlowChart {
    pub fn new() -> Self {
        Self {
            flow_data: Vec::new(),
        }
    }
    
    pub fn update_flows(&mut self, flows: &std::collections::HashMap<String, TrafficFlow>) {
        self.flow_data = flows
            .values()
            .map(|flow| FlowVisualization {
                flow_id: flow.flow_id.clone(),
                src: flow.src_addr.to_string(),
                dst: flow.dst_addr.to_string(),
                direction: flow.direction.clone(),
                bandwidth: flow.bytes_per_second,
                protocol: flow.protocol.clone(),
                active: flow.is_active,
            })
            .collect();
        
        // Sort by bandwidth (highest first)
        self.flow_data.sort_by(|a, b| b.bandwidth.partial_cmp(&a.bandwidth).unwrap_or(std::cmp::Ordering::Equal));
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame) {
        use ratatui::widgets::{List, ListItem};
        
        let items: Vec<ListItem> = self.flow_data
            .iter()
            .take(area.height.saturating_sub(2) as usize) // Account for borders
            .enumerate()
            .map(|(i, flow)| {
                let direction_symbol = match flow.direction {
                    FlowDirection::Inbound => "←",
                    FlowDirection::Outbound => "→",
                    FlowDirection::Internal => "↔",
                    FlowDirection::Unknown => "?",
                };
                
                let bandwidth_mb = flow.bandwidth / 1_000_000.0;
                let protocol_str = format!("{:?}", flow.protocol);
                
                let color = if flow.active {
                    match flow.direction {
                        FlowDirection::Inbound => Color::Green,
                        FlowDirection::Outbound => Color::Blue,
                        FlowDirection::Internal => Color::Yellow,
                        FlowDirection::Unknown => Color::Gray,
                    }
                } else {
                    Color::DarkGray
                };
                
                let text = format!(
                    "{:2} {} {} {} {:.2}MB/s [{}]",
                    i + 1,
                    direction_symbol,
                    flow.src,
                    flow.dst,
                    bandwidth_mb,
                    protocol_str
                );
                
                ListItem::new(text).style(Style::default().fg(color))
            })
            .collect();
        
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Active Traffic Flows")
                    .borders(Borders::ALL),
            )
            .style(Style::default().fg(Color::White));
        
        frame.render_widget(list, area);
    }
}

pub struct TimeSeriesChart {
    datasets: Vec<TimeSeriesDataset>,
    time_window: f64,
    max_points: usize,
}

pub struct TimeSeriesDataset {
    pub name: String,
    pub data: VecDeque<(f64, f64)>,
    pub color: Color,
    pub style: GraphType,
}

impl TimeSeriesChart {
    pub fn new(time_window: f64, max_points: usize) -> Self {
        Self {
            datasets: Vec::new(),
            time_window,
            max_points,
        }
    }
    
    pub fn add_dataset(&mut self, name: String, color: Color, style: GraphType) {
        self.datasets.push(TimeSeriesDataset {
            name,
            data: VecDeque::new(),
            color,
            style,
        });
    }
    
    pub fn add_data_point(&mut self, dataset_name: &str, timestamp: f64, value: f64) {
        if let Some(dataset) = self.datasets.iter_mut().find(|d| d.name == dataset_name) {
            dataset.data.push_back((timestamp, value));
            
            // Remove old points
            let cutoff_time = timestamp - self.time_window;
            while let Some(&(time, _)) = dataset.data.front() {
                if time < cutoff_time {
                    dataset.data.pop_front();
                } else {
                    break;
                }
            }
            
            // Limit points
            while dataset.data.len() > self.max_points {
                dataset.data.pop_front();
            }
        }
    }
    
    pub fn render(&self, area: Rect, frame: &mut Frame, title: &str, y_label: &str) {
        if self.datasets.is_empty() {
            return;
        }
        
        // Collect all data first to avoid borrowing issues
        let dataset_data: Vec<(String, Color, GraphType, Vec<(f64, f64)>)> = self.datasets
            .iter()
            .map(|ds| {
                let data_points: Vec<(f64, f64)> = ds.data.iter().cloned().collect();
                (ds.name.clone(), ds.color, ds.style, data_points)
            })
            .collect();
        
        let datasets: Vec<Dataset> = dataset_data
            .iter()
            .map(|(name, color, style, data_points)| {
                Dataset::default()
                    .name(name.clone())
                    .marker(symbols::Marker::Braille)
                    .style(Style::default().fg(*color))
                    .graph_type(*style)
                    .data(data_points)
            })
            .collect();
        
        let (min_time, max_time) = self.get_time_bounds();
        let (min_value, max_value) = self.get_value_bounds();
        
        let chart = Chart::new(datasets)
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::White)),
            )
            .x_axis(
                Axis::default()
                    .title("Time")
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_time, max_time])
                    .labels(vec![
                        format!("{:.0}s", min_time).into(),
                        format!("{:.0}s", max_time).into(),
                    ]),
            )
            .y_axis(
                Axis::default()
                    .title(y_label)
                    .style(Style::default().fg(Color::Gray))
                    .bounds([min_value, max_value])
                    .labels(vec![
                        format!("{:.1}", min_value).into(),
                        format!("{:.1}", max_value).into(),
                    ]),
            );
        
        frame.render_widget(chart, area);
    }
    
    fn get_time_bounds(&self) -> (f64, f64) {
        let mut min_time = f64::MAX;
        let mut max_time = f64::MIN;
        
        for dataset in &self.datasets {
            if let (Some(&(min_t, _)), Some(&(max_t, _))) = 
                (dataset.data.front(), dataset.data.back()) {
                min_time = min_time.min(min_t);
                max_time = max_time.max(max_t);
            }
        }
        
        if min_time == f64::MAX {
            (0.0, 60.0)
        } else {
            (min_time, max_time)
        }
    }
    
    fn get_value_bounds(&self) -> (f64, f64) {
        let mut min_value = f64::MAX;
        let mut max_value = f64::MIN;
        
        for dataset in &self.datasets {
            for &(_, value) in &dataset.data {
                min_value = min_value.min(value);
                max_value = max_value.max(value);
            }
        }
        
        if min_value == f64::MAX {
            (0.0, 1.0)
        } else {
            (min_value.min(0.0), max_value.max(1.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_chart_creation() {
        let chart = BandwidthChart::new(100, 60.0);
        assert_eq!(chart.data_points.len(), 0);
        assert_eq!(chart.max_points, 100);
    }
    
    #[test]
    fn test_protocol_chart_creation() {
        let chart = ProtocolChart::new();
        assert_eq!(chart.protocol_data.len(), 0);
    }
}
