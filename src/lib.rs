// Library exports for network-monitor
pub mod analysis;
pub mod capture;
pub mod config;
pub mod traffic;
pub mod ui;
pub mod utils;
pub mod visualization;
pub mod firewall;

pub use analysis::{protocols, connections, statistics};
pub use capture::{pcap_engine, proc_parser};
pub use config::settings;
pub use traffic::{inspector, analyzer};
pub use ui::app;
pub use utils::formatting;
pub use visualization::{charts, widgets, layouts};

// Error types
pub use anyhow::{Error, Result};
