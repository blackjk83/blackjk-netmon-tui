use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub capture: CaptureConfig,
    pub ui: UiConfig,
    pub system: SystemConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CaptureConfig {
    pub interface: Option<String>,
    pub buffer_size: usize,
    pub timeout_ms: u32,
    pub promiscuous: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UiConfig {
    pub refresh_rate_ms: u64,
    pub default_view: String,
    pub color_scheme: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SystemConfig {
    pub kernel_version: String,
    pub use_ebpf_fallback: bool,
    pub check_capabilities: bool,
    pub rocky_linux_mode: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            buffer_size: 65536,
            timeout_ms: 1000,
            promiscuous: false,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            refresh_rate_ms: 1000,
            default_view: "dashboard".to_string(),
            color_scheme: "dark".to_string(),
        }
    }
}

impl Config {
    pub fn detect_system() -> Self {
        let kernel_version = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
            
        let is_kernel_5x = kernel_version.starts_with("5.");
        
        Config {
            capture: CaptureConfig::default(),
            ui: UiConfig::default(),
            system: SystemConfig {
                kernel_version,
                use_ebpf_fallback: is_kernel_5x,
                check_capabilities: true,
                rocky_linux_mode: Self::is_rocky_linux(),
            }
        }
    }
    
    fn is_rocky_linux() -> bool {
        fs::read_to_string("/etc/os-release")
            .map(|content| content.contains("Rocky Linux"))
            .unwrap_or(false)
    }
    
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
    
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
