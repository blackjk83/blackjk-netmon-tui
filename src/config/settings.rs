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
    
    pub fn validate_rocky_linux_9() -> Result<(), String> {
        // Check if we're running on Rocky Linux
        let os_release = fs::read_to_string("/etc/os-release")
            .map_err(|_| "Cannot read /etc/os-release - unsupported system".to_string())?;
        
        if !os_release.contains("Rocky Linux") {
            return Err("This application currently only supports Rocky Linux. Other distributions will be supported in future versions.".to_string());
        }
        
        // Extract Rocky Linux version
        let version_line = os_release
            .lines()
            .find(|line| line.starts_with("VERSION_ID="))
            .ok_or("Cannot determine Rocky Linux version".to_string())?;
        
        let version = version_line
            .split('=')
            .nth(1)
            .ok_or("Invalid version format".to_string())?
            .trim_matches('"');
        
        if !version.starts_with("9.") {
            return Err(format!(
                "This application currently only supports Rocky Linux 9.x. Found version: {}. Other versions will be supported in future releases.", 
                version
            ));
        }
        
        // Check kernel version compatibility
        let kernel_version = std::process::Command::new("uname")
            .arg("-r")
            .output()
            .map_err(|_| "Cannot determine kernel version".to_string())?
            .stdout;
        
        let kernel_str = String::from_utf8_lossy(&kernel_version).trim().to_string();
        
        if !kernel_str.contains("el9") {
            return Err(format!(
                "This application requires Rocky Linux 9 kernel (el9). Found kernel: {}. Please ensure you're running on Rocky Linux 9.", 
                kernel_str
            ));
        }
        
        Ok(())
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
