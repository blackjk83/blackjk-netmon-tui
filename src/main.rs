use clap::Parser;
use network_monitor::{app::App, settings::Config, config::AdvancedFeatures};
use std::process;

#[derive(Parser)]
#[command(name = "network-monitor")]
#[command(about = "TUI Network Monitor for Rocky Linux")]
struct Cli {
    #[arg(short, long, help = "Network interface to monitor")]
    interface: Option<String>,
    
    #[arg(short, long, help = "Configuration file path")]
    config: Option<String>,
    
    #[arg(short, long, help = "Enable debug logging")]
    debug: bool,
    
    // Advanced features (opt-in)
    #[arg(long, help = "Enable firewall functionality (advanced)")]
    enable_firewall: bool,
    
    #[arg(long, help = "Enable metrics explorer (advanced)")]
    enable_metrics: bool,
    
    #[arg(long, help = "Enable fuzzy search (advanced)")]
    enable_search: bool,
    
    #[arg(long, help = "Enable all advanced features")]
    enable_all_advanced: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    if cli.debug {
        env_logger::init();
    }
    
    // Load configuration
    let config = Config::detect_system();
    println!("Detected kernel: {}", config.system.kernel_version);
    
    if config.system.rocky_linux_mode {
        println!("Rocky Linux compatibility mode enabled");
    }
    
    if config.system.use_ebpf_fallback {
        println!("Using fallback methods for kernel 5.x compatibility");
    }
    
    // Configure advanced features based on CLI arguments
    let advanced_features = AdvancedFeatures::from_cli_args(
        cli.enable_firewall,
        cli.enable_metrics,
        cli.enable_search,
        cli.enable_all_advanced,
    );
    
    // Display enabled advanced features
    if advanced_features.has_any_advanced_features() {
        let enabled_features = advanced_features.get_enabled_features();
        let memory_usage = advanced_features.get_memory_usage_estimate();
        println!("Advanced features enabled: {}", enabled_features.join(", "));
        println!("Estimated additional memory usage: {} KB", memory_usage);
    } else {
        println!("Running in lightweight mode (use --help to see advanced options)");
    }
    
    // Check for available interfaces
    match network_monitor::capture::ProcNetParser::get_interfaces() {
        Ok(interfaces) => {
            if interfaces.is_empty() {
                eprintln!("Warning: No network interfaces found");
            } else {
                println!("Available interfaces: {:?}", interfaces);
            }
        },
        Err(e) => {
            eprintln!("Warning: Could not enumerate interfaces: {}", e);
        }
    }
    
    // Initialize TUI application with advanced features
    let mut app = App::with_advanced_features(advanced_features);
    
    // Try to initialize packet capture (graceful fallback if it fails)
    if let Err(e) = app.initialize_capture(cli.interface) {
        eprintln!("Warning: Packet capture initialization failed: {}", e);
        eprintln!("Continuing with connection monitoring only...");
    }
    
    // Start the TUI
    println!("Starting Network Monitor TUI...");
    println!("Press 'q' to quit, Tab or 1-3 to switch between views");
    
    if let Err(e) = app.run() {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
    
    println!("Network Monitor TUI stopped.");
    Ok(())
}
