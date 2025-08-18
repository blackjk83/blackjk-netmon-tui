use clap::Parser;
use network_monitor::{app::App, settings::Config};
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
    
    // Initialize TUI application
    let mut app = App::new();
    
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
