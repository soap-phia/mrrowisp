mod protocol;
mod server;

use clap::Parser;
use mimalloc::MiMalloc;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use tracing_subscriber::EnvFilter;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Deserialize)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    root: Option<String>,
    buffer_bytes: Option<u32>,
    continue_threshold_bytes: Option<u32>,
}

#[derive(Parser, Debug)]
#[command(name = "mrrowisp", about = "Wisp v1/v2 + Twisp server in Rust")]
struct Args {
    #[arg(short = 'c', long, default_value = "config.json")]
    config: String,

    #[arg(short = 'h', long)]
    host: Option<String>,

    #[arg(short = 'p', long)]
    port: Option<u16>,

    #[arg(short = 'r', long)]
    root: Option<String>,

    #[arg(short = 'b', long, value_name = "BYTES")]
    buffer_bytes: Option<u32>,

    #[arg(short = 't', long, value_name = "BYTES")]
    continue_threshold_bytes: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let file_cfg = load_config_file(&args.config)?;

    let host = args
        .host
        .or_else(|| file_cfg.host)
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port = args.port.or_else(|| file_cfg.port).unwrap_or(6001);
    let root = args
        .root
        .or_else(|| file_cfg.root)
        .unwrap_or_else(|| "./twisp".to_string());
    let buffer_bytes = args
        .buffer_bytes
        .or_else(|| file_cfg.buffer_bytes)
        .unwrap_or(16 * 1024 * 1024);
    let continue_threshold_bytes = args
        .continue_threshold_bytes
        .or_else(|| file_cfg.continue_threshold_bytes)
        .unwrap_or((buffer_bytes as u64 * 90 / 100) as u32);

    let cfg = server::ServerConfig {
        host,
        port,
        root,
        buffer_bytes,
        continue_threshold_bytes,
    };
    server::run(cfg).await
}

fn load_config_file(path: &str) -> anyhow::Result<FileConfig> {
    let path = Path::new(path);
    if !path.exists() {
        return Ok(FileConfig {
            host: None,
            port: None,
            root: None,
            buffer_bytes: None,
            continue_threshold_bytes: None,
        });
    }

    let contents = fs::read_to_string(path)?;
    let cfg: FileConfig = serde_json::from_str(&contents)?;
    Ok(cfg)
}
