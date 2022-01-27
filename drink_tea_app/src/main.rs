use tea_app::core::transport::listen::BindTcp;
use tea_app::Config;
use tea_tracing as trace;
use tokio::sync::mpsc;
pub use tracing::{debug, error, info, warn};

mod runtime;

// 定义全局内存分配器
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

const EX_USAGE: i32 = 64;

fn main() {
    let trace = match trace::init() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Invalid logging configuration: {}", e);
            std::process::exit(EX_USAGE);
        }
    };
    info!("start!");
    // 解析环境变量里面的 配置项
    let config = match Config::try_from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Invalid configuration: {}", e);
            std::process::exit(EX_USAGE);
        }
    };
    runtime::build().block_on(async move {
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
        let bind = BindTcp::with_orig_dst();
        let app = match config.build(bind, bind, shutdown_tx, trace).await {
            Ok(app) => app,
            Err(e) => {
                eprintln!("Initialization failure: {}", e);
                std::process::exit(1);
            }
        };

        info!("Inbound interface on {}", app.inbound_addr());
        info!("Outbound interface on {}", app.outbound_addr());
    })
}
