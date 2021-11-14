use tea_signal as signal;
use tea_tracing as trace;
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
    info!("start!")
}
