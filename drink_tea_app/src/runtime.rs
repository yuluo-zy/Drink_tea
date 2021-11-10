use tokio::runtime::{Builder, Runtime};
use tracing::{info, warn};

#[cfg(feature = "multicore")]
pub(crate) fn build() -> Runtime {

    let mut cores = std::env::var("DRINK_TEA_CORES")
        .ok()
        .and_then(|v| {
            let opt = v.parse::<usize>().ok().filter(|n| *n > 0);
            if opt.is_none() {
                warn!(DRINK_TEA_CORES = %v, "Ignoring invalid configuration");
            }
            opt
        })
        .unwrap_or(0);

    let cpus = num_cpus::get();
    debug_assert!(cpus > 0, "At least one CPU must be available");
    if cores > cpus {
        warn!(
            cpus,
            DRINK_TEA_CORES = cores,
            "Ignoring configuration due to insufficient resources"
        );
        cores = cpus;
    }

    match cores {
        // `0` is unexpected, but it's a wild world out there.
        0 | 1 => {
            info!("Using single-threaded proxy runtime");
            Builder::new_current_thread()
                .enable_all()
                .thread_name("proxy")
                .build()
                .expect("failed to build basic runtime!")
        }
        num_cpus => {
            info!(%cores, "Using multi-threaded proxy runtime");
            Builder::new_multi_thread()
                .enable_all()
                .thread_name("proxy")
                .worker_threads(num_cpus)
                .max_blocking_threads(num_cpus)
                .build()
                .expect("failed to build threaded runtime!")
        }
    }
}

#[cfg(not(feature = "multicore"))]
pub(crate) fn build() -> Runtime {
    Builder::new()
        .enable_all()
        .thread_name("proxy")
        .basic_scheduler()
        .build()
        .expect("failed to build basic runtime!")
}
