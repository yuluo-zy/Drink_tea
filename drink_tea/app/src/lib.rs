use tea_app_core::trace;
use tokio::sync::mpsc;
use tracing::{debug, info, info_span, Instrument};

use tea_app_inbound;
use tea_app_outbound;
use tea_drive;

mod env;

#[derive(Clone, Debug)]
pub struct Config {
    pub outbound: tea_app_outbound::Config,
    pub inbound: tea_app_inbound::Config,
    pub tun: tea_drive::Config,
}

impl Config {
    pub fn try_from_env() -> Result<Self, env::EnvError> {
        env::Env.try_config()
    }
}

impl Config {
    pub async fn build<Bin, Bout>(
        self,
        bind_in: Bin,
        bind_out: Bout,
        shutdown_tx: mpsc::UnboundedSender<()>,
        log_level: trace::Handle,
    ) {
    }
}
