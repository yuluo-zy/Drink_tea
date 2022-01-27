pub use tea_app_core::{self as core};
use tea_app_core::{
    config::ServerConfig,
    dns, drain, trace,
    transport::{listen::Bind, ClientAddr, Local, OrigDstAddr, Remote, ServerAddr},
    Error, ProxyRuntime,
};
use tea_app_inbound;
use tea_app_outbound;
use tea_drive;
use tokio::sync::mpsc;
use tracing::{debug, info, info_span, Instrument};
mod env;

#[derive(Clone, Debug)]
pub struct Config {
    pub outbound: tea_app_outbound::Config,
    pub inbound: tea_app_inbound::Config,
    pub dns: dns::Config,
    pub tun: tea_drive::Config,
}

pub struct App {}
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
    ) -> Result<App, Error>
    where
        Bin: Bind<ServerConfig> + 'static,
        Bin::Addrs: Param<Remote<ClientAddr>> + Param<Local<ServerAddr>> + Param<OrigDstAddr>,
        Bout: Bind<ServerConfig> + 'static,
        Bout::Addrs: Param<Remote<ClientAddr>> + Param<Local<ServerAddr>> + Param<OrigDstAddr>,
    {
        let Config {
            outbound,
            inbound,
            dns,
            tun,
        } = self;

        debug!("building app");
        let dns = dns.build();

        let (drain_tx, drain_rx) = drain::channel();

        let runtime = ProxyRuntime {
            drain: drain_rx.clone(),
        };
    }
}
