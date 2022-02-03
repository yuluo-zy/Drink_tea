use std::future;
use std::pin::Pin;
use tea_app_core::transport::addrs::{ClientAddr, Local, OrigDstAddr, Remote, ServerAddr};
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
    // pub tun: tea_drive::Config
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
        } = self;

        debug!("building app");
        let dns = dns.build();

        let (drain_tx, drain_rx) = drain::channel();

        let runtime = ProxyRuntime {
            drain: drain_rx.clone(),
        };
        let inbound = Inbound::new(inbound, runtime.clone());
        let outbound = Outbound::new(outbound, runtime);
    }
}
pub struct App {
    drain: drain::Signal,
    inbound_addr: Local<ServerAddr>,
    outbound_addr: Local<ServerAddr>,
    start_proxy: Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
}

impl App {
    pub fn inbound_addr(&self) -> Local<ServerAddr> {
        self.inbound_addr
    }

    pub fn outbound_addr(&self) -> Local<ServerAddr> {
        self.outbound_addr
    }

    pub fn spawn(self) -> drain::Signal {
        let App {
            drain, start_proxy, ..
        } = self;

        let (admin_shutdown_tx, admin_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        debug!("spawning daemon thread");
        tokio::spawn(future::pending().map(|()| drop(admin_shutdown_tx)));
        std::thread::Builder::new()
            .name("admin".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("building admin runtime must succeed");
                rt.block_on(
                    async move {
                        debug!("running admin thread");
                        // we don't care if the admin shutdown channel is
                        // dropped or actually triggered.
                        let _ = admin_shutdown_rx.await;
                    }
                    .instrument(info_span!("daemon")),
                );
            })
            .expect("admin");

        tokio::spawn(start_proxy);

        drain
    }
}
