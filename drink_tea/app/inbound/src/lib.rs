use tea_app_core::config::ConnectConfig;
use tea_app_core::transport::addrs::{Remote, ServerAddr};
use tea_app_core::{drain, svc, transport, Error, ProxyRuntime};

mod policy;

#[derive(Clone, Debug)]
pub struct Config {}

#[derive(Clone)]
struct Runtime {
    drain: drain::Watch,
}

#[derive(Clone)]
pub struct Inbound<S> {
    config: Config,
    runtime: Runtime,
    stack: svc::Stack<S>,
}

impl<S> Inbound<S> {
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn into_stack(self) -> svc::Stack<S> {
        self.stack
    }
    pub fn into_inner(self) -> S {
        self.stack.into_inner()
    }
    fn map_stack<T>(
        self,
        f: impl FnOnce(&Config, &Runtime, svc::Stack<S>) -> svc::Stack<T>,
    ) -> Inbound<T> {
        let stack = f(&self.config, &self.runtime, self.stack);
        Inbound {
            config: self.config,
            runtime: self.runtime,
            stack,
        }
    }
}

impl Inbound<()> {
    pub fn new(config: Config, runtime: ProxyRuntime) -> Self {
        let runtime = Runtime {
            drain: runtime.drain,
        };
        Self {
            config,
            runtime,
            stack: svc::stack(()),
        }
    }

    pub fn with_stack<S>(self, stack: S) -> Inbound<S> {
        self.map_stack(move |_, _, _| svc::stack(stack))
    }

    // 准备入站堆栈以建立 TCP 连接（用于 TCP 转发和 HTTP 代理）
    pub fn into_tcp_connect<T>(
        self,
        proxy_port: u16,
    ) -> Inbound<
        impl svc::MakeConnection<
                T,
                Connection = impl Send + Unpin,
                Metadata = impl Send + Unpin,
                Error = Error,
                Future = impl Send,
            > + Clone,
    >
    where
        T: svc::Param<Remote<ServerAddr>> + 'static,
    {
        self.map_stack(|config, _, _| {
            // Establishes connections to remote peers (for both TCP
            // forwarding and HTTP proxying).
            let ConnectConfig {
                ref keepalive,
                ref timeout,
                ..
            } = config.proxy.connect;

            #[derive(Debug, thiserror::Error)]
            #[error("inbound connection must not target port {0}")]
            struct Loop(u16);

            svc::stack(transport::connect::ConnectTcp::new(*keepalive))
                // Limits the time we wait for a connection to be established.
                .push_connect_timeout(*timeout)
                // Prevent connections that would target the inbound proxy port from looping.
                .push_request_filter(move |t: T| {
                    let addr = t.param();
                    let port = addr.port();
                    if port == proxy_port {
                        return Err(Loop(port));
                    }
                    Ok(addr)
                })
        })
    }
}

impl<S> Inbound<S> {
    // pub fn push<L>(self, layer: L) -> Inbound<L::Service> {
    //     self.map_stack(|_, _, stack| stack.push(layer))
    // }

    // Forwards TCP streams that cannot be decoded as HTTP.
    //
    // Looping is always prevented.
    pub fn push_tcp_forward<T, I>(
        self,
    ) -> Inbound<
        svc::ArcNewService<
            T,
            impl svc::Service<I, Response = (), Error = Error, Future = impl Send> + Clone,
        >,
    >
    where
        T: svc::Param<transport::labels::Key> + Clone + Send + 'static,
        I: io::AsyncRead + io::AsyncWrite,
        I: Debug + Send + Unpin + 'static,
        S: svc::MakeConnection<T> + Clone + Send + Sync + Unpin + 'static,
        S::Connection: Send + Unpin,
        S::Metadata: Send + Unpin,
        S::Future: Send,
    {
        self.map_stack(|_, rt, connect| {
            connect
                .push(transport::metrics::Client::layer(
                    rt.metrics.proxy.transport.clone(),
                ))
                .push(svc::stack::WithoutConnectionMetadata::layer())
                .push_make_thunk()
                .push_on_service(
                    svc::layers()
                        .push(tcp::Forward::layer())
                        .push(drain::Retain::layer(rt.drain.clone())),
                )
                .instrument(|_: &_| debug_span!("tcp"))
                .push(svc::ArcNewService::layer())
                .check_new::<T>()
        })
    }
}
