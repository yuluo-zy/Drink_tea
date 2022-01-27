use crate::orig_dst::BindWithOrigDst;
use crate::{addrs::*, Keepalive};
use futures::prelude::*;
use std::{fmt, pin::Pin};
use tea_error::Result;
use tea_io as io;
use tea_stack::Param;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_stream::wrappers::TcpListenerStream;

/// Binds a listener, producing a stream of incoming connections.
///
/// Typically, this represents binding a TCP socket. However, it may also be an
/// stream of in-memory mock connections, for testing purposes.
pub trait Bind<T> {
    type Io: io::AsyncRead
        + io::AsyncWrite
        + io::Peek
        + io::PeerAddr
        + fmt::Debug
        + Unpin
        + Send
        + Sync
        + 'static;
    type Addrs: Clone + Send + Sync + 'static;
    type Incoming: Stream<Item = Result<(Self::Addrs, Self::Io)>> + Send + Sync + 'static;

    fn bind(self, params: &T) -> Result<Bound<Self::Incoming>>;
}

pub type Bound<I> = (Local<ServerAddr>, I);

#[derive(Copy, Clone, Debug, Default)]
pub struct BindTcp(());

#[derive(Copy, Clone, Debug, Default)]
pub struct BindUdp(());

#[derive(Clone, Debug)]
pub struct Addrs {
    pub server: Local<ServerAddr>,
    pub client: Remote<ClientAddr>,
}

#[derive(Debug, Error)]
#[error("failed to accept socket: {0}")]
struct AcceptError(#[source] io::Error);

#[derive(Debug, Error)]
#[error("failed to set TCP keepalive: {0}")]
struct KeepaliveError(#[source] io::Error);

#[derive(Debug, Error)]
#[error("failed to obtain peer address: {0}")]
struct PeerAddrError(#[source] io::Error);

// === impl BindTcp ===

impl BindTcp {
    pub fn with_orig_dst() -> BindWithOrigDst<Self> {
        BindWithOrigDst::from(Self::default())
    }
}

impl BindUdp {
    pub fn with_orig_dst() -> BindWithOrigDst<Self> {
        BindWithOrigDst::from(Self::default())
    }
}

impl<T> Bind<T> for BindTcp
where
    T: Param<ListenAddr> + Param<Keepalive>,
{
    type Io = TcpStream;
    type Addrs = Addrs;
    type Incoming = Pin<Box<dyn Stream<Item = Result<(Self::Addrs, Self::Io)>> + Send + Sync>>;

    fn bind(self, params: &T) -> Result<Bound<Self::Incoming>> {
        let listen = {
            let ListenAddr(addr) = params.param();
            let l = std::net::TcpListener::bind(addr)?;
            // Ensure that O_NONBLOCK is set on the socket before using it with Tokio.
            l.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(l).expect("listener must be valid")
        };
        let server = Local(ServerAddr(listen.local_addr()?));
        let Keepalive(keepalive) = params.param();
        let accept = TcpListenerStream::new(listen).map(move |res| {
            let tcp = res.map_err(AcceptError)?;
            super::set_nodelay_or_warn(&tcp);
            let tcp = super::set_keepalive_or_warn(tcp, keepalive).map_err(KeepaliveError)?;
            let client = Remote(ClientAddr(tcp.peer_addr().map_err(PeerAddrError)?));
            Ok((Addrs { server, client }, tcp))
        });

        Ok((server, Box::pin(accept)))
    }
}

// === impl Addrs ===

impl Param<Remote<ClientAddr>> for Addrs {
    #[inline]
    fn param(&self) -> Remote<ClientAddr> {
        self.client
    }
}

impl Param<Local<ServerAddr>> for Addrs {
    #[inline]
    fn param(&self) -> Local<ServerAddr> {
        self.server
    }
}
