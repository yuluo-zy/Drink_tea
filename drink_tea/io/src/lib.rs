#![deny(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod boxed;
mod either;
mod prefixed;
mod scoped;
mod sensor;

pub use self::{
    boxed::BoxedIo,
    either::EitherIo,
    prefixed::PrefixedIo,
    scoped::ScopedIo,
    sensor::{Sensor, SensorIo},
};
pub use std::io::*;
use std::net::SocketAddr;
pub use tokio::io::{
    duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf,
};
pub use tokio_util::io::{poll_read_buf, poll_write_buf};

pub type Poll<T> = std::task::Poll<Result<T>>;

// === Peek ===

#[async_trait::async_trait]
pub trait Peek {
    async fn peek(&self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
impl Peek for tokio::net::TcpStream {
    async fn peek(&self, buf: &mut [u8]) -> Result<usize> {
        tokio::net::TcpStream::peek(self, buf).await
    }
}

#[async_trait::async_trait]
impl Peek for tokio::io::DuplexStream {
    async fn peek(&self, _: &mut [u8]) -> Result<usize> {
        Ok(0)
    }
}

// === PeerAddr ===

pub trait PeerAddr {
    fn peer_addr(&self) -> Result<SocketAddr>;
}

impl PeerAddr for tokio::net::TcpStream {
    fn peer_addr(&self) -> Result<SocketAddr> {
        tokio::net::TcpStream::peer_addr(self)
    }
}

#[cfg(feature = "tokio-test")]
impl PeerAddr for tokio_test::io::Mock {
    fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(([0, 0, 0, 0], 0).into())
    }
}

impl PeerAddr for tokio::io::DuplexStream {
    fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(([0, 0, 0, 0], 0).into())
    }
}
