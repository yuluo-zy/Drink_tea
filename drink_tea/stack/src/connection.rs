use std::future::Future;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tea_error::Error;

#[derive(Clone, Debug)]
pub struct WithoutConnectionMetadata<S>(S);

pub trait MakeConnection<T> {
    /// An I/O type that represents a connection to the remote endpoint.
    type Connection: AsyncRead + AsyncWrite;

    /// Metadata associated with the established connection.
    type Metadata;

    type Error: Into<Error>;

    type Future: Future<Output = Result<(Self::Connection, Self::Metadata), Self::Error>>;

    /// Determines whether the connector is ready to establish a connection.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Establishes a connection.
    fn connect(&mut self, t: T) -> Self::Future;

    /// Returns a new `Service` that drops the connection metadata from returned values.
    fn without_connection_metadata(self) -> WithoutConnectionMetadata<Self>
    where
        Self: Sized,
    {
        WithoutConnectionMetadata(self)
    }

    // Coerces a `MakeConnection` into a `Service`.
    // fn into_service(self) -> MakeConnectionService<Self>
    // where
    //     Self: Sized,
    // {
    //     MakeConnectionService(self)
    // }
}
// 
// impl<T, S, I, M> MakeConnection<T> for S
//     where
//         S: Service<T, Response = (I, M)>,
//         S::Error: Into<Error>,
//         I: AsyncRead + AsyncWrite,
// {
//     type Connection = I;
//     type Metadata = M;
//     type Error = S::Error;
//     type Future = S::Future;
// 
//     #[inline]
//     fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         Service::poll_ready(self, cx)
//     }
// 
//     #[inline]
//     fn connect(&mut self, t: T) -> Self::Future {
//         Service::call(self, t)
//     }
// }
