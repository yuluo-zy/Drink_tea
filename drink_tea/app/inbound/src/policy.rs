#[derive(Clone, Debug, Error)]
#[error("unauthorized connection on unknown port {0}")]
pub struct DeniedUnknownPort(pub u16);

#[derive(Clone, Debug, Error)]
#[error("unauthorized connection on server {server}")]
pub struct DeniedUnauthorized {
    server: std::sync::Arc<str>,
}

pub trait CheckPolicy {
    /// Checks that the destination address is configured to allow traffic.
    fn check_policy(&self, dst: OrigDstAddr) -> Result<AllowPolicy, DeniedUnknownPort>;
}

#[derive(Clone, Debug)]
pub struct AllowPolicy {
    dst: OrigDstAddr,
    server: watch::Receiver<ServerPolicy>,
}
