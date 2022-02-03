use std::time::Duration;
use tea_proxy_transport::Keepalive;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub addr: ListenAddr,
    pub keepalive: Keepalive,
    pub transport: TransportSetting,
}

#[derive(Clone, Debug)]
pub struct ConnectConfig {
    // pub backoff: ExponentialBackoff,
    pub timeout: Duration,
    pub keepalive: Keepalive,
    // pub transport: TransportSetting,
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub server: ServerConfig,
    pub connect: ConnectConfig,
    pub buffer_capacity: usize,
    pub cache_max_idle_age: Duration,
    pub dispatch_timeout: Duration,
    pub max_in_flight_requests: usize,
    pub detect_protocol_timeout: Duration,
}
