use std::io;

use thiserror::Error;

pub type TeaResult<T> = Result<T, TeaError>;

#[derive(Error, Debug)]
pub enum TeaError {
    /// Crypto init error, this is recoverable
    #[error("Crypto initialization error: {0}")]
    CryptoInit(&'static str),

    /// Crypto init error, this is fatal and the init needs to be aborted
    #[error("Fatal crypto initialization error: {0}")]
    CryptoInitFatal(&'static str),

    /// Crypto error with this one message, no permanent error
    #[error("Crypto error: {0}")]
    Crypto(&'static str),

    #[error("Invalid crypto state: {0}")]
    InvalidCryptoState(&'static str),

    #[error("Invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("Socker error: {0}")]
    Socket(&'static str),

    #[error("Socker error: {0} ({1})")]
    SocketIo(&'static str, #[source] io::Error),

    #[error("Device error: {0}")]
    Device(&'static str),

    #[error("Device error: {0} ({1})")]
    DeviceIo(&'static str, #[source] io::Error),

    #[error("File error: {0}")]
    FileIo(&'static str, #[source] io::Error),

    #[error("Message error: {0}")]
    Message(&'static str),

    #[error("Beacon error: {0} ({1})")]
    BeaconIo(&'static str, #[source] io::Error),

    #[error("Parse error: {0}")]
    Parse(&'static str),

    #[error("Name can not be resolved: {0}")]
    NameUnresolvable(String),

    #[error("Mtu set error: {0}")]
    MtuSetError(&'static str),

    #[error("Invalid network address config : {0}")]
    InvalidNetAddressConfig(&'static str),

    #[error("Invalid network config : {0}")]
    InvalidNetConfig(&'static str),

    // kcp 错误定义
    #[error("packet to be sent too large to be fragmented")]
    OversizePacket,
    #[error("incomplete KCP packet")]
    IncompletePacket,
    #[error("invalid KCP command: {0}")]
    InvalidCommand(u8),
    #[error("empty queue (try again later)")]
    NotAvailable,
    #[error("wrong conv. (expected {expected}, found {found})")]
    WrongConv { expected: u16, found: u16 },
}
