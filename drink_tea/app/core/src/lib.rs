pub mod addr_match;
pub mod config;
pub mod dns;

pub use drain;
pub use tea_addr::{self as addr, Addr, NameAddr};
pub use tea_error::{is_error, Error, Infallible, Recover, Result};
pub use tea_tracing as trace;

#[derive(Clone, Debug)]
pub struct ProxyRuntime {
    pub drain: drain::Watch,
}
