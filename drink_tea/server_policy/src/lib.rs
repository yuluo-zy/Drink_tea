#![deny(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]

mod network;

pub use self::network::Network;
use std::{collections::HashSet, hash::Hash, sync::Arc, time};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerPolicy {
    pub protocol: Protocol,
    pub authorizations: Vec<Authorization>,
    pub name: Arc<str>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub networks: Vec<Network>,
    pub authentication: Authentication,
    pub name: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authentication {
    Unauthenticated,
    TlsUnauthenticated,
    TlsAuthenticated {
        identities: HashSet<String>,
        suffixes: Vec<Suffix>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suffix {
    ends_with: String,
}

// === impl Suffix ===

impl From<Vec<String>> for Suffix {
    fn from(parts: Vec<String>) -> Self {
        let ends_with = if parts.is_empty() {
            "".to_string()
        } else {
            format!(".{}", parts.join("."))
        };
        Suffix { ends_with }
    }
}

impl Suffix {
    #[inline]
    pub fn contains(&self, name: &str) -> bool {
        name.ends_with(&self.ends_with)
    }
}
