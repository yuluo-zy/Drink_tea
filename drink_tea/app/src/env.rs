use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tea_app_core::dns::Config;
use tea_app_core::{addr, dns, Addr};
use thiserror::Error;
use tracing::{debug, error, info, warn};

pub trait Strings {
    /// Retrieves the value for the key `key`.
    ///
    /// `key` must be one of the `ENV_` values below.
    fn get(&self, key: &str) -> Result<Option<String>, EnvError>;
}

/// An implementation of `Strings` that reads the values from environment variables.
pub struct Env;

/// Errors produced when loading a `Config` struct.
#[derive(Clone, Debug, Error)]
pub enum EnvError {
    #[error("invalid environment variable")]
    InvalidEnvVar,
    #[error("no destination service configured")]
    NoDestinationAddress,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("not a valid duration")]
    NotADuration,
    #[error("not a valid DNS domain suffix")]
    NotADomainSuffix,
    #[error("not a boolean value: {0}")]
    NotABool(
        #[from]
        #[source]
        std::str::ParseBoolError,
    ),
    #[error("not an integer: {0}")]
    NotAnInteger(
        #[from]
        #[source]
        std::num::ParseIntError,
    ),
    #[error("not a floating-point number: {0}")]
    NotAFloat(
        #[from]
        #[source]
        std::num::ParseFloatError,
    ),
    #[error("not a valid subnet mask")]
    NotANetwork,
    #[error("host is not an IP address")]
    HostIsNotAnIpAddress,
    #[error("not a valid IP address: {0}")]
    NotAnIp(
        #[from]
        #[source]
        std::net::AddrParseError,
    ),
    #[error(transparent)]
    AddrError(addr::Error),
    #[error("not a valid identity name")]
    NameError,
    #[error("could not read token source")]
    InvalidTokenSource,
    #[error("invalid trust anchors")]
    InvalidTrustAnchors,
    #[error("not a valid port policy: {0}")]
    InvalidPortPolicy(String),
}

impl Strings for Env {
    fn get(&self, key: &str) -> Result<Option<String>, EnvError> {
        use std::env;

        match env::var(key) {
            Ok(value) => Ok(Some(value)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                error!("{} is not encoded in Unicode", key);
                Err(EnvError::InvalidEnvVar)
            }
        }
    }
}
pub fn parse_config<S: Strings>(strings: &S) -> Result<super::Config, EnvError> {
    let outbound_listener_addr = parse(strings, ENV_OUTBOUND_LISTEN_ADDR, parse_socket_addr);
    let inbound_listener_addr = parse(strings, ENV_INBOUND_LISTEN_ADDR, parse_socket_addr);

    Ok(super::Config {
        outbound: tea_app_outbound::Config {},
        inbound: tea_app_inbound::Config {},
        dns: tea_app_core::dns::Config {
            min_ttl: None,
            max_ttl: None,
            resolv_conf_path: Default::default(),
        },
        tun: tea_drive::Config {},
    })
}
impl Env {
    pub fn try_config(&self) -> Result<super::Config, EnvError> {
        parse_config(self)
    }
}

fn parse_bool(s: &str) -> Result<bool, ParseError> {
    s.parse().map_err(Into::into)
}

fn parse_number<T>(s: &str) -> Result<T, ParseError>
where
    T: FromStr,
    ParseError: From<T::Err>,
{
    s.parse().map_err(Into::into)
}

fn parse_duration(s: &str) -> Result<Duration, ParseError> {
    use regex::Regex;

    let re = Regex::new(r"^\s*(\d+)(ms|s|m|h|d)?\s*$").expect("duration regex");

    let cap = re.captures(s).ok_or(ParseError::NotADuration)?;

    let magnitude = parse_number(&cap[1])?;
    match cap.get(2).map(|m| m.as_str()) {
        None if magnitude == 0 => Ok(Duration::from_secs(0)),
        Some("ms") => Ok(Duration::from_millis(magnitude)),
        Some("s") => Ok(Duration::from_secs(magnitude)),
        Some("m") => Ok(Duration::from_secs(magnitude * 60)),
        Some("h") => Ok(Duration::from_secs(magnitude * 60 * 60)),
        Some("d") => Ok(Duration::from_secs(magnitude * 60 * 60 * 24)),
        _ => Err(ParseError::NotADuration),
    }
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, ParseError> {
    match parse_addr(s)? {
        Addr::Socket(a) => Ok(a),
        _ => {
            error!("Expected IP:PORT; found: {}", s);
            Err(ParseError::HostIsNotAnIpAddress)
        }
    }
}

fn parse_ip_set(s: &str) -> Result<HashSet<IpAddr>, ParseError> {
    s.split(',')
        .map(|s| s.parse::<IpAddr>().map_err(Into::into))
        .collect()
}

fn parse_addr(s: &str) -> Result<Addr, ParseError> {
    Addr::from_str(s).map_err(|e| {
        error!("Not a valid address: {}", s);
        ParseError::AddrError(e)
    })
}

fn parse_port_set(s: &str) -> Result<HashSet<u16>, ParseError> {
    let mut set = HashSet::new();
    for num in s.split(',') {
        set.insert(parse_number::<u16>(num)?);
    }
    Ok(set)
}

pub(super) fn parse<T, Parse>(
    strings: &dyn Strings,
    name: &str,
    parse: Parse,
) -> Result<Option<T>, EnvError>
where
    Parse: FnOnce(&str) -> Result<T, ParseError>,
{
    match strings.get(name)? {
        Some(ref s) => {
            let r = parse(s).map_err(|parse_error| {
                error!("{}={:?} is not valid: {:?}", name, s, parse_error);
                EnvError::InvalidEnvVar
            })?;
            Ok(Some(r))
        }
        None => Ok(None),
    }
}

#[allow(dead_code)]
fn parse_deprecated<T, Parse>(
    strings: &dyn Strings,
    name: &str,
    deprecated_name: &str,
    f: Parse,
) -> Result<Option<T>, EnvError>
where
    Parse: Copy,
    Parse: Fn(&str) -> Result<T, ParseError>,
{
    match parse(strings, name, f)? {
        Some(v) => Ok(Some(v)),
        None => {
            let v = parse(strings, deprecated_name, f)?;
            if v.is_some() {
                warn!("{} has been deprecated; use {}", deprecated_name, name);
            }
            Ok(v)
        }
    }
}

fn parse_dns_suffixes(list: &str) -> Result<HashSet<dns::Suffix>, ParseError> {
    let mut suffixes = HashSet::new();
    for item in list.split(',') {
        let item = item.trim();
        if !item.is_empty() {
            let sfx = parse_dns_suffix(item)?;
            suffixes.insert(sfx);
        }
    }

    Ok(suffixes)
}

fn parse_dns_suffix(s: &str) -> Result<dns::Suffix, ParseError> {
    if s == "." {
        return Ok(dns::Suffix::Root);
    }

    dns::Suffix::from_str(s).map_err(|_| ParseError::NotADomainSuffix)
}

// fn parse_networks(list: &str) -> Result<HashSet<IpNet>, ParseError> {
//     let mut nets = HashSet::new();
//     for input in list.split(',') {
//         let input = input.trim();
//         if !input.is_empty() {
//             let net = IpNet::from_str(input).map_err(|error| {
//                 error!(%input, %error, "Invalid network");
//                 ParseError::NotANetwork
//             })?;
//             nets.insert(net);
//         }
//     }
//     Ok(nets)
// }
