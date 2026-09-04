use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks5,
    Socks5h,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProxyEndpoint {
    pub protocol: ProxyProtocol,
    url: Url,
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyEndpoint")
            .field("protocol", &self.protocol)
            .field("url", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EgressError {
    #[error("unsupported proxy scheme")]
    UnsupportedProxyScheme,
    #[error("proxy endpoint requires a host")]
    MissingProxyHost,
    #[error("destination is not allowlisted")]
    DestinationNotAllowed,
    #[error("private, loopback, link-local, and metadata destinations are denied")]
    UnsafeDestination,
    #[error("the proxy chain has no configured endpoint")]
    EmptyProxyChain,
    #[error("proxy index does not exist")]
    UnknownProxyIndex,
    #[error("destination DNS resolution failed or returned no addresses")]
    ResolutionFailed,
}

impl ProxyEndpoint {
    pub fn parse(value: &str) -> Result<Self, EgressError> {
        let url = Url::parse(value).map_err(|_| EgressError::UnsupportedProxyScheme)?;
        let protocol = match url.scheme() {
            "http" => ProxyProtocol::Http,
            "https" => ProxyProtocol::Https,
            "socks5" => ProxyProtocol::Socks5,
            "socks5h" => ProxyProtocol::Socks5h,
            _ => return Err(EgressError::UnsupportedProxyScheme),
        };
        if url.host_str().is_none() {
            return Err(EgressError::MissingProxyHost);
        }
        Ok(Self { protocol, url })
    }

    pub fn redacted_authority(&self) -> String {
        let host = self.url.host_str().expect("validated proxy endpoint host");
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        match self.url.port() {
            Some(port) => format!("{}://{host}:{port}", self.url.scheme()),
            None => format!("{}://{host}", self.url.scheme()),
        }
    }

    pub(crate) fn as_url(&self) -> &Url {
        &self.url
    }
}

#[derive(Clone, Debug)]
pub struct DestinationPolicy {
    allowlist: Vec<String>,
    allow_unsafe_private_networks: bool,
}

impl DestinationPolicy {
    pub fn new(allowlist: Vec<String>, allow_unsafe_private_networks: bool) -> Self {
        Self {
            allowlist,
            allow_unsafe_private_networks,
        }
    }

    pub fn authorize(&self, destination: &Url) -> Result<(), EgressError> {
        let Some(host) = destination.host_str() else {
            return Err(EgressError::DestinationNotAllowed);
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if !self.allow_unsafe_private_networks && is_unsafe_host(&host) {
            return Err(EgressError::UnsafeDestination);
        }
        if self
            .allowlist
            .iter()
            .any(|entry| host_matches(&host, entry))
        {
            return Ok(());
        }
        Err(EgressError::DestinationNotAllowed)
    }

    pub async fn resolve_authorized(
        &self,
        destination: &Url,
    ) -> Result<Vec<SocketAddr>, EgressError> {
        self.authorize(destination)?;
        let host = destination
            .host_str()
            .ok_or(EgressError::DestinationNotAllowed)?;
        let port = destination
            .port_or_known_default()
            .ok_or(EgressError::DestinationNotAllowed)?;
        let addresses = if let Ok(address) = IpAddr::from_str(host) {
            vec![SocketAddr::new(address, port)]
        } else {
            tokio::net::lookup_host((host, port))
                .await
                .map_err(|_| EgressError::ResolutionFailed)?
                .collect::<Vec<_>>()
        };
        if addresses.is_empty() {
            return Err(EgressError::ResolutionFailed);
        }
        if !self.allow_unsafe_private_networks
            && addresses.iter().any(|address| is_unsafe_ip(address.ip()))
        {
            return Err(EgressError::UnsafeDestination);
        }
        Ok(addresses)
    }
}

#[derive(Clone, Debug)]
pub struct ProxyChain {
    endpoints: Vec<ProxyEndpoint>,
    active_index: usize,
    consecutive_failures: Vec<u8>,
    consecutive_successes: Vec<u8>,
}

impl ProxyChain {
    pub fn new(endpoints: Vec<ProxyEndpoint>) -> Result<Self, EgressError> {
        if endpoints.is_empty() {
            return Err(EgressError::EmptyProxyChain);
        }
        let endpoint_count = endpoints.len();
        Ok(Self {
            endpoints,
            active_index: 0,
            consecutive_failures: vec![0; endpoint_count],
            consecutive_successes: vec![0; endpoint_count],
        })
    }

    pub fn active(&self) -> &ProxyEndpoint {
        &self.endpoints[self.active_index]
    }

    pub fn active_index(&self) -> usize {
        self.active_index
    }

    pub fn record_failure(&mut self) {
        let active = self.active_index;
        self.consecutive_successes[active] = 0;
        self.consecutive_failures[active] = self.consecutive_failures[active].saturating_add(1);
        if self.consecutive_failures[active] >= 3 && active + 1 < self.endpoints.len() {
            self.active_index += 1;
        }
    }

    pub fn record_success(&mut self) {
        let active = self.active_index;
        self.consecutive_failures[active] = 0;
        self.consecutive_successes[active] = self.consecutive_successes[active].saturating_add(1);
    }

    pub fn make_active(&mut self, index: usize) -> Result<(), EgressError> {
        if index >= self.endpoints.len() {
            return Err(EgressError::UnknownProxyIndex);
        }
        self.active_index = index;
        self.consecutive_failures[index] = 0;
        self.consecutive_successes[index] = 0;
        Ok(())
    }
}

fn host_matches(host: &str, configured: &str) -> bool {
    let configured = configured.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = configured.strip_prefix("*.") {
        return host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    host == configured
}

fn is_unsafe_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    let Ok(address) = IpAddr::from_str(host) else {
        return false;
    };
    is_unsafe_ip(address)
}

fn is_unsafe_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast()
                || address.is_documentation()
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
        }
    }
}
