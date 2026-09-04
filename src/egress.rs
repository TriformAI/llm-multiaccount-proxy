use std::fmt;

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
}

impl ProxyEndpoint {
    pub fn parse(_value: &str) -> Result<Self, EgressError> {
        unimplemented!("RED: residential proxy parsing")
    }

    pub fn redacted_authority(&self) -> String {
        let _ = &self.url;
        unimplemented!("RED: secret-safe proxy display")
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

    pub fn authorize(&self, _destination: &Url) -> Result<(), EgressError> {
        let _ = (&self.allowlist, self.allow_unsafe_private_networks);
        unimplemented!("RED: destination SSRF policy")
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
    pub fn new(_endpoints: Vec<ProxyEndpoint>) -> Result<Self, EgressError> {
        unimplemented!("RED: ordered residential proxy chain")
    }

    pub fn active(&self) -> &ProxyEndpoint {
        &self.endpoints[self.active_index]
    }

    pub fn active_index(&self) -> usize {
        self.active_index
    }

    pub fn record_failure(&mut self) {
        let _ = (&self.consecutive_failures, &self.consecutive_successes);
        unimplemented!("RED: sticky proxy failover")
    }

    pub fn record_success(&mut self) {
        unimplemented!("RED: proxy recovery")
    }

    pub fn make_active(&mut self, _index: usize) -> Result<(), EgressError> {
        unimplemented!("RED: manual proxy activation")
    }
}
