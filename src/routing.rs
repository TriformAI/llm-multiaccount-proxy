use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAccount {
    pub id: String,
    pub provider: String,
    pub enabled: bool,
    pub healthy: bool,
    pub in_flight: u32,
    pub utilization_basis_points: u16,
    pub models: HashSet<String>,
    pub depleted_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRequest {
    pub session_id: Option<String>,
    pub model: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSelection {
    pub account_id: String,
    pub provider: String,
    pub reused_session: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RouteError {
    #[error("no healthy account can serve this request")]
    NoEligibleAccount,
    #[error("unknown account")]
    UnknownAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamOutcome {
    Success,
    Unauthorized,
    RateLimited { retry_at: DateTime<Utc> },
    Overloaded { retry_at: DateTime<Utc> },
    TransientFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    RetryAnotherAccount,
    ReturnFailure,
}

pub fn retry_decision(
    _outcome: UpstreamOutcome,
    _request_bytes_may_have_been_sent: bool,
    _response_bytes_seen: bool,
) -> RetryDecision {
    unimplemented!("RED: streaming retry boundary")
}

pub struct Router {
    accounts: HashMap<String, RouteAccount>,
    sessions: HashMap<String, String>,
}

impl Router {
    pub fn new(accounts: Vec<RouteAccount>) -> Self {
        Self {
            accounts: accounts
                .into_iter()
                .map(|account| (account.id.clone(), account))
                .collect(),
            sessions: HashMap::new(),
        }
    }

    pub fn choose(
        &mut self,
        _request: &RouteRequest,
        _now: DateTime<Utc>,
    ) -> Result<RouteSelection, RouteError> {
        let _ = (&self.accounts, &self.sessions);
        unimplemented!("RED: sticky capacity routing")
    }

    pub fn record_outcome(
        &mut self,
        _account_id: &str,
        _outcome: UpstreamOutcome,
    ) -> Result<(), RouteError> {
        unimplemented!("RED: upstream response classification")
    }
}
