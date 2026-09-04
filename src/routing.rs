use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
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
    outcome: UpstreamOutcome,
    request_bytes_may_have_been_sent: bool,
    response_bytes_seen: bool,
) -> RetryDecision {
    if request_bytes_may_have_been_sent || response_bytes_seen {
        return RetryDecision::ReturnFailure;
    }
    match outcome {
        UpstreamOutcome::Unauthorized
        | UpstreamOutcome::RateLimited { .. }
        | UpstreamOutcome::Overloaded { .. }
        | UpstreamOutcome::TransientFailure => RetryDecision::RetryAnotherAccount,
        UpstreamOutcome::Success => RetryDecision::ReturnFailure,
    }
}

pub struct Router {
    accounts: HashMap<String, RouteAccount>,
    sessions: HashMap<String, SessionBinding>,
}

#[derive(Clone)]
struct SessionBinding {
    account_id: String,
    last_seen_at: DateTime<Utc>,
}

const SESSION_IDLE_TIMEOUT: Duration = Duration::minutes(30);

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

    pub fn replace_accounts(&mut self, accounts: Vec<RouteAccount>) {
        let replacement: HashMap<_, _> = accounts
            .into_iter()
            .map(|account| (account.id.clone(), account))
            .collect();
        self.sessions
            .retain(|_, binding| replacement.contains_key(&binding.account_id));
        self.accounts = replacement;
    }

    pub fn session_count(&mut self, now: DateTime<Utc>) -> usize {
        self.sessions
            .retain(|_, binding| binding.last_seen_at + SESSION_IDLE_TIMEOUT >= now);
        self.sessions.len()
    }

    pub fn start_request(&mut self, account_id: &str) -> Result<(), RouteError> {
        let account = self
            .accounts
            .get_mut(account_id)
            .ok_or(RouteError::UnknownAccount)?;
        account.in_flight = account.in_flight.saturating_add(1);
        Ok(())
    }

    pub fn choose(
        &mut self,
        request: &RouteRequest,
        now: DateTime<Utc>,
    ) -> Result<RouteSelection, RouteError> {
        if let Some(session_id) = request.session_id.as_deref() {
            let binding = self.sessions.get(session_id).cloned();
            if let Some(account) = binding
                .as_ref()
                .filter(|binding| binding.last_seen_at + SESSION_IDLE_TIMEOUT >= now)
                .and_then(|binding| self.accounts.get(&binding.account_id))
            {
                if eligible(account, &request.model, now) {
                    let account_id = account.id.clone();
                    let provider = account.provider.clone();
                    if let Some(binding) = self.sessions.get_mut(session_id) {
                        binding.last_seen_at = now;
                    }
                    return Ok(RouteSelection {
                        account_id,
                        provider,
                        reused_session: true,
                    });
                }
            }
            self.sessions.remove(session_id);
        }

        let account = self
            .accounts
            .values()
            .filter(|account| eligible(account, &request.model, now))
            .min_by(|left, right| {
                left.in_flight
                    .cmp(&right.in_flight)
                    .then_with(|| {
                        left.utilization_basis_points
                            .cmp(&right.utilization_basis_points)
                    })
                    .then_with(|| left.id.cmp(&right.id))
            })
            .ok_or(RouteError::NoEligibleAccount)?;

        if let Some(session_id) = &request.session_id {
            self.sessions.insert(
                session_id.clone(),
                SessionBinding {
                    account_id: account.id.clone(),
                    last_seen_at: now,
                },
            );
        }
        Ok(RouteSelection {
            account_id: account.id.clone(),
            provider: account.provider.clone(),
            reused_session: false,
        })
    }

    pub fn record_outcome(
        &mut self,
        account_id: &str,
        outcome: UpstreamOutcome,
    ) -> Result<(), RouteError> {
        let account = self
            .accounts
            .get_mut(account_id)
            .ok_or(RouteError::UnknownAccount)?;
        account.in_flight = account.in_flight.saturating_sub(1);
        match outcome {
            UpstreamOutcome::Success => {}
            UpstreamOutcome::Unauthorized => {
                account.healthy = false;
                self.sessions
                    .retain(|_, binding| binding.account_id != account_id);
            }
            UpstreamOutcome::RateLimited { retry_at }
            | UpstreamOutcome::Overloaded { retry_at } => {
                account.depleted_until = Some(retry_at);
                self.sessions
                    .retain(|_, binding| binding.account_id != account_id);
            }
            UpstreamOutcome::TransientFailure => {
                self.sessions
                    .retain(|_, binding| binding.account_id != account_id);
            }
        }
        Ok(())
    }
}

fn eligible(account: &RouteAccount, model: &str, now: DateTime<Utc>) -> bool {
    account.enabled
        && account.healthy
        && account
            .depleted_until
            .is_none_or(|depleted_until| depleted_until <= now)
        && (model.is_empty() || crate::models::accepted(&account.models, model))
}
