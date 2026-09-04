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
        request: &RouteRequest,
        now: DateTime<Utc>,
    ) -> Result<RouteSelection, RouteError> {
        if let Some(session_id) = request.session_id.as_deref() {
            let bound_account = self.sessions.get(session_id).cloned();
            if let Some(account) = bound_account
                .as_ref()
                .and_then(|account_id| self.accounts.get(account_id))
            {
                if eligible(account, &request.model, now) {
                    return Ok(RouteSelection {
                        account_id: account.id.clone(),
                        provider: account.provider.clone(),
                        reused_session: true,
                    });
                }
            }
        }

        let account = self
            .accounts
            .values()
            .filter(|account| eligible(account, &request.model, now))
            .min_by(|left, right| {
                left.utilization_basis_points
                    .cmp(&right.utilization_basis_points)
                    .then_with(|| left.in_flight.cmp(&right.in_flight))
                    .then_with(|| left.id.cmp(&right.id))
            })
            .ok_or(RouteError::NoEligibleAccount)?;

        if let Some(session_id) = &request.session_id {
            self.sessions.insert(session_id.clone(), account.id.clone());
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
        match outcome {
            UpstreamOutcome::Success => {}
            UpstreamOutcome::Unauthorized => {
                account.healthy = false;
                self.sessions
                    .retain(|_, selected_account| selected_account != account_id);
            }
            UpstreamOutcome::RateLimited { retry_at }
            | UpstreamOutcome::Overloaded { retry_at } => {
                account.depleted_until = Some(retry_at);
                self.sessions
                    .retain(|_, selected_account| selected_account != account_id);
            }
            UpstreamOutcome::TransientFailure => {
                self.sessions
                    .retain(|_, selected_account| selected_account != account_id);
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
        && (model.is_empty() || account.models.is_empty() || account.models.contains(model))
}
