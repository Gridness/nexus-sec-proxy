use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tracing::error;

#[derive(Debug, Clone)]
pub(crate) struct DecisionLog {
	inner: Arc<Mutex<VecDeque<RecentDecision>>>,
	capacity: usize,
}

impl DecisionLog {
	pub(crate) fn new(capacity: usize) -> Self {
		Self {
			inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
			capacity,
		}
	}

	pub(crate) fn push(&self, decision: RecentDecision) {
		match self.inner.lock() {
			Ok(mut decisions) => {
				decisions.push_front(decision);
				while decisions.len() > self.capacity {
					decisions.pop_back();
				}
			}
			Err(error) => {
				error!("decision log lock was poisoned");
				let mut decisions = error.into_inner();
				decisions.push_front(decision);
				while decisions.len() > self.capacity {
					decisions.pop_back();
				}
			}
		}
	}

	pub(crate) fn list(&self, limit: usize) -> Vec<RecentDecision> {
		match self.inner.lock() {
			Ok(decisions) => decisions.iter().take(limit).cloned().collect(),
			Err(error) => {
				error!("decision log lock was poisoned");
				error.into_inner().iter().take(limit).cloned().collect()
			}
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RecentDecision {
	pub(crate) timestamp: String,
	pub(crate) repository: String,
	pub(crate) format: String,
	pub(crate) team: Option<String>,
	pub(crate) target: String,
	pub(crate) outcome: DecisionOutcome,
	pub(crate) policy_id: Option<String>,
	pub(crate) reason: String,
	pub(crate) vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionOutcome {
	Blocked,
	ReportOnly,
}

use nexus_sec_proxy_security::{BlockReport, PolicyContext};

use crate::audit::vulnerability_ids;
use crate::state::AppState;
use crate::time_utils::now_rfc3339;

pub(crate) fn record_decision(
	state: &AppState,
	context: &PolicyContext,
	outcome: DecisionOutcome,
	report: &BlockReport,
) {
	state.decision_log.push(RecentDecision {
		timestamp: now_rfc3339(),
		repository: context.repository.clone(),
		format: context.format.clone(),
		team: context.team.clone(),
		target: report.target.display_name(),
		outcome,
		policy_id: report.policy_id.clone(),
		reason: report.reason.clone(),
		vulnerability_ids: vulnerability_ids(report),
	});
}
