//! The active policy, shared by every request. Judges upload an edited catalog
//! and watch the layer adapt (task.md §6), so activation must not need a
//! restart — and a broken upload must not take the control layer down: it is
//! rejected before it ever reaches this handle.

use std::sync::Arc;

use arc_swap::ArcSwap;

use super::Policy;

/// A cheap-to-clone handle to the active policy. Readers take a snapshot with
/// [`PolicyHandle::load`]; activation swaps the pointer, so a request that is
/// already running finishes under the policy it started with.
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<ArcSwap<Policy>>,
}

impl PolicyHandle {
    pub fn new(policy: Policy) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(policy)),
        }
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<Policy>> {
        self.inner.load()
    }

    /// A snapshot that may be held across `.await` points.
    pub fn load_full(&self) -> Arc<Policy> {
        self.inner.load_full()
    }

    /// Atomically activate an already validated policy. Callers always observe
    /// either the old policy or the complete new one, never a half-applied
    /// configuration. Returns `false` when the version is already active.
    pub fn replace(&self, next: Policy) -> bool {
        if next.sha256 == self.inner.load().sha256 {
            return false;
        }
        tracing::info!(
            version = %next.sha256[..12].to_owned(),
            deterministic = next.deterministic.len(),
            semantic = next.semantic.len(),
            "policy activated",
        );
        self.inner.store(Arc::new(next));
        true
    }
}
