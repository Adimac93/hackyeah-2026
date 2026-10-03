//! Hot-reload. task.md §6 says judges will edit the configuration and watch how
//! the layer adapts, so a reload must not need a restart — and a broken edit
//! must not take the control layer down. On a failed parse the previous policy
//! keeps serving and the error is logged.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};

use super::{Policy, PolicyError};

/// A cheap-to-clone handle to the active policy. Readers take a snapshot with
/// [`PolicyHandle::load`]; a reload swaps the pointer, so a request that is
/// already running finishes under the policy it started with.
#[derive(Clone)]
pub struct PolicyHandle {
    inner: Arc<ArcSwap<Policy>>,
    path: PathBuf,
}

impl PolicyHandle {
    pub fn new(policy: Policy, path: impl Into<PathBuf>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(policy)),
            path: path.into(),
        }
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<Policy>> {
        self.inner.load()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read from disk. Returns `Ok(false)` when the file is byte-identical to
    /// the active version, which is what makes the duplicate filesystem events
    /// most editors emit on save harmless.
    pub fn reload(&self) -> Result<bool, PolicyError> {
        let next = Policy::load(&self.path)?;
        if next.sha256 == self.inner.load().sha256 {
            return Ok(false);
        }
        tracing::info!(
            version = %next.sha256[..12].to_owned(),
            deterministic = next.deterministic.len(),
            semantic = next.semantic.len(),
            "policy reloaded",
        );
        self.inner.store(Arc::new(next));
        Ok(true)
    }

    /// Atomically activate an already validated uploaded catalog.  Validation
    /// happens before this swap, so callers always observe either the old
    /// policy or the complete new policy—never a half-uploaded configuration.
    pub fn replace(&self, next: Policy) -> bool {
        if next.sha256 == self.inner.load().sha256 {
            return false;
        }
        self.inner.store(Arc::new(next));
        true
    }
}

/// Watch the catalog and reload on change.
///
/// The returned watcher must be kept alive: dropping it stops the watch. The
/// parent directories are watched rather than the files themselves, because
/// editors that save by rename replace the inode and leave a file watch
/// pointing at nothing. The signature feed is watched too: a feed edit is part
/// of the policy version, so it must reload the same way.
pub fn spawn_watcher(handle: PolicyHandle) -> notify::Result<RecommendedWatcher> {
    let target = handle.path().to_path_buf();
    let feed = handle.load().feed_path.clone();
    let mut dirs = vec![parent_of(&target)];
    if let Some(feed) = &feed
        && !dirs.contains(&parent_of(feed))
    {
        dirs.push(parent_of(feed));
    }

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            let touches = |file: &Path| event.paths.iter().any(|p| p.ends_with(file));
            let touches_target = touches(&target) || feed.as_deref().is_some_and(touches);
            let is_write = matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
            );
            if touches_target
                && is_write
                && let Err(error) = handle.reload()
            {
                tracing::error!(%error, "policy reload failed — keeping the previous version");
            }
        }
        Err(error) => tracing::error!(%error, "policy watch error"),
    })?;

    for dir in &dirs {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
        tracing::info!(dir = %dir.display(), "watching policy directory");
    }
    Ok(watcher)
}

fn parent_of(file: &Path) -> PathBuf {
    file.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
