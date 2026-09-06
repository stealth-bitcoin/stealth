//! In-memory store for asynchronous scan jobs.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use stealth_engine::progress::ScanProgress;
use stealth_engine::Report;

// Finished jobs stay queryable for a while, then get dropped lazily on
// the next job creation (no dedicated timer).
const FINISHED_JOB_RETENTION: Duration = Duration::from_secs(15 * 60);

/// Terminal result of a scan job.
#[derive(Debug, Clone)]
pub enum JobOutcome {
    Done(Report),
    Failed(String),
    Cancelled,
}

#[derive(Debug)]
struct JobEntry {
    progress: ScanProgress,
    outcome: Option<JobOutcome>,
    finished_at: Option<Instant>,
}

/// What a request handler needs to know about one job.
#[derive(Debug, Clone)]
pub struct JobView {
    pub outcome: Option<JobOutcome>,
    pub progress: ScanProgress,
}

#[derive(Debug, Default)]
pub struct JobStore {
    entries: Mutex<HashMap<String, JobEntry>>,
    sequence: AtomicU64,
}

impl JobStore {
    /// Register a new job around the given sink and return its id.
    /// Expired finished jobs are pruned as a side effect.
    pub fn create(&self, progress: ScanProgress) -> String {
        let id = self.next_id();
        let mut entries = self.lock();
        entries.retain(|_, entry| {
            entry
                .finished_at
                .is_none_or(|finished| finished.elapsed() < FINISHED_JOB_RETENTION)
        });
        entries.insert(
            id.clone(),
            JobEntry {
                progress,
                outcome: None,
                finished_at: None,
            },
        );
        id
    }

    /// Record a job's terminal outcome. The first outcome wins: a job
    /// never leaves a terminal state.
    pub fn finish(&self, id: &str, outcome: JobOutcome) {
        if let Some(entry) = self.lock().get_mut(id) {
            if entry.outcome.is_none() {
                entry.outcome = Some(outcome);
                entry.finished_at = Some(Instant::now());
            }
        }
    }

    pub fn view(&self, id: &str) -> Option<JobView> {
        self.lock().get(id).map(|entry| JobView {
            outcome: entry.outcome.clone(),
            progress: entry.progress.clone(),
        })
    }

    // Sequence for uniqueness, plus a cheap random suffix (std's
    // randomly-seeded hasher) so ids are not trivially guessable.
    fn next_id(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let entropy = RandomState::new().build_hasher().finish() as u32;
        format!("scan-{sequence}-{entropy:08x}")
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, JobEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let store = JobStore::default();
        let first = store.create(ScanProgress::new());
        let second = store.create(ScanProgress::new());
        assert!(first.starts_with("scan-"), "{first}");
        assert_ne!(first, second);
    }

    #[test]
    fn finish_is_terminal_and_first_outcome_wins() {
        let store = JobStore::default();
        let id = store.create(ScanProgress::new());
        store.finish(&id, JobOutcome::Cancelled);
        store.finish(&id, JobOutcome::Failed("late".into()));
        let view = store.view(&id).expect("job must exist");
        assert!(matches!(view.outcome, Some(JobOutcome::Cancelled)));
    }

    #[test]
    fn view_of_unknown_id_is_none() {
        let store = JobStore::default();
        assert!(store.view("nope").is_none());
    }
}
