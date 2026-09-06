//! Shared progress sink for long-running scans.
//!
//! A [`ScanProgress`] is a cheaply clonable handle: the party running the
//! scan (engine/gateway) writes phases, rescan progress and the temporary
//! wallet name into it, while an observer (e.g. an HTTP job store) reads
//! snapshots and may request cancellation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// Phase of a running scan, in the order the pipeline traverses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Pending,
    Rescanning,
    LoadingHistory,
    Analyzing,
}

/// Point-in-time view of a [`ScanProgress`].
#[derive(Debug, Clone, PartialEq)]
pub struct ProgressSnapshot {
    pub phase: ScanPhase,
    /// Rescan completion in `0.0..=1.0`; only meaningful while
    /// [`ScanPhase::Rescanning`].
    pub rescan_progress: Option<f32>,
    /// Name of the temporary watch-only wallet backing the scan.
    pub wallet_name: Option<String>,
    pub cancel_requested: bool,
}

#[derive(Debug, Default)]
struct ProgressState {
    phases: Vec<ScanPhase>,
    rescan_progress: Option<f32>,
    wallet_name: Option<String>,
}

/// Thread-safe scan progress sink.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    state: Arc<Mutex<ProgressState>>,
    cancelled: Arc<AtomicBool>,
}

impl ScanProgress {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a phase transition. Consecutive duplicates are collapsed.
    pub fn set_phase(&self, phase: ScanPhase) {
        let mut state = self.lock();
        if state.phases.last() != Some(&phase) {
            state.phases.push(phase);
        }
    }

    /// Record rescan completion, clamped to `0.0..=1.0`.
    pub fn set_rescan_progress(&self, progress: f32) {
        self.lock().rescan_progress = Some(progress.clamp(0.0, 1.0));
    }

    pub fn set_wallet_name(&self, name: impl Into<String>) {
        self.lock().wallet_name = Some(name.into());
    }

    pub fn request_cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        let state = self.lock();
        ProgressSnapshot {
            phase: state.phases.last().copied().unwrap_or(ScanPhase::Pending),
            rescan_progress: state.rescan_progress,
            wallet_name: state.wallet_name.clone(),
            cancel_requested: self.cancel_requested(),
        }
    }

    /// Ordered list of phases the scan has traversed so far.
    pub fn phase_history(&self) -> Vec<ScanPhase> {
        self.lock().phases.clone()
    }

    // A sink write must never take the scan down; recover from poisoning.
    fn lock(&self) -> MutexGuard<'_, ProgressState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanPhase, ScanProgress};

    #[test]
    fn snapshot_starts_pending_without_progress_or_wallet() {
        let sink = ScanProgress::new();
        let snapshot = sink.snapshot();
        assert_eq!(snapshot.phase, ScanPhase::Pending);
        assert_eq!(snapshot.rescan_progress, None);
        assert_eq!(snapshot.wallet_name, None);
        assert!(!snapshot.cancel_requested);
        assert!(sink.phase_history().is_empty());
    }

    #[test]
    fn set_phase_records_ordered_history_without_consecutive_duplicates() {
        let sink = ScanProgress::new();
        sink.set_phase(ScanPhase::Rescanning);
        sink.set_phase(ScanPhase::Rescanning);
        sink.set_phase(ScanPhase::LoadingHistory);
        sink.set_phase(ScanPhase::Analyzing);

        assert_eq!(
            sink.phase_history(),
            vec![
                ScanPhase::Rescanning,
                ScanPhase::LoadingHistory,
                ScanPhase::Analyzing,
            ]
        );
        assert_eq!(sink.snapshot().phase, ScanPhase::Analyzing);
    }

    #[test]
    fn rescan_progress_is_clamped_to_unit_interval() {
        let sink = ScanProgress::new();
        sink.set_rescan_progress(0.42);
        assert_eq!(sink.snapshot().rescan_progress, Some(0.42));
        sink.set_rescan_progress(7.0);
        assert_eq!(sink.snapshot().rescan_progress, Some(1.0));
        sink.set_rescan_progress(-1.0);
        assert_eq!(sink.snapshot().rescan_progress, Some(0.0));
    }

    #[test]
    fn wallet_name_and_cancellation_are_shared_across_clones() {
        let sink = ScanProgress::new();
        let observer = sink.clone();

        sink.set_wallet_name("_stealth_scan_1_2_3");
        assert_eq!(
            observer.snapshot().wallet_name.as_deref(),
            Some("_stealth_scan_1_2_3")
        );

        assert!(!observer.cancel_requested());
        sink.request_cancel();
        assert!(observer.cancel_requested());
        assert!(observer.snapshot().cancel_requested);
    }
}
