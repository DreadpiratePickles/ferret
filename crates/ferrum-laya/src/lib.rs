#![no_std]
//! `ferrum-laya` — explainable scored decision engine (integer math only).
//!
//! The System-1 core (signals, scoring, hysteresis, [`LayaEngine::system1`]) is `#![no_std]`, has no
//! allocation and builds for bare-metal targets with `--no-default-features`. System-2
//! ([`LayaEngine::system2`], IDS escalation) needs the `std` crate `ferrum-ids` and is only available
//! with the default-on `ids` feature.
//!
//! Replaces the old `if/else` ladder in `ferrum-brain`:
//!
//! 1. [`signals_from`] maps telemetry to six normalized `0..=100` signals ([`SignalVector`]).
//! 2. A transparent weight table scores six policies and normalizes them to a distribution that
//!    sums to exactly 100 (largest-remainder rounding) — see the `score` module.
//! 3. A hysteresis state machine ([`LayaEngine`]) stops borderline inputs from flapping the policy.
//! 4. `LayaEngine::system2` (feature `ids`) lets IDS detections escalate the decision.
//!
//! Note: `decision_latency_ms` is intentionally absent; it is a presentation concern of the caller.

#[cfg(test)]
extern crate std;

mod hysteresis;
mod score;
mod signals;

pub use hysteresis::{LayaEngine, SWITCH_DWELL_TICKS, SWITCH_MARGIN_PCT};
pub use score::{RationaleParts, TypedDecision, N_POLICIES};
pub use signals::{signals_from, SignalKind, SignalVector, N_SIGNALS};

#[cfg(all(test, feature = "ids"))]
mod tests {
    use super::*;
    use ferrum_ids::{Detection, Severity};
    use ferrum_proto::PolicyMode;
    use std::string::String;

    fn det(sev: Severity, rec: PolicyMode) -> Detection {
        Detection {
            rule_id: "T-001",
            severity: sev,
            title: "test",
            mitre: "T0000",
            explanation: String::new(),
            recommended_policy: rec,
        }
    }

    fn base() -> TypedDecision {
        LayaEngine::new().system1(&SignalVector::default())
    }

    #[test]
    fn test_critical_detection_forces_lockdown() {
        let mut e = LayaEngine::new();
        let d = e.system2(
            base(),
            &[det(Severity::Critical, PolicyMode::ForensicLockdown)],
        );
        assert_eq!(d.selected_policy, PolicyMode::ForensicLockdown);
        assert!(d.trigger_s3_camera_mic);
        assert_eq!(d.confidence_pct, 99);
    }

    #[test]
    fn test_high_detection_adopts_recommended() {
        let mut e = LayaEngine::new();
        let d = e.system2(base(), &[det(Severity::High, PolicyMode::SurgicalCapture)]);
        assert_eq!(d.selected_policy, PolicyMode::SurgicalCapture);
    }

    #[test]
    fn test_high_adoption_reports_adopted_policy_confidence() {
        // On a High (non-critical) escalation, confidence must track the ADOPTED policy's share
        // of the System-1 distribution, not the superseded incumbent's figure.
        let mut e = LayaEngine::new();
        let s1 = base();
        let d = e.system2(s1, &[det(Severity::High, PolicyMode::SurgicalCapture)]);
        let adopted_share = d
            .distribution
            .iter()
            .find(|(p, _)| *p == PolicyMode::SurgicalCapture)
            .map(|(_, share)| *share)
            .expect("adopted policy is always present in the distribution");
        assert_eq!(d.confidence_pct, adopted_share);
        // And when the adopted policy differs from what System-1 selected, the stale number is gone.
        if s1.selected_policy != PolicyMode::SurgicalCapture {
            assert_ne!(d.confidence_pct, s1.confidence_pct);
        }
    }

    #[test]
    fn test_low_detection_leaves_system1() {
        let mut e = LayaEngine::new();
        let s1 = base();
        let d = e.system2(s1, &[det(Severity::Low, PolicyMode::SurgicalCapture)]);
        assert_eq!(d, s1);
    }
}
