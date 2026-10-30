#![no_std]
//! `ferrum-laya` — explainable scored decision engine (`#![no_std]`, integer math only).
//!
//! Replaces the old `if/else` ladder in `ferrum-brain`:
//!
//! 1. [`signals_from`] maps telemetry to six normalized `0..=100` signals ([`SignalVector`]).
//! 2. A transparent weight table scores six policies and normalizes them to a distribution that
//!    sums to exactly 100 (largest-remainder rounding) — see the `score` module.
//! 3. A hysteresis state machine ([`LayaEngine`]) stops borderline inputs from flapping the policy.
//! 4. [`LayaEngine::system2`] lets IDS detections escalate the decision.
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

#[cfg(test)]
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
    fn test_low_detection_leaves_system1() {
        let mut e = LayaEngine::new();
        let s1 = base();
        let d = e.system2(s1, &[det(Severity::Low, PolicyMode::SurgicalCapture)]);
        assert_eq!(d, s1);
    }
}
