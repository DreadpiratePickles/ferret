//! Hysteresis state machine + the [`LayaEngine`] façade.
//!
//! Policy flapping is operationally expensive (every switch re-tasks three radios), so the engine
//! keeps an *incumbent* policy and only replaces it when a challenger is clearly better:
//!
//! * **Margin `M` = 20 percentage points**: the challenger's confidence exceeds the incumbent's by
//!   at least `M` in a single tick (decisive evidence switches immediately), or
//! * **Dwell `K` = 3 ticks**: the *same* challenger has led (by any amount) for `K` consecutive
//!   ticks. Any tick where the incumbent leads again, or a different challenger leads, resets it.
//!
//! The first tick has no incumbent and adopts the argmax directly.

use crate::score::{decide, rank, TypedDecision};
use crate::signals::SignalVector;
#[cfg(feature = "ids")]
use ferrum_ids::{Detection, Severity};
use ferrum_proto::PolicyMode;

/// Lead (percentage points) at which a challenger displaces the incumbent immediately.
pub const SWITCH_MARGIN_PCT: u8 = 20;
/// Consecutive ticks a challenger must lead to displace the incumbent without the margin.
pub const SWITCH_DWELL_TICKS: u8 = 3;

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct Hysteresis {
    incumbent: Option<PolicyMode>,
    challenger: Option<PolicyMode>,
    streak: u8,
}

impl Hysteresis {
    /// Consumes a descending-sorted distribution and returns the policy to act on this tick.
    pub(crate) fn step(&mut self, dist: &[(PolicyMode, u8); 6]) -> PolicyMode {
        let (leader, leader_pct) = dist[0];
        let Some(inc) = self.incumbent else {
            self.incumbent = Some(leader);
            return leader;
        };
        if leader == inc {
            self.challenger = None;
            self.streak = 0;
            return inc;
        }
        let inc_pct = dist.iter().find(|(p, _)| *p == inc).map_or(0, |(_, c)| *c);
        let lead = leader_pct.saturating_sub(inc_pct);
        if self.challenger == Some(leader) {
            self.streak = self.streak.saturating_add(1);
        } else {
            self.challenger = Some(leader);
            self.streak = 1;
        }
        if lead >= SWITCH_MARGIN_PCT || self.streak >= SWITCH_DWELL_TICKS {
            self.incumbent = Some(leader);
            self.challenger = None;
            self.streak = 0;
            return leader;
        }
        inc
    }
}

/// Explainable scored decision engine (System-1 reactive + System-2 escalation).
#[derive(Clone, Debug, Default)]
pub struct LayaEngine {
    hyst: Hysteresis,
}

impl LayaEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// System-1: score the signals, apply hysteresis, return the typed decision.
    pub fn system1(&mut self, s: &SignalVector) -> TypedDecision {
        let ranked = rank(s);
        let selected = self.hyst.step(&ranked.dist);
        decide(s, selected, &ranked)
    }

    /// System-2: IDS detections escalate the System-1 decision.
    ///
    /// * any `Critical` => `ForensicLockdown`, cam/mic on, confidence 99;
    /// * else the highest-severity detection at `High` or above adopts its `recommended_policy`
    ///   (and that policy's actuation profile when it is one of the six System-1 policies), with
    ///   `confidence_pct` reset to the adopted policy's share of the System-1 distribution;
    /// * else `d` is returned unchanged.
    ///
    /// `distribution` and `rationale` keep describing the System-1 evidence that was overridden.
    #[cfg(feature = "ids")]
    pub fn system2(&mut self, d: TypedDecision, detections: &[Detection]) -> TypedDecision {
        let mut d = d;
        if detections.iter().any(|x| x.severity == Severity::Critical) {
            d.selected_policy = PolicyMode::ForensicLockdown;
            d.trigger_s3_camera_mic = true;
            d.confidence_pct = 99;
        } else if let Some(top) = detections.iter().max_by_key(|x| x.severity.rank()) {
            if top.severity.rank() >= Severity::High.rank() {
                d.selected_policy = top.recommended_policy;
                crate::score::apply_profile(&mut d, top.recommended_policy);
                // Report the adopted policy's own share of the System-1 distribution, not the
                // superseded incumbent's figure. All six policies are present in `distribution`,
                // so this normally resolves; if it somehow does not, leave the prior value.
                if let Some((_, share)) = d
                    .distribution
                    .iter()
                    .find(|(p, _)| *p == top.recommended_policy)
                {
                    d.confidence_pct = *share;
                }
            }
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use crate::{LayaEngine, SignalVector};

    fn bt(v: u8) -> SignalVector {
        SignalVector {
            bt_ble: v,
            ..SignalVector::default()
        }
    }

    #[test]
    fn test_no_flap_on_borderline() {
        // 45 / 41 straddle the WideRecon <-> AnomalyTriage score crossover.
        let mut e = LayaEngine::new();
        let mut last = None;
        let mut changes = 0;
        for i in 0..10 {
            let d = e.system1(&bt(if i % 2 == 0 { 45 } else { 41 }));
            if let Some(prev) = last {
                if prev != d.selected_policy {
                    changes += 1;
                }
            }
            last = Some(d.selected_policy);
        }
        assert!(changes <= 1, "flapped {changes} times");
    }

    #[test]
    fn test_sustained_challenger_takes_over_after_k_ticks() {
        let mut e = LayaEngine::new();
        let first = e.system1(&bt(41)).selected_policy; // WideRecon side
        let mut switched_at = None;
        for i in 1..=6 {
            if e.system1(&bt(45)).selected_policy != first {
                switched_at = Some(i);
                break;
            }
        }
        assert_eq!(switched_at, Some(3));
    }

    #[test]
    fn test_decisive_signal_switches_immediately() {
        let mut e = LayaEngine::new();
        let a = e.system1(&SignalVector::default()).selected_policy;
        let b = e.system1(&bt(100)).selected_policy;
        assert_ne!(a, b);
    }
}
