//! Weighted scoring model: `SignalVector` -> calibrated distribution over six policies.
//!
//! ```text
//! raw_p   = max(0, BIAS_p * 100 + sum_s WEIGHTS[p][s] * signal_s)       (1/100 "points")
//! mass_p  = raw_p^2 + FLOOR                                             (sharpen, never exactly 0)
//! pct_p   = mass_p / sum(mass) * 100, rounded with the largest-remainder method => sums to 100
//! ```
//!
//! Everything is integer math; there is no float and no allocation.
//!
//! Weight design: the scale of each weight encodes the retired ladder's priority
//! (`jam 300 > proximity/subghz 130 > ghost 105 > deauth 95 > bt 80`), so when several signals fire
//! at once the same policy wins as before, while the distribution now shows the runner-ups.

use crate::signals::{SignalKind, SignalVector, N_SIGNALS};
use ferrum_proto::{DualNrfPolicy, PolicyMode};

/// Number of policies System-1 scores (`ForensicLockdown` etc. are System-2 only).
pub const N_POLICIES: usize = 6;

/// Policy order of the weight table rows.
pub(crate) const POLICIES: [PolicyMode; N_POLICIES] = [
    PolicyMode::WideRecon,
    PolicyMode::AnomalyTriage,
    PolicyMode::SurgicalCapture,
    PolicyMode::FloodJamSurvival,
    PolicyMode::TriangulateLock,
    PolicyMode::SentinelCorrelate,
];

/// Quiet-baseline prior (in points) per policy: only `WideRecon` wins when nothing is happening.
const BIAS: [i16; N_POLICIES] = [60, 0, 0, 0, 0, 0];

/// `WEIGHTS[policy][signal]`, signal order = `[jam, proximity, ghost_esb, deauth_eapol, bt_ble, subghz]`.
/// A signal at 100 adds `weight` points to that policy.
pub(crate) const WEIGHTS: [[i16; N_SIGNALS]; N_POLICIES] = [
    [-60, -60, -60, -60, -60, -60], // WideRecon: any activity argues against a nominal sweep
    [0, 0, 0, 0, 80, 0],            // AnomalyTriage
    [0, 0, 0, 95, 0, 0],            // SurgicalCapture
    [300, 0, 0, 0, 0, 0],           // FloodJamSurvival
    [0, 10, 105, 0, 0, 0],          // TriangulateLock
    [0, 130, 0, 0, 0, 130],         // SentinelCorrelate
];

/// Uncertainty floor added to each squared score so no policy is ever reported as exactly 0%/100%.
const MASS_FLOOR: u64 = 80_000;

/// Per-policy actuation profile: (WROOM dual-nRF mode, cooperative band split, S3 camera+mic).
const fn profile(p: PolicyMode) -> Option<(DualNrfPolicy, bool, bool)> {
    match p {
        PolicyMode::WideRecon => Some((DualNrfPolicy::SplitSpectrumWaterfall, false, false)),
        PolicyMode::AnomalyTriage => Some((DualNrfPolicy::Simultaneous3ChBle, true, false)),
        PolicyMode::SurgicalCapture => Some((DualNrfPolicy::Simultaneous3ChBle, true, false)),
        PolicyMode::FloodJamSurvival => Some((DualNrfPolicy::Layer1JamTriage, true, false)),
        PolicyMode::TriangulateLock => Some((DualNrfPolicy::HunterKillerEsb, true, false)),
        PolicyMode::SentinelCorrelate => Some((DualNrfPolicy::Simultaneous3ChBle, true, true)),
        _ => None,
    }
}

/// Machine-readable "why": the three signals that drove the selected policy, each with its share
/// (percent, `0..=100`) of the policy's total absolute weighted contribution.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RationaleParts {
    pub top_signals: [(SignalKind, u8); 3],
}

/// Typed System-1/System-2 decision. Presentation concerns (latency, prose) live in the caller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TypedDecision {
    pub selected_policy: PolicyMode,
    pub selected_nrf_policy: DualNrfPolicy,
    pub confidence_pct: u8,
    pub cooperative_band_split: bool,
    pub trigger_s3_camera_mic: bool,
    pub rationale: RationaleParts,
    /// All six scored policies; percentages sum to exactly 100. `[0]` is always the selected policy
    /// (== argmax unless hysteresis is holding an incumbent); the rest are sorted descending.
    pub distribution: [(PolicyMode, u8); 6],
}

/// Raw scoring result before hysteresis.
pub(crate) struct Ranked {
    /// Distribution sorted descending by percentage (ties: higher raw score, then table order).
    pub dist: [(PolicyMode, u8); N_POLICIES],
}

pub(crate) fn raw_scores(s: &SignalVector) -> [i32; N_POLICIES] {
    let sig = s.as_array();
    let mut out = [0i32; N_POLICIES];
    let mut p = 0;
    while p < N_POLICIES {
        let mut acc = BIAS[p] as i32 * 100;
        let mut k = 0;
        while k < N_SIGNALS {
            acc += WEIGHTS[p][k] as i32 * sig[k].min(100) as i32;
            k += 1;
        }
        out[p] = acc.max(0);
        p += 1;
    }
    out
}

/// Largest-remainder normalization of `mass` to integers summing to exactly 100.
fn normalize(mass: &[u64; N_POLICIES]) -> [u8; N_POLICIES] {
    let total: u64 = mass.iter().sum(); // > 0 thanks to MASS_FLOOR
    let mut pct = [0u8; N_POLICIES];
    let mut rem = [0u64; N_POLICIES];
    let mut assigned = 0u32;
    for i in 0..N_POLICIES {
        let num = mass[i] * 100;
        pct[i] = (num / total) as u8;
        rem[i] = num % total;
        assigned += pct[i] as u32;
    }
    let mut left = 100 - assigned;
    let mut bumped = [false; N_POLICIES];
    while left > 0 {
        let mut best = usize::MAX;
        for i in 0..N_POLICIES {
            if !bumped[i] && (best == usize::MAX || rem[i] > rem[best]) {
                best = i;
            }
        }
        pct[best] += 1;
        bumped[best] = true;
        left -= 1;
    }
    pct
}

pub(crate) fn rank(s: &SignalVector) -> Ranked {
    let raw = raw_scores(s);
    let mut mass = [0u64; N_POLICIES];
    for i in 0..N_POLICIES {
        mass[i] = raw[i] as u64 * raw[i] as u64 + MASS_FLOOR;
    }
    let pct = normalize(&mass);

    // Insertion sort of indices: pct desc, raw desc, index asc.
    let mut idx = [0usize, 1, 2, 3, 4, 5];
    for i in 1..N_POLICIES {
        let mut j = i;
        while j > 0 {
            let (a, b) = (idx[j - 1], idx[j]);
            let a_first = (pct[a], raw[a], usize::MAX - a) >= (pct[b], raw[b], usize::MAX - b);
            if a_first {
                break;
            }
            idx.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut dist = [(POLICIES[0], 0u8); N_POLICIES];
    for (slot, &i) in dist.iter_mut().zip(idx.iter()) {
        *slot = (POLICIES[i], pct[i]);
    }
    Ranked { dist }
}

fn policy_index(p: PolicyMode) -> usize {
    POLICIES.iter().position(|&q| q == p).unwrap_or(0)
}

/// Top-3 signals by absolute weighted contribution to `selected`, as percent shares.
fn top_signals(selected: PolicyMode, s: &SignalVector) -> [(SignalKind, u8); 3] {
    let row = &WEIGHTS[policy_index(selected)];
    let sig = s.as_array();
    let mut contrib = [0u32; N_SIGNALS];
    let mut total = 0u32;
    for k in 0..N_SIGNALS {
        contrib[k] = (row[k] as i32 * sig[k].min(100) as i32).unsigned_abs();
        total += contrib[k];
    }
    let mut order = [0usize, 1, 2, 3, 4, 5];
    for i in 1..N_SIGNALS {
        let mut j = i;
        while j > 0 && contrib[order[j - 1]] < contrib[order[j]] {
            order.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut out = [(SignalKind::JamRatio, 0u8); 3];
    for (slot, &k) in out.iter_mut().zip(order.iter()) {
        let share = (contrib[k] * 100).checked_div(total).unwrap_or(0);
        *slot = (SignalKind::ALL[k], share as u8);
    }
    out
}

/// Builds the typed decision for `selected` (which may be a held incumbent, not the argmax).
pub(crate) fn decide(s: &SignalVector, selected: PolicyMode, ranked: &Ranked) -> TypedDecision {
    let (nrf, coop, cam) =
        profile(selected).unwrap_or((DualNrfPolicy::SplitSpectrumWaterfall, false, false));
    let mut distribution = ranked.dist;
    let pos = distribution
        .iter()
        .position(|(p, _)| *p == selected)
        .unwrap_or(0);
    // Move the selected policy to the front, preserving the order of the others.
    let chosen = distribution[pos];
    let mut i = pos;
    while i > 0 {
        distribution[i] = distribution[i - 1];
        i -= 1;
    }
    distribution[0] = chosen;

    TypedDecision {
        selected_policy: selected,
        selected_nrf_policy: nrf,
        confidence_pct: chosen.1,
        cooperative_band_split: coop,
        trigger_s3_camera_mic: cam,
        rationale: RationaleParts {
            top_signals: top_signals(selected, s),
        },
        distribution,
    }
}

/// Re-applies the actuation profile of `p` onto `d` (used by System-2 adoption).
#[cfg(feature = "ids")]
pub(crate) fn apply_profile(d: &mut TypedDecision, p: PolicyMode) {
    if let Some((nrf, coop, cam)) = profile(p) {
        d.selected_nrf_policy = nrf;
        d.cooperative_band_split = coop;
        d.trigger_s3_camera_mic = cam;
    }
}

#[cfg(test)]
mod tests {
    use crate::{LayaEngine, SignalVector};
    use ferrum_proto::PolicyMode;

    fn sv(jam: u8, prox: u8, ghost: u8, deauth: u8, bt: u8, sub: u8) -> SignalVector {
        SignalVector {
            jam_ratio: jam,
            proximity: prox,
            ghost_esb: ghost,
            deauth_eapol: deauth,
            bt_ble: bt,
            subghz: sub,
        }
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let v = (self.0 >> 33) as u32;
            // bias towards the interesting extremes: 0, 100 and the middle
            match v % 4 {
                0 => 0,
                1 => 100,
                _ => (v / 4 % 101) as u8,
            }
        }
    }

    #[test]
    fn test_distribution_sums_to_100() {
        for jam in [0u8, 5, 50, 100] {
            for prox in [0u8, 12, 100] {
                for ghost in [0u8, 100] {
                    for deauth in [0u8, 10, 100] {
                        for bt in [0u8, 15, 45, 100] {
                            for sub in [0u8, 100] {
                                let d = LayaEngine::new()
                                    .system1(&sv(jam, prox, ghost, deauth, bt, sub));
                                let sum: u32 = d.distribution.iter().map(|(_, p)| *p as u32).sum();
                                assert_eq!(sum, 100);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_argmax_matches_selected() {
        let mut r = Lcg(0xFE22);
        for _ in 0..2000 {
            let s = sv(r.next(), r.next(), r.next(), r.next(), r.next(), r.next());
            let d = LayaEngine::new().system1(&s);
            assert_eq!(d.distribution[0].0, d.selected_policy);
            assert_eq!(d.distribution[0].1, d.confidence_pct);
            assert!(d.distribution.windows(2).all(|w| w[0].1 >= w[1].1));
        }
    }

    #[test]
    fn property_stateful_engine_invariants() {
        // One long-lived engine: hysteresis may hold an incumbent, but the report must stay
        // self-consistent (sum == 100, selected listed first, rest sorted, 6 distinct policies).
        let mut r = Lcg(7);
        let mut e = LayaEngine::new();
        for _ in 0..5000 {
            let d = e.system1(&sv(
                r.next(),
                r.next(),
                r.next(),
                r.next(),
                r.next(),
                r.next(),
            ));
            let sum: u32 = d.distribution.iter().map(|(_, p)| *p as u32).sum();
            assert_eq!(sum, 100);
            assert_eq!(d.distribution[0], (d.selected_policy, d.confidence_pct));
            assert!(d.distribution[1..].windows(2).all(|w| w[0].1 >= w[1].1));
            for i in 0..6 {
                for j in (i + 1)..6 {
                    assert_ne!(d.distribution[i].0, d.distribution[j].0);
                }
            }
            let top: u32 = d.rationale.top_signals.iter().map(|(_, p)| *p as u32).sum();
            assert!(top <= 100);
        }
    }

    #[test]
    fn test_jammer_selects_floodjamsurvival() {
        let d = LayaEngine::new().system1(&sv(100, 0, 0, 0, 0, 0));
        assert_eq!(d.selected_policy, PolicyMode::FloodJamSurvival);
        assert!(!d.trigger_s3_camera_mic);
    }

    #[test]
    fn test_ghost_esb_selects_triangulatelock() {
        let d = LayaEngine::new().system1(&sv(0, 0, 100, 0, 0, 0));
        assert_eq!(d.selected_policy, PolicyMode::TriangulateLock);
    }

    #[test]
    fn test_proximity_selects_sentinelcorrelate() {
        let d = LayaEngine::new().system1(&sv(0, 100, 0, 0, 0, 0));
        assert_eq!(d.selected_policy, PolicyMode::SentinelCorrelate);
        assert!(d.trigger_s3_camera_mic);
    }

    #[test]
    fn test_baseline_selects_widerecon() {
        let d = LayaEngine::new().system1(&SignalVector::default());
        assert_eq!(d.selected_policy, PolicyMode::WideRecon);
        assert!(!d.cooperative_band_split);
    }

    #[test]
    fn test_old_ladder_priority_preserved_when_all_signals_max() {
        // jam > proximity/subghz > ghost > deauth > bt (the order of the retired if/else ladder)
        let p = |s| LayaEngine::new().system1(&s).selected_policy;
        assert_eq!(
            p(sv(100, 100, 100, 100, 100, 100)),
            PolicyMode::FloodJamSurvival
        );
        assert_eq!(
            p(sv(0, 100, 100, 100, 100, 100)),
            PolicyMode::SentinelCorrelate
        );
        assert_eq!(p(sv(0, 0, 100, 100, 100, 0)), PolicyMode::TriangulateLock);
        assert_eq!(p(sv(0, 0, 0, 100, 100, 0)), PolicyMode::SurgicalCapture);
        assert_eq!(p(sv(0, 0, 0, 0, 100, 0)), PolicyMode::AnomalyTriage);
    }
}
