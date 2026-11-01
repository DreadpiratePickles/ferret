//! Scenario timelines: when adversaries appear and disappear.
//!
//! Adversary ids inside a scenario are implicit: the n-th [`ScenarioEvent::Spawn`] (in timeline
//! order) gets `AdversaryId(n)`, so a later [`ScenarioEvent::Clear`] can refer to it.
//! `SimController` hands out ids for [`inject`](crate::SimController::inject)ed adversaries
//! after the scenario's, so they never collide.
use crate::adversary::{Adversary, AdversaryId};

/// One timeline entry's action.
#[derive(Clone, Debug, PartialEq)]
pub enum ScenarioEvent {
    /// Bring an adversary into the world (it gets the next scenario `AdversaryId`).
    Spawn(Adversary),
    /// Remove a previously spawned adversary.
    Clear(AdversaryId),
}

/// A named, time-ordered list of `(t_ms, event)` pairs.
#[derive(Clone, Debug, PartialEq)]
pub struct Scenario {
    pub name: &'static str,
    timeline: Vec<(u64, ScenarioEvent)>,
}

impl Scenario {
    /// Build a scenario; entries are stably sorted by time.
    pub fn new(name: &'static str, mut timeline: Vec<(u64, ScenarioEvent)>) -> Self {
        timeline.sort_by_key(|(t, _)| *t);
        Self { name, timeline }
    }

    pub fn timeline(&self) -> &[(u64, ScenarioEvent)] {
        &self.timeline
    }

    /// Number of `Spawn` events (= number of scenario-assigned ids).
    pub fn spawn_count(&self) -> u32 {
        self.timeline
            .iter()
            .filter(|(_, e)| matches!(e, ScenarioEvent::Spawn(_)))
            .count() as u32
    }

    /// Time (ms) of the last event.
    pub fn last_event_ms(&self) -> u64 {
        self.timeline.last().map_or(0, |(t, _)| *t)
    }
}

/// Anchors: WROOM `(0,0)`, C5 `(6,0)`, S3 `(3,5.2)`.
fn quiet() -> Scenario {
    Scenario::new("quiet", Vec::new())
}

/// The flagship walk through all four pillars (at 10 Hz: ticks = ms / 100).
///
/// | t (s)  | phase                                                           |
/// |--------|-----------------------------------------------------------------|
/// | 0-5    | baseline, quiet                                                 |
/// | 5-10   | MouseJack ESB + ghost-band carrier implant (nRF ch 98)         |
/// | 10-17  | 5 GHz evil twin (ch 36), deauth burst for the first 4 s        |
/// | 17-22  | Layer-1 wideband jammer (> 40 nRF channels RPD-hot)             |
/// | 22-30+ | close-range BT skimmer + sub-GHz 433 MHz replay + BLE MAC rotation |
fn red_team_incursion() -> Scenario {
    use ScenarioEvent::{Clear, Spawn};
    Scenario::new(
        "red-team-incursion",
        vec![
            // id 0: MouseJack + ghost-band implant.
            (
                5_000,
                Spawn(Adversary::mousejack((1.0, 1.5), 96, 4, Some(98))),
            ),
            (10_000, Clear(AdversaryId(0))),
            // id 1: evil twin + deauth burst on 5 GHz.
            (
                10_000,
                Spawn(Adversary::evil_twin_deauth((5.0, 1.5), 36, 4_000)),
            ),
            (17_000, Clear(AdversaryId(1))),
            // id 2: Layer-1 jammer.
            (17_000, Spawn(Adversary::jammer((1.5, 1.0), 45))),
            (22_000, Clear(AdversaryId(2))),
            // ids 3-5: close-range intruder + sub-GHz replay + BLE rotation.
            (22_000, Spawn(Adversary::bt_skimmer((3.0, 4.6)))),
            (22_000, Spawn(Adversary::subghz_replay(433, 2_000, 600))),
            (
                22_000,
                Spawn(Adversary::ble_rotating_implant((2.4, 4.0), 3_000)),
            ),
        ],
    )
}

/// Look up a scenario by name (`"quiet"`, `"red-team-incursion"`).
pub fn scenario_by_name(name: &str) -> Option<Scenario> {
    match name {
        "quiet" => Some(quiet()),
        "red-team-incursion" => Some(red_team_incursion()),
        _ => None,
    }
}

/// Names accepted by [`scenario_by_name`].
pub const SCENARIO_NAMES: [&str; 2] = ["quiet", "red-team-incursion"];
