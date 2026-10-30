//! [`SimController`]: owns the [`RfWorld`], plays a [`Scenario`] and drives adversaries.
use crate::adversary::{Adversary, AdversaryId};
use crate::scenario::{scenario_by_name, Scenario, ScenarioEvent};
use crate::world::RfWorld;

/// Advances the simulated world: scenario events fire, active adversaries update the world,
/// then the world steps. Deterministic for a given `(seed, scenario, dt sequence)`.
pub struct SimController {
    /// The simulated RF environment (public so orchestrators can build sim PHYs / read it).
    pub world: RfWorld,
    scenario: Scenario,
    cursor: usize,
    active: Vec<(AdversaryId, Adversary)>,
    next_id: u32,
    spawned: u32,
}

impl SimController {
    /// Controller over `RfWorld::new(seed)` playing `scenario`. An unknown scenario name falls
    /// back to `"quiet"` (use [`scenario_by_name`] first to detect typos).
    pub fn new(seed: u64, scenario: &str) -> Self {
        let scenario = scenario_by_name(scenario)
            .or_else(|| scenario_by_name("quiet"))
            .expect("the quiet scenario always exists");
        Self {
            world: RfWorld::new(seed),
            next_id: scenario.spawn_count(),
            scenario,
            cursor: 0,
            active: Vec::new(),
            spawned: 0,
        }
    }

    /// Advance `dt_ms`: fire timeline events due at the current time, let every active
    /// adversary apply itself, then step the world.
    pub fn advance(&mut self, dt_ms: u64) {
        let now = self.world.time_ms();
        while let Some((t, ev)) = self.scenario.timeline().get(self.cursor) {
            if *t > now {
                break;
            }
            let ev = ev.clone();
            self.cursor += 1;
            match ev {
                ScenarioEvent::Spawn(a) => {
                    let id = AdversaryId(self.spawned);
                    self.spawned += 1;
                    self.active.push((id, a));
                }
                ScenarioEvent::Clear(id) => self.clear(id),
            }
        }
        for (_, a) in &mut self.active {
            a.apply(&mut self.world, now);
        }
        self.world.step(dt_ms);
    }

    /// Add an adversary right now; returns its handle.
    pub fn inject(&mut self, a: Adversary) -> AdversaryId {
        let id = AdversaryId(self.next_id);
        self.next_id += 1;
        self.active.push((id, a));
        id
    }

    /// Remove an adversary (and its emitters). Unknown / already-cleared ids are ignored.
    pub fn clear(&mut self, id: AdversaryId) {
        if let Some(i) = self.active.iter().position(|(aid, _)| *aid == id) {
            let (_, mut a) = self.active.remove(i);
            a.despawn(&mut self.world);
        }
    }

    pub fn world(&self) -> &RfWorld {
        &self.world
    }

    pub fn world_mut(&mut self) -> &mut RfWorld {
        &mut self.world
    }

    pub fn scenario(&self) -> &Scenario {
        &self.scenario
    }

    /// Currently active adversaries (scenario-spawned and injected), oldest first.
    pub fn active(&self) -> &[(AdversaryId, Adversary)] {
        &self.active
    }

    /// Frequency (MHz) of an in-progress sub-GHz burst from any active adversary.
    pub fn subghz_burst_mhz(&self) -> Option<u16> {
        self.active.iter().find_map(|(_, a)| a.subghz_burst_mhz())
    }
}
