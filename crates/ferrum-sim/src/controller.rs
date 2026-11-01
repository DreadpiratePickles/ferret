//! [`SimController`]: owns the [`RfWorld`], plays a [`Scenario`] and drives adversaries.
//!
//! The scenario/adversary bookkeeping lives in [`ScenarioDriver`], which operates on a
//! *borrowed* world so an orchestrator can own the world behind a
//! [`SharedWorld`](crate::phy_impl::SharedWorld) (shared with the node PHYs) and still reuse the
//! exact same timeline + adversary logic. [`SimController`] is the owned-world convenience wrapper
//! used by the golden/reproducibility tests.
use crate::adversary::{Adversary, AdversaryId};
use crate::scenario::{scenario_by_name, Scenario, ScenarioEvent};
use crate::world::RfWorld;

/// Scenario timeline + active-adversary bookkeeping, decoupled from world ownership.
///
/// Every method that perturbs the world takes it by `&mut` so the caller controls the borrow,
/// which matters when the world lives behind a `RefCell` shared with the node PHYs: borrow to
/// [`advance`](Self::advance), drop the borrow, then tick the agents.
pub struct ScenarioDriver {
    scenario: Scenario,
    cursor: usize,
    active: Vec<(AdversaryId, Adversary)>,
    next_id: u32,
    spawned: u32,
}

impl ScenarioDriver {
    /// Driver for `scenario`. An unknown scenario name falls back to `"quiet"` (use
    /// [`scenario_by_name`] first to detect typos).
    pub fn new(scenario: &str) -> Self {
        let scenario = scenario_by_name(scenario)
            .or_else(|| scenario_by_name("quiet"))
            .expect("the quiet scenario always exists");
        Self {
            next_id: scenario.spawn_count(),
            scenario,
            cursor: 0,
            active: Vec::new(),
            spawned: 0,
        }
    }

    /// Advance `dt_ms` against `world`: fire timeline events due at the current time, let every
    /// active adversary apply itself, then step the world.
    pub fn advance(&mut self, world: &mut RfWorld, dt_ms: u64) {
        let now = world.time_ms();
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
                ScenarioEvent::Clear(id) => self.clear(world, id),
            }
        }
        for (_, a) in &mut self.active {
            a.apply(world, now);
        }
        world.step(dt_ms);
    }

    /// Add an adversary right now; returns its handle. (Emitters appear on the next `advance`.)
    pub fn inject(&mut self, a: Adversary) -> AdversaryId {
        let id = AdversaryId(self.next_id);
        self.next_id += 1;
        self.active.push((id, a));
        id
    }

    /// Remove an adversary (and its emitters) from `world`. Unknown / cleared ids are ignored.
    pub fn clear(&mut self, world: &mut RfWorld, id: AdversaryId) {
        if let Some(i) = self.active.iter().position(|(aid, _)| *aid == id) {
            let (_, mut a) = self.active.remove(i);
            a.despawn(world);
        }
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

/// Advances the simulated world: scenario events fire, active adversaries update the world,
/// then the world steps. Deterministic for a given `(seed, scenario, dt sequence)`.
///
/// Owns its [`RfWorld`] by value; an orchestrator that must share the world with the node PHYs
/// drives a [`ScenarioDriver`] against its own `Rc<RefCell<RfWorld>>` instead.
pub struct SimController {
    /// The simulated RF environment (public so orchestrators can build sim PHYs / read it).
    pub world: RfWorld,
    driver: ScenarioDriver,
}

impl SimController {
    /// Controller over `RfWorld::new(seed)` playing `scenario`. An unknown scenario name falls
    /// back to `"quiet"` (use [`scenario_by_name`] first to detect typos).
    pub fn new(seed: u64, scenario: &str) -> Self {
        Self {
            world: RfWorld::new(seed),
            driver: ScenarioDriver::new(scenario),
        }
    }

    /// Advance `dt_ms`: fire timeline events due at the current time, let every active
    /// adversary apply itself, then step the world.
    pub fn advance(&mut self, dt_ms: u64) {
        self.driver.advance(&mut self.world, dt_ms);
    }

    /// Add an adversary right now; returns its handle.
    pub fn inject(&mut self, a: Adversary) -> AdversaryId {
        self.driver.inject(a)
    }

    /// Remove an adversary (and its emitters). Unknown / already-cleared ids are ignored.
    pub fn clear(&mut self, id: AdversaryId) {
        self.driver.clear(&mut self.world, id);
    }

    pub fn world(&self) -> &RfWorld {
        &self.world
    }

    pub fn world_mut(&mut self) -> &mut RfWorld {
        &mut self.world
    }

    pub fn scenario(&self) -> &Scenario {
        self.driver.scenario()
    }

    /// Currently active adversaries (scenario-spawned and injected), oldest first.
    pub fn active(&self) -> &[(AdversaryId, Adversary)] {
        self.driver.active()
    }

    /// Frequency (MHz) of an in-progress sub-GHz burst from any active adversary.
    pub fn subghz_burst_mhz(&self) -> Option<u16> {
        self.driver.subghz_burst_mhz()
    }
}
