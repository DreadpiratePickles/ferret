# Ferret "Living Swarm" (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn Ferret's scripted simulation into a continuously-running, interactive, WebSocket-streamed live swarm demo whose node logic sits behind a hardware-abstraction layer, so the showcase and future esp-hal firmware are one effort.

**Architecture:** Shared `no_std` cores (`ferrum-proto`, new `ferrum-hal` traits, new `ferrum-laya` scored decision engine, trait-driven node agents) are driven in the showcase by a new `std` simulator (`ferrum-sim`: seeded RF world + adversary models) and an async orchestrator/web server (`ferrum-brain`: tokio + axum) that streams `SwarmSnapshot`s to an upgraded single-page dashboard and accepts operator commands back. In Phase 2 the same traits get esp-hal implementations.

**Tech Stack:** Rust 2021; `no_std` cores with integer/fixed-point math; `std` crates use tokio, axum, serde/serde_json, rand_pcg, anyhow, tracing; vanilla JS/CSS dashboard served embedded.

**Spec:** `docs/superpowers/specs/2026-10-29-ferret-living-swarm-design.md`

## Global Constraints

- Rust edition `2021`; pin a stable toolchain in `rust-toolchain.toml`.
- `no_std` cores (`ferrum-proto`, `ferrum-hal`, `ferrum-laya`, `ferrum-wroom-nrf`, `ferrum-c5-scout`, `ferrum-s3-sense`, `ferrum-ids`, `ferrum-deceive`, `ferrum-secure`, `ferrum-forensics`, `ferrum-triage`) must keep `#![no_std]` and add **no** dependency that blocks `xtensa-*`/`riscv32imac-*` cross-compilation. No `std`, no float-std, no `tokio`/`axum`/`serde` in these crates.
- Heavy dependencies (`tokio`, `axum`, `serde`, `serde_json`, `rand_pcg`, `anyhow`, `tracing`) land **only** in `ferrum-sim` and `ferrum-brain`.
- `ferrum-laya` uses **integer/fixed-point math only**; the confidence distribution it emits must sum to exactly `100` across reported policies.
- Per-tick orchestration code is **panic-free**: saturating arithmetic and clamps, no fallible allocation, no `unwrap()` on runtime values.
- `cargo test --workspace`, `cargo clippy --workspace` (warnings denied), and `cargo fmt --check` must all pass at the end of every task.
- Default tick rate `10 Hz`; demo must run from a single `cargo run -p ferrum-brain`.

## Review Focus

- **Node transport failure** — a HAL `Transport`/sensor call returning `Err` must mark that node `offline` and let the tick loop continue, never panic. (Pinned in Task 2/Task 3 via a mock PHY that returns `Err`.)
- **WebSocket client disconnect or lag** — a client dropping or lagging mid-stream must not stall or crash the broadcast to other clients. (Pinned in Task 10.)
- **Forged/replayed policy command** — a tampered or replayed sealed command must be rejected by `ferrum-secure` and surface as a snapshot event, not a panic. (Pinned in Task 9 integration test.)
- **Borderline alternating signals** — inputs hovering at a decision boundary must not flap the selected policy every tick (hysteresis). (Pinned in Task 1.)
- **Seed reproducibility** — the same `--seed` + scenario must produce a byte-identical snapshot timeline. (Pinned in Task 7 golden test.)

---

### Task 0: Toolchain + green baseline

**Files:**
- Create: `rust-toolchain.toml`, `justfile`, `.github/workflows/ci.yml`
- Modify: none (code unchanged)

**Interfaces:**
- Consumes: the existing 10-crate workspace as-is.
- Produces: a machine where `cargo test --workspace` runs; `just test`/`just lint`/`just run` targets.

- [ ] **Step 1: Install the Rust toolchain** — run `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`, then `source "$HOME/.cargo/env"`. Verify `rustc --version` and `cargo --version` print.
- [ ] **Step 2: Run the existing suite** — `cargo test --workspace`. Expected: builds and the existing 25 tests pass. If anything fails to compile on current stable, fix minimally and note it in the commit.
- [ ] **Step 3: Add `rust-toolchain.toml`** pinning `channel = "stable"` and components `rustfmt`, `clippy`.
- [ ] **Step 4: Add `justfile`** with `test: cargo test --workspace`, `lint: cargo clippy --workspace -- -D warnings && cargo fmt --check`, `run: cargo run -p ferrum-brain`, `demo: cargo run -p ferrum-brain -- --scenario red-team-incursion`.
- [ ] **Step 5: Add `.github/workflows/ci.yml`** running fmt-check, clippy (`-D warnings`), and `cargo test --workspace` on stable.
- [ ] **Step 6: Make lint clean** — run `just lint`; fix formatting/clippy findings in existing code.
- [ ] **Step 7: Commit** — `git add -A && git commit -m "chore: pin toolchain, add justfile + CI, green baseline"`.

---

### Task 1: Extract `ferrum-laya` — explainable scored decision engine

**Files:**
- Create: `crates/ferrum-laya/Cargo.toml`, `crates/ferrum-laya/src/lib.rs`, `crates/ferrum-laya/src/signals.rs`, `crates/ferrum-laya/src/score.rs`, `crates/ferrum-laya/src/hysteresis.rs`
- Modify: `Cargo.toml` (add member), `crates/ferrum-brain/src/main.rs` (use the crate; delete the moved fns)

**Interfaces:**
- Consumes: `ferrum_proto::{NodeTelemetry, PolicyMode, DualNrfPolicy}`, `ferrum_ids::{Detection, Severity}`.
- Produces (public API consumed by Tasks 9+):
  - `struct SignalVector { pub jam_ratio: u8, pub proximity: u8, pub ghost_esb: u8, pub deauth_eapol: u8, pub bt_ble: u8, pub subghz: u8 }` (each `0..=100`).
  - `fn signals_from(wroom: &NodeTelemetry, c5: &NodeTelemetry, s3: &NodeTelemetry, rpd_jammed_channels: u8, subghz_burst_mhz: Option<u16>) -> SignalVector`
  - `struct TypedDecision { pub selected_policy: PolicyMode, pub selected_nrf_policy: DualNrfPolicy, pub confidence_pct: u8, pub cooperative_band_split: bool, pub trigger_s3_camera_mic: bool, pub rationale: RationaleParts, pub distribution: [(PolicyMode, u8); 6] }`
  - `struct RationaleParts { pub top_signals: [(SignalKind, u8); 3] }` with `enum SignalKind`
  - `struct LayaEngine { /* holds hysteresis state */ }` with `fn new() -> Self`, `fn system1(&mut self, s: &SignalVector) -> TypedDecision`, `fn system2(&mut self, d: TypedDecision, detections: &[Detection]) -> TypedDecision`.
- Note: `decision_latency_ms` is presentation-only and moves to `ferrum-brain`/snapshot, not the engine.

- [ ] **Step 1: Write failing tests** in `crates/ferrum-laya/src/score.rs` tests module:
  - `test_distribution_sums_to_100`: for a sweep of `SignalVector`s, `system1(..).distribution.iter().map(|(_,p)| *p as u32).sum::<u32>() == 100`.
  - `test_argmax_matches_selected`: `distribution[0].0 == selected_policy` and `distribution[0].1 == confidence_pct`.
  - `test_jammer_selects_floodjamsurvival`: high `jam_ratio` → `PolicyMode::FloodJamSurvival`.
  - `test_ghost_esb_selects_triangulatelock`; `test_proximity_selects_sentinelcorrelate` with `trigger_s3_camera_mic == true`; `test_baseline_selects_widerecon`.
- [ ] **Step 2: Write failing hysteresis test** in `hysteresis.rs`: `test_no_flap_on_borderline` — feed 10 ticks alternating just-above/just-below the WideRecon↔AnomalyTriage boundary through one `LayaEngine`; assert the selected policy changes at most once.
- [ ] **Step 3: Write failing System-2 tests**: `test_critical_detection_forces_lockdown` (a `Severity::Critical` detection → `PolicyMode::ForensicLockdown`, `trigger_s3_camera_mic == true`); `test_high_detection_adopts_recommended`; `test_low_detection_leaves_system1`.
- [ ] **Step 4: Run tests to verify they fail** — `cargo test -p ferrum-laya`. Expected: compile errors / FAIL (crate not implemented).
- [ ] **Step 5: Implement `signals_from`** in `signals.rs` — map telemetry fields to normalized `0..=100` signals using saturating integer math. Preserve the thresholds encoded in the current `main.rs` ladder (jam >40 ch, proximity > -42 dBm, ghost/esb > 0, deauth > 5 or eapol > 0, bt_classic > 0 or ble_adv_fps > 350, subghz present) as the high-activation points.
- [ ] **Step 6: Implement scoring** in `score.rs` — a weight table `[[i16; 6]; N_POLICIES]` over the six signals per `PolicyMode`; compute integer scores, clamp to non-negative, normalize to a distribution summing to 100 (largest-remainder method so rounding is exact), take top 6. Fill `RationaleParts.top_signals` from the highest weighted contributions. Set `cooperative_band_split`/`trigger_s3_camera_mic` from the selected policy (table-driven).
- [ ] **Step 7: Implement `LayaEngine` hysteresis** in `hysteresis.rs` — keep the incumbent policy and a dwell counter; a challenger replaces the incumbent only if it leads by a margin `M` or has led for `K` consecutive ticks (pick small constants; document them in a doc comment).
- [ ] **Step 8: Implement `system2`** in `lib.rs` — Critical → `ForensicLockdown` + cam/mic + confidence 99; else highest-severity ≥ High adopts its `recommended_policy`; else return input unchanged.
- [ ] **Step 9: Rewire `ferrum-brain`** — delete `LayaTypedDecision`, `evaluate_laya_system1_decision`, `evaluate_laya_system2_decision` from `main.rs`; call `ferrum_laya` instead; keep `main` output format working (compute `decision_latency_ms` locally for the narrative).
- [ ] **Step 10: Run `cargo test -p ferrum-laya` and `cargo run -p ferrum-brain`** — Expected: laya tests PASS; brain narrative still prints a sensible policy per tick.
- [ ] **Step 11: `just lint`** then **Commit** — `git add -A && git commit -m "feat(laya): extract explainable scored decision engine"`.

---

### Task 2: `ferrum-hal` traits + mock PHY test harness

**Files:**
- Create: `crates/ferrum-hal/Cargo.toml`, `crates/ferrum-hal/src/lib.rs`, `crates/ferrum-hal/src/mock.rs` (behind `#[cfg(any(test, feature = "mock"))]`)
- Modify: root `Cargo.toml` (add member)

**Interfaces:**
- Consumes: `ferrum_proto` types only.
- Produces (consumed by Tasks 3–6):
  - `trait SpectrumScanner { fn set_channel(&mut self, ch: u8); fn read_rpd(&mut self) -> bool; fn sample_rssi(&mut self) -> i8; }`
  - `trait PacketSniffer { type Frame; fn next_frame(&mut self) -> Option<Self::Frame>; }`
  - `trait Transport { type Error; fn send(&mut self, buf: &[u8]) -> Result<(), Self::Error>; fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>; }`
  - `trait Clock { fn now_ms(&self) -> u64; }`
  - `enum NodeStatus { Online(ferrum_proto::NodeTelemetry), Offline }` — the shared return type of every agent's `tick()` (Tasks 3–5).
  - `mock::{MockScanner, MockSniffer, MockTransport, MockClock}` — scripted scanners/frames and a `MockTransport` whose `send`/`recv` can be configured to return `Err` for the offline-node test.

- [ ] **Step 1: Write failing test** in `mock.rs`: `test_mock_transport_can_fail` — a `MockTransport` configured to fail returns `Err` from `send`; a healthy one returns `Ok`.
- [ ] **Step 2: Run to verify fail** — `cargo test -p ferrum-hal`. Expected: FAIL (crate not implemented).
- [ ] **Step 3: Implement the four traits** in `lib.rs` (`#![no_std]`, no deps beyond `ferrum-proto`).
- [ ] **Step 4: Implement the mocks** in `mock.rs` — `MockScanner` returns scripted `(rpd, rssi)` per channel; `MockSniffer` yields a scripted `Vec`-free fixed array of frames; `MockTransport { fail: bool }`; `MockClock { ms: u64 }`.
- [ ] **Step 5: Run to verify pass** — `cargo test -p ferrum-hal`. Expected: PASS.
- [ ] **Step 6: `just lint`** then **Commit** — `git commit -am "feat(hal): peripheral/transport traits + mock PHYs"`.

---

### Task 3: Migrate WROOM node to a trait-driven agent

**Files:**
- Modify: `crates/ferrum-wroom-nrf/Cargo.toml` (dep on `ferrum-hal`), `crates/ferrum-wroom-nrf/src/lib.rs`
- Test: `crates/ferrum-wroom-nrf/src/lib.rs` tests module

**Interfaces:**
- Consumes: `ferrum_hal::{SpectrumScanner, PacketSniffer, Transport, Clock}`, existing `ferrum_proto` telemetry/bitmap types, `build_ble_fingerprint`.
- Produces (consumed by Tasks 6, 9):
  - `struct WroomAgent<S, P, T, C>` with `fn new(scanner: S, sniffer: P, transport: T, clock: C) -> Self`
  - `fn tick(&mut self) -> ferrum_hal::NodeStatus` (defined in Task 2)
  - `fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd)`
  - Keep `build_ble_fingerprint` public and unchanged.

- [ ] **Step 1: Write failing tests** using `ferrum_hal::mock`:
  - `test_agent_builds_telemetry_from_scanner` — a `MockScanner` scripted with a ghost-band hit + ESB frames yields a `NodeStatus::Online(t)` with `t.ghost_band_hits > 0` and `t.esb_hid_frames > 0`.
  - `test_agent_offline_on_transport_error` — a failing `MockTransport` makes `tick()` return `NodeStatus::Offline` without panicking. *(Review Focus: node transport failure.)*
- [ ] **Step 2: Run to verify fail** — `cargo test -p ferrum-wroom-nrf`. Expected: FAIL.
- [ ] **Step 3: Refactor `WroomDualNrfNode` → `WroomAgent<S,P,T,C>`** — move the existing scan/telemetry-assembly logic to read from the injected `scanner`/`sniffer` instead of struct fields set externally; relay telemetry via `transport.send(...)` and map `Err` to `NodeStatus::Offline`. Preserve the 126-channel split-spectrum sweep and dual-nRF policy handling.
- [ ] **Step 4: Run to verify pass** — `cargo test -p ferrum-wroom-nrf`. Expected: PASS.
- [ ] **Step 5: `just lint`** then **Commit** — `git commit -am "refactor(wroom): trait-driven agent over ferrum-hal"`.

---

### Task 4: Migrate ESP32-C5 node to a trait-driven agent

**Files:**
- Modify: `crates/ferrum-c5-scout/Cargo.toml`, `crates/ferrum-c5-scout/src/lib.rs`

**Interfaces:**
- Consumes: `ferrum_hal` traits + mocks.
- Produces: `struct C5Agent<S, T, C>` with `fn new(..) -> Self`, `fn tick(&mut self) -> ferrum_hal::NodeStatus`, `fn apply_policy_cmd(&mut self, cmd: &FerrumPolicyCmd)`.

- [ ] **Step 1: Write failing tests** — `test_c5_telemetry_from_scanner` (scripted deauth/EAPOL counts surface in telemetry; 5 GHz channel tracked), `test_c5_offline_on_transport_error`.
- [ ] **Step 2: Run to verify fail** — `cargo test -p ferrum-c5-scout`. Expected: FAIL.
- [ ] **Step 3: Implement `C5Agent`** preserving the 5 GHz UNII scheduler + 384 KB SRAM budget guard + failover behavior.
- [ ] **Step 4: Run to verify pass**; **Step 5: `just lint`**; **Step 6: Commit** — `git commit -am "refactor(c5): trait-driven agent"`.

---

### Task 5: Migrate XIAO-S3 node to a trait-driven agent

**Files:**
- Modify: `crates/ferrum-s3-sense/Cargo.toml`, `crates/ferrum-s3-sense/src/lib.rs`

**Interfaces:**
- Consumes: `ferrum_hal` traits + `NodeStatus`.
- Produces: `struct S3Agent<S, T, C>` with `new`/`tick`/`apply_policy_cmd`, exposing the PSRAM partition state (`pcap_ringbuf_kb`, `camera_fb_kb`, `pdm_audio_fft_kb`, `camera_powered`) through its telemetry/accessors for the snapshot.

- [ ] **Step 1: Write failing tests** — `test_s3_psram_repartition_on_lockdown` (applying a cam/mic policy shifts PSRAM quotas and powers the camera on), `test_s3_offline_on_transport_error`.
- [ ] **Step 2: Run to verify fail** — `cargo test -p ferrum-s3-sense`. Expected: FAIL.
- [ ] **Step 3: Implement `S3Agent`** preserving the 8 MB PSRAM partition controller logic.
- [ ] **Step 4: Run to verify pass**; **Step 5: `just lint`**; **Step 6: Commit** — `git commit -am "refactor(s3): trait-driven agent"`.

---

### Task 6: `ferrum-sim` — RF world, physics, and sim PHYs

**Files:**
- Create: `crates/ferrum-sim/Cargo.toml`, `crates/ferrum-sim/src/lib.rs`, `crates/ferrum-sim/src/world.rs`, `crates/ferrum-sim/src/phys.rs`, `crates/ferrum-sim/src/phy_impl.rs`
- Modify: root `Cargo.toml`

**Interfaces:**
- Consumes: `ferrum_hal` traits, `ferrum_proto` types. Deps: `rand_pcg`, `rand_core`.
- Produces (consumed by Tasks 7, 9):
  - `struct RfWorld { /* emitters, rng, time_ms */ }` with `fn new(seed: u64) -> Self`, `fn step(&mut self, dt_ms: u64)`, and per-node readout accessors used by the sim PHYs (e.g. `fn rpd_at(&self, node: NodeId, ch: u8) -> bool`, `fn rssi_at(&self, node: NodeId, ch: u8) -> i8`, `fn next_frame(&mut self, node: NodeId) -> Option<SimFrame>`).
  - `struct Emitter { pub pos: (f32, f32), pub tx_dbm: i8, pub channel: u8, pub kind: EmitterKind }`
  - `fn rssi_from_distance(tx_dbm: i8, dist_m: f32) -> i8` (log-distance path-loss, the model already in `trilaterate_target_position_meters`).
  - `struct SimScanner`, `SimSniffer`, `SimTransport`, `SimClock` implementing the `ferrum-hal` traits by reading `RfWorld` (shared via `Rc<RefCell<RfWorld>>` or by passing a readout snapshot each tick — implementer's call; keep it single-threaded within one tick).
- Produces: `trilaterate(anchor_rssi: [i8; 3]) -> (f32, f32, [f32; 3])` moved here from `main.rs` (shared by narrative + snapshot).

- [ ] **Step 1: Write failing tests** in `phys.rs`: `test_rssi_decreases_with_distance` (monotonic), `test_rssi_clamped` (stays within `[-90, -25]`); and `test_trilaterate_centroid` porting the existing trilateration behavior (closest anchor dominates).
- [ ] **Step 2: Write failing test** in `world.rs`: `test_world_step_advances_time` and `test_quiet_world_is_quiet` (no adversaries → low RPD/rssi, no frames).
- [ ] **Step 3: Run to verify fail** — `cargo test -p ferrum-sim`. Expected: FAIL.
- [ ] **Step 4: Implement `phys.rs`** (path-loss + trilateration) and **`world.rs`** (emitters, seeded `Pcg64`, `step` advancing time and regenerating per-channel readouts with bounded jitter).
- [ ] **Step 5: Implement `phy_impl.rs`** — the four sim PHYs reading the world.
- [ ] **Step 6: Run to verify pass**; **Step 7: `just lint`**; **Step 8: Commit** — `git commit -am "feat(sim): seeded RF world, path-loss physics, sim PHYs"`.

---

### Task 7: `ferrum-sim` — adversary models and scenarios

**Files:**
- Create: `crates/ferrum-sim/src/adversary.rs`, `crates/ferrum-sim/src/scenario.rs`
- Modify: `crates/ferrum-sim/src/lib.rs`

**Interfaces:**
- Consumes: `RfWorld` from Task 6.
- Produces (consumed by Task 9):
  - `enum Adversary { Jammer{..}, EvilTwinDeauth{..}, MouseJackEsb{..}, BleRotatingImplant{..}, SubGhzReplay{..}, BtSkimmer{..} }` each with `fn apply(&mut self, world: &mut RfWorld, t_ms: u64)`.
  - `struct Scenario { pub name: &'static str, timeline: Vec<(u64, ScenarioEvent)> }`, `enum ScenarioEvent { Spawn(Adversary), Clear(AdversaryId) }`
  - `fn scenario_by_name(name: &str) -> Option<Scenario>` with at least `"quiet"` and the flagship `"red-team-incursion"` (walks: baseline → MouseJack/ghost-band → 5 GHz evil-twin/deauth → Layer-1 jammer → close-range intruder + sub-GHz replay + BLE rotation).
  - `struct SimController { world: RfWorld, scenario: Scenario, .. }` with `fn new(seed, scenario)`, `fn advance(&mut self, dt_ms)`, `fn inject(&mut self, a: Adversary)`, `fn clear(&mut self, id)`.

- [ ] **Step 1: Write failing adversary tests** — one per adversary asserting the signal it is meant to drive appears (e.g. `Jammer` → >40 channels RPD-hot; `EvilTwinDeauth` → deauth count rises on a 5 GHz channel; `BleRotatingImplant` → two different MACs resolve to one fingerprint via `build_ble_fingerprint`).
- [ ] **Step 2: Write failing golden test** — `test_red_team_incursion_is_reproducible`: run `SimController::new(42, "red-team-incursion")` for 300 ticks, hash the per-tick readouts, assert equality against a committed golden hash. *(Review Focus: seed reproducibility.)*
- [ ] **Step 3: Run to verify fail** — `cargo test -p ferrum-sim`. Expected: FAIL.
- [ ] **Step 4: Implement adversaries + scenarios + `SimController`.** Generate the golden hash once, commit it as a constant.
- [ ] **Step 5: Run to verify pass**; **Step 6: `just lint`**; **Step 7: Commit** — `git commit -am "feat(sim): adversary models + flagship scenario (reproducible)"`.

---

### Task 8: `SwarmSnapshot` serialization types

**Files:**
- Create: `crates/ferrum-brain/src/snapshot.rs`
- Modify: `crates/ferrum-brain/Cargo.toml` (add `serde`, `serde_json`)

**Interfaces:**
- Consumes: outputs of `ferrum-laya`, agents, `ferrum-ids`, `ferrum-forensics`, `ferrum-triage`, `ferrum-sim`.
- Produces (consumed by Tasks 9–12):
  - `#[derive(Serialize)] struct SwarmSnapshot { tick: u64, nodes: [NodeView; 3], decision: DecisionView, radar: RadarView, spectrum: SpectrumView, pillars: PillarView, detections: Vec<DetectionView>, forensics: ForensicsView, secure: SecureView, lora_queue_depth: u8, scenario: ScenarioView, events: Vec<EventView> }` plus the nested `*View` structs (plain serializable mirrors of engine types; keep field names snake_case and stable — the dashboard depends on them).
  - `#[derive(Deserialize)] enum OperatorCommand { InjectAdversary(String), ClearAdversary(u32), ForcePolicy(u8), SetScenario(String), Pause, Resume, SetTickHz(u8) }` (consumed by Task 11).

- [ ] **Step 1: Write failing test** — `test_snapshot_roundtrips_json`: build a `SwarmSnapshot`, `serde_json::to_string` then `from_str` into a `serde_json::Value`, assert key fields (`tick`, `nodes[0].online`, `decision.selected_policy`, `pillars.detect`) are present and typed as expected.
- [ ] **Step 2: Write failing test** — `test_operator_command_parses`: each `OperatorCommand` variant parses from its JSON form.
- [ ] **Step 3: Run to verify fail** — `cargo test -p ferrum-brain snapshot`. Expected: FAIL.
- [ ] **Step 4: Implement the `*View` structs + `OperatorCommand`** and `From`/constructor helpers mapping engine types into views.
- [ ] **Step 5: Run to verify pass**; **Step 6: `just lint`**; **Step 7: Commit** — `git commit -am "feat(brain): SwarmSnapshot + OperatorCommand serde types"`.

---

### Task 9: `ferrum-brain` headless orchestrator + storyline integration test

**Files:**
- Create: `crates/ferrum-brain/src/orchestrator.rs`, `crates/ferrum-brain/tests/storyline.rs`
- Modify: `crates/ferrum-brain/src/main.rs` (wire `--headless`, `--scenario`, `--seed`)

**Interfaces:**
- Consumes: `ferrum-sim` `SimController` + sim PHYs, the three agents, `ferrum_laya::LayaEngine`, `ferrum_ids::IdsEngine`, `ferrum_deceive`, `ferrum_secure::SecureChannel`, `ferrum_forensics`, `ferrum_triage`, Task 8 views.
- Produces (consumed by Tasks 10–11):
  - `struct Orchestrator { .. }` with `fn new(seed: u64, scenario: &str) -> anyhow::Result<Self>`, `fn tick(&mut self) -> SwarmSnapshot` (advances sim, runs the full §7 data flow, returns the snapshot), `fn apply_command(&mut self, cmd: OperatorCommand)`.
  - `fn run_headless(seed, scenario, ticks: Option<u64>)` printing the narrative.

- [ ] **Step 1: Write failing integration test** `tests/storyline.rs::test_red_team_incursion_hits_all_pillars` — build `Orchestrator::new(42, "red-team-incursion")`, call `tick()` for the scenario's length collecting snapshots, and assert over the run: at least one DETECT detection raised, at least one DECEIVE tripwire fired, a `ForensicLockdown` tick occurs, the forensic chain `verify`s true at that point, and the LoRa queue drains. Also assert **no tick panics**.
- [ ] **Step 2: Write failing test** `test_forged_command_surfaces_event` — inject a tampered sealed command path (flip a byte) and assert the snapshot's `events` contains a secure-rejection event and the loop continues. *(Review Focus: forged/replayed command.)*
- [ ] **Step 3: Run to verify fail** — `cargo test -p ferrum-brain --test storyline`. Expected: FAIL.
- [ ] **Step 4: Implement `Orchestrator::tick`** running the §7 pipeline with saturating/panic-free arithmetic; build the `SwarmSnapshot` each tick; record secure open failures as `EventView`s.
- [ ] **Step 5: Implement `run_headless` + arg parsing** so `cargo run -p ferrum-brain -- --headless --scenario red-team-incursion --seed 42` prints the tactical narrative.
- [ ] **Step 6: Run to verify pass** — integration tests PASS; `just run -- --headless` prints the storyline.
- [ ] **Step 7: `just lint`** then **Commit** — `git commit -am "feat(brain): orchestrator tick loop + storyline integration test"`.

---

### Task 10: axum web server + WebSocket streaming + serve dashboard

**Files:**
- Create: `crates/ferrum-brain/src/server.rs`
- Modify: `crates/ferrum-brain/Cargo.toml` (`tokio`, `axum`, `tracing`), `crates/ferrum-brain/src/main.rs` (default = serve; `--headless` = narrative)

**Interfaces:**
- Consumes: `Orchestrator` (Task 9), `SwarmSnapshot` (Task 8).
- Produces: `async fn serve(orch: Orchestrator, port: u16, tick_hz: u8) -> anyhow::Result<()>` — spawns a tick task driving the orchestrator at `tick_hz`, publishing each snapshot to a `tokio::sync::broadcast::Sender<SwarmSnapshot>`; `GET /` serves the embedded dashboard; `GET /ws` subscribes a client and forwards snapshots as JSON text frames.

- [ ] **Step 1: Write failing test** `server.rs::test_two_clients_one_drop` — start `serve` on an ephemeral port in a tokio test, connect two WS clients, read a snapshot on both, drop client A, then assert client B keeps receiving subsequent snapshots. *(Review Focus: WebSocket disconnect/lag.)*
- [ ] **Step 2: Write failing test** `test_index_serves_dashboard` — `GET /` returns 200 and a body containing `ferrum` marker text.
- [ ] **Step 3: Run to verify fail** — `cargo test -p ferrum-brain server`. Expected: FAIL.
- [ ] **Step 4: Implement `serve`** — tick task + broadcast; per-client WS loop that on `RecvError::Lagged` fetches the latest and continues, and on client error drops only that client; embed the dashboard via `include_str!("../../../dashboard/ferrum_cyberswarm_deck.html")`.
- [ ] **Step 5: Run to verify pass**; manually `cargo run -p ferrum-brain` and confirm `http://127.0.0.1:<port>/` loads.
- [ ] **Step 6: `just lint`** then **Commit** — `git commit -am "feat(brain): axum server + WebSocket snapshot streaming"`.

---

### Task 11: Operator command intake (interactivity)

**Files:**
- Modify: `crates/ferrum-brain/src/server.rs`

**Interfaces:**
- Consumes: `OperatorCommand` (Task 8), `Orchestrator::apply_command` (Task 9).
- Produces: inbound WS messages parsed as `OperatorCommand` and applied to the shared orchestrator before the next tick (orchestrator guarded by a `tokio::sync::Mutex`).

- [ ] **Step 1: Write failing test** `test_inject_adversary_changes_stream` — connect a WS client, send `{"InjectAdversary":"jammer"}`, and assert that within a few subsequent snapshots the decision shifts to `FLOOD_JAM_SURVIVAL`.
- [ ] **Step 2: Write failing test** `test_force_policy_flows_through_secure` — send `{"ForcePolicy":9}` and assert a following snapshot shows the forced policy and a valid secure `seq` increment.
- [ ] **Step 3: Run to verify fail** — Expected: FAIL.
- [ ] **Step 4: Implement inbound handling** — read client WS messages, deserialize to `OperatorCommand`, `orch.lock().await.apply_command(cmd)`; ignore malformed messages (log at `warn`).
- [ ] **Step 5: Run to verify pass**; **Step 6: `just lint`**; **Step 7: Commit** — `git commit -am "feat(brain): interactive operator commands over WebSocket"`.

---

### Task 12: Live dashboard client + visuals

**Files:**
- Modify: `dashboard/ferrum_cyberswarm_deck.html` (embedded JS/CSS; single file)

**Interfaces:**
- Consumes: the `/ws` JSON `SwarmSnapshot` stream and sends `OperatorCommand` JSON back. Field names must match Task 8 exactly.

- [ ] **Step 1: Wire the socket** — on load, open `ws://<host>/ws`; on message, `JSON.parse` and dispatch to renderers; auto-reconnect with backoff if the socket closes.
- [ ] **Step 2: Render the live panels** — (a) 2.4 GHz + 5 GHz **spectrum waterfall** (scrolling canvas from `spectrum`); (b) **trilateration radar** plotting `radar.pos` + anchor rings, animated between ticks; (c) **decision feed** showing selected policy, confidence, distribution bars, and `rationale.top_signals`; (d) **pillar strip** (DETECT/DECEIVE/DEFEND/PROVE) lighting on activity; (e) **forensics/secure** line (chain tip, seq, LoRa depth); (f) per-node cards showing `online/offline`.
- [ ] **Step 3: Add operator controls** — buttons/menu to inject each adversary, force a policy, switch scenario, pause/resume, set tick-rate — sending `OperatorCommand` JSON up the socket.
- [ ] **Step 4: Verify in a browser** — run `cargo run -p ferrum-brain`, load the page, confirm panels animate live and controls visibly re-task the swarm. Use the built-in browser to screenshot each panel.
- [ ] **Step 5: `just lint`** (unaffected) then **Commit** — `git commit -am "feat(dashboard): live WebSocket client, waterfall/radar/pillars + controls"`.

---

### Task 13: Docs rewrite + demo polish

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`
- Create: `docs/DEMO.md`, `docs/media/demo.gif`

**Interfaces:**
- Consumes: the finished system.

- [ ] **Step 1: Rewrite `README.md`** — new quickstart (`rustup` install, `cargo run -p ferrum-brain`, open the URL), the two-world (sim/firmware) architecture, the crate table (add `ferrum-hal`, `ferrum-laya`, `ferrum-sim`), and a Phase-2 pointer.
- [ ] **Step 2: Update `ARCHITECTURE.md`** — add the HAL boundary, the scored decision engine, the simulator/adversary model, and the live data-flow diagram; mark the policy table as sim-backed today / firmware-backed in Phase 2.
- [ ] **Step 3: Write `docs/DEMO.md`** — a 60-second scripted walkthrough of the flagship scenario and which controls to hit for the "wow".
- [ ] **Step 4: Record `docs/media/demo.gif`** — capture the flagship scenario running (built-in browser → GIF), embed it at the top of the README.
- [ ] **Step 5: Final gate** — `cargo test --workspace`, `just lint`, `cargo run -p ferrum-brain` smoke test. **Commit** — `git commit -am "docs: rewrite README/ARCHITECTURE, add demo walkthrough + GIF"`.

---

## Notes for the executor

- Tasks 3→4→5 share `NodeStatus` (moved to `ferrum-hal` in Task 4 Step 1); if implementing out of order, put `NodeStatus` in `ferrum-hal` first.
- Keep every `no_std` crate free of the Global Constraints' banned dependencies — if a core crate suddenly needs `std`, stop: that is a design smell to raise, not to paper over with a feature flag.
- The classic narrative (`--headless`) is the human-readable regression oracle; keep it working through every task until the dashboard supersedes it.
