# Ferret 10x — Phase 1: "Living Swarm" Design Spec

- **Date:** 2026-10-29
- **Status:** Approved design (pre-implementation)
- **Scope:** Phase 1 only. Phase 2 (real esp-hal firmware) gets its own spec.

---

## 1. Intent (the agreed understanding)

Ferret (Ferrum CyberSwarm) is today a ~2,900-line Rust workspace (10 crates, 25
tests) that **models** an AI-adaptive wireless-surveillance swarm: a Raspberry
Pi 5 "brain" running a two-tier decision engine (Laya System-1 reactive +
System-2 escalation) that commands three ESP32 RF sensor nodes, plus a
uConsole/LoRa operator deck, organized around four pillars — **DETECT /
DECEIVE / DEFEND / PROVE**. It currently runs a 5-tick *scripted* simulation and
prints a tactical narrative; the decision engine is a hand-written if/else
ladder; there is no live data, no networking, and no hardware I/O. No Rust
toolchain is installed on the build machine.

**The owner wants two outcomes at once:**

1. **Showcase / portfolio** — a jaw-dropping *live* demo and narrative to
   impress people. Delivered as a **live Rust-served dashboard**.
2. **Real deployable hardware** — the owner has the full kit (Pi 5 + three
   ESP32 nodes + LoRa) and intends to flash real firmware.

**Definition of "10x" / success for Phase 1:**

- A single `cargo run` starts a continuously-running simulated swarm and serves
  an interactive, real-time dashboard that is visibly impressive: live spectrum
  waterfall, moving trilateration radar, a decision feed with confidence and
  rationale, pillars lighting up, forensic hash-chain sealing, and the ability
  for an operator to **inject attacks from the browser and watch the swarm
  re-task live**.
- The decision engine is a **genuine explainable scored model** (not if/else
  dressed up), fully unit-tested and `no_std`-portable.
- The code is restructured behind a **hardware-abstraction layer (HAL)** so the
  simulated radios and the future esp-hal radios are interchangeable — Phase 2
  firmware becomes a drop-in behind the same traits. Nothing built in Phase 1 is
  throwaway.
- Everything compiles, `cargo test --workspace` is green, and `cargo clippy`
  and `cargo fmt --check` are clean.

**Chosen approach:** "Living Swarm" (Approach A) — do the HAL refactor so the
showcase and the hardware path are a single effort.

**Explicitly deferred to Phase 2 (out of scope here):** real esp-hal peripheral
drivers, real ESP-NOW/LoRa radio transport, `espflash` flashing, and
cross-compilation to `xtensa-*`/`riscv32imac-*` targets.

---

## 2. Target workspace layout

### Shared cores — `no_std`, compiled into both the simulator and (Phase 2) firmware

| Crate | State | Role |
| :--- | :--- | :--- |
| `ferrum-proto` | keep | Wire protocol, CRC-8, telemetry/policy structs. Minor additions only. |
| `ferrum-hal` | **new** | Peripheral & transport traits the node agents are written against. Dep-light, `no_std`. |
| `ferrum-laya` | **new** | The decision engine extracted out of `ferrum-brain`'s binary so it is testable and firmware-portable. |
| `ferrum-wroom-nrf` | refactor | WROOM node **agent**, generic over HAL traits. Keeps telemetry assembly. |
| `ferrum-c5-scout` | refactor | ESP32-C5 node agent, generic over HAL traits. |
| `ferrum-s3-sense` | refactor | XIAO-S3 node agent, generic over HAL traits. |
| `ferrum-ids` | keep (+rules) | DETECT. A few additional WIDS rules; otherwise unchanged. |
| `ferrum-deceive` | keep | DECEIVE. Decoys + tripwires. |
| `ferrum-secure` | keep | DEFEND. Seal/open command channel; surfaced as live events. |
| `ferrum-forensics` | keep | PROVE. Hash-chain sealing, wired into the live stream. |
| `ferrum-triage` | keep | SURVIVE. Compressed LoRa feature vectors. |

### Showcase-only — `std`

| Crate | State | Role |
| :--- | :--- | :--- |
| `ferrum-sim` | **new** | Continuous seeded RF world + adversary models + scenarios. Implements the sim side of the HAL traits. |
| `ferrum-brain` | rebuild | Async orchestrator + web server (tokio + axum). Owns the world, the three agents, the laya engine, and the pillars; drives the tick loop; serves and streams the dashboard. |

### Dashboard

`dashboard/ferrum_cyberswarm_deck.html` is upgraded into a live WebSocket client
and **embedded into and served by `ferrum-brain`** (single file, stays
portable).

---

## 3. The HAL boundary (`ferrum-hal`)

The crux of hardware-readiness. Node logic is written against small traits that
model real ESP peripherals. Sim impls live in `ferrum-sim`; esp-hal impls arrive
in Phase 2. Illustrative shape (final signatures settled during implementation):

```rust
#![no_std]

/// Received-power / RSSI scanning (nRF24 RPD, Wi-Fi survey).
pub trait SpectrumScanner {
    fn set_channel(&mut self, ch: u8);
    fn read_rpd(&mut self) -> bool;     // carrier above threshold?
    fn sample_rssi(&mut self) -> i8;    // dBm
}

/// Promiscuous frame intake (ESB/MouseJack, 802.11 mgmt, BLE adv).
pub trait PacketSniffer {
    type Frame;
    fn next_frame(&mut self) -> Option<Self::Frame>;
}

/// Node interconnect (ESP-NOW now, LoRa SX1262 out-of-band).
pub trait Transport {
    type Error;
    fn send(&mut self, buf: &[u8]) -> Result<(), Self::Error>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Monotonic time source.
pub trait Clock {
    fn now_ms(&self) -> u64;
}
```

Each node becomes an agent generic over these traits, e.g.
`WroomAgent<S: SpectrumScanner, P: PacketSniffer, T: Transport, C: Clock>`, with
a `tick()` that scans, assembles a `NodeTelemetry`, and applies inbound
`FerrumPolicyCmd`s. In the simulator the trait objects are fed by the RF world;
on hardware they will be esp-hal drivers — identical agent code either way.

---

## 4. Decision engine (`ferrum-laya`) — explainable scored model

Extracted from the binary into a `no_std` crate. Replaces the if/else ladder
with:

- **`SignalVector`** — normalized features derived from the three nodes'
  telemetry plus the sub-GHz/jam inputs: jam ratio, proximity, ghost-band/ESB
  activity, deauth/EAPOL rate, BT-classic/BLE anomaly, sub-GHz burst.
- **Weighted per-policy scoring** — each `PolicyMode` carries weights over the
  signals; `score = Σ wᵢ·signalᵢ`. Scores are normalized into an integer
  confidence distribution that **sums to 100** across the top policies. Argmax
  selects the policy; the distribution is what the dashboard renders.
  **Fixed-point / integer math only** — no float std, no float dependency, so
  the crate stays `no_std`-pure for firmware.
- **Explainability** — the engine can emit the top contributing signals for the
  chosen policy (drives the dashboard's rationale line).
- **Hysteresis state machine** — a dwell/decay rule prevents policy flapping
  between ticks; a policy must win by a margin or persist for N ticks before it
  replaces the incumbent. More realistic and visibly smoother in the demo.
- **System-2 escalation** retained: any `ferrum-ids` **Critical** detection
  forces `ForensicLockdown`; a **High** detection adopts the rule's recommended
  policy; otherwise System-1 stands.

System-1 is a single forward pass (preserving the "~20–30 ms one-pass typed
decision" framing honestly — it is now a real scored pass, not marketing).

---

## 5. Simulator (`ferrum-sim`)

- **`RfWorld`** — holds emitters (legit APs, BLE devices) and injected
  adversaries with positions, tx-powers and channels; computes per-node,
  per-channel RSSI/RPD, frame streams, deauth/EAPOL counts, ghost-band hits,
  etc. A **seeded RNG** (`rand_pcg` or similar) makes any run reproducible from
  `--seed`; a jitter term gives organic movement.
- **Adversary models** — `Jammer`, `EvilTwinDeauth`, `MouseJackEsb`,
  `BleRotatingImplant`, `SubGhzReplay`, `BtSkimmer`. Each advances over time and
  perturbs the world; each maps to signals the laya engine and IDS already
  understand.
- **Scenarios** — a scripted timeline of adversary spawns. Ships a flagship
  **"Red-Team Incursion"** storyline that deliberately walks through all four
  pillars for the demo, plus `--scenario` selection and a fully interactive mode
  driven by operator commands.
- **Sim PHY impls** — concrete `SpectrumScanner` / `PacketSniffer` / `Transport`
  / `Clock` implementations that read from `RfWorld` for the node they represent.

---

## 6. Orchestrator & server (`ferrum-brain`)

- **Runtime:** tokio. A `tokio::time::interval` tick (default 10 Hz) drives one
  pass of the data flow in §7.
- **Snapshot:** each tick produces a `SwarmSnapshot` (serde `Serialize`)
  containing: the three node telemetries, the System-1 decision + distribution +
  rationale + confidence, the System-2 result, the radar position + per-anchor
  distances, the 2.4 GHz (126-ch) + 5 GHz spectrum/occupancy, active pillars,
  IDS detections, forensic hash-chain tip, secure sequence number, LoRa queue
  depth, and the current scenario/adversary state.
- **HTTP/WS (axum):**
  - `GET /` → serves the embedded dashboard HTML.
  - `GET /ws` → upgrades to WebSocket; the server broadcasts each
    `SwarmSnapshot` (via a `tokio::sync::broadcast` channel) to all connected
    clients.
  - Inbound WS messages = **operator commands**: inject/clear an adversary,
    force a policy, switch scenario, pause/resume, set tick rate. These mutate
    the world and are visible on the next tick — and policy forcing flows
    through the real `ferrum-secure` seal/open path.
- **Modes / flags:** `--headless` (print the classic tactical narrative, so
  `cargo run` works with no browser), `--scenario <name>`, `--seed <n>`,
  `--port <n>`, `--tick-hz <n>`.

---

## 7. Data flow (one tick)

```
world.step()
  → sim PHYs updated
  → for each node: agent.tick() builds NodeTelemetry
  → laya.system1(signals) → typed decision + distribution
  → ids.evaluate(telemetry, tripwires) → detections
  → laya.system2(decision, detections) → escalated decision
  → FerrumPolicyCmd → ferrum-secure.seal() → agents.apply()
  → if lockdown: ferrum-forensics seals PCAP block; if survive: ferrum-triage
    feature-vector queued for LoRa
  → assemble SwarmSnapshot → broadcast to WebSocket clients → dashboard renders
```

Operator command (inbound) → mutates world/scenario or forces a policy →
observable on the next tick.

---

## 8. Error handling

- **Tick logic is panic-free by construction** — saturating arithmetic and
  clamps throughout; property-tested. A bad input can never kill the server
  loop.
- **HAL traits return `Result`.** Sim impls are infallible, but Phase-2 firmware
  impls will fail, so agents handle transport errors by **degrading gracefully
  and marking a node `offline`** (surfaced on the dashboard — itself good demo
  material).
- **WebSocket:** lagging or broken clients are dropped individually; the server
  runs correctly with zero or many clients. A `broadcast` lag just means that
  client gets the next snapshot.
- **Secure channel:** replay/auth failures become **events in the snapshot**,
  never panics.
- **Startup only** uses `anyhow` (bind port, load scenario). Per-tick code does
  not allocate fallibly.

---

## 9. Testing strategy

- Keep the existing 25 tests. Add:
  - **`ferrum-laya`** — table-driven tests asserting each flagship scenario
    yields the expected policy and confidence ordering; a property test that the
    distribution sums to 100 and argmax matches the selected policy; hysteresis
    tests (no flap under alternating borderline inputs).
  - **Node agents / `ferrum-hal`** — a **mock PHY** in tests feeds known stimuli
    and asserts the resulting `NodeTelemetry` bytes.
  - **`ferrum-sim`** — deterministic seed → **golden-snapshot** of a scenario
    timeline (regression); adversary models produce signals in expected ranges.
  - **Integration** — run the headless storyline for N ticks on a fixed
    seed/scenario and assert the narrative hits every pillar: DETECT raises a
    detection, DECEIVE trips a decoy, lockdown seals a chain block,
    `verify_chain` returns valid, and the LoRa queue drains. This doubles as the
    demo's correctness guarantee.
- **Quality gates:** `cargo test --workspace`, `cargo clippy` (deny warnings in
  CI), `cargo fmt --check`. Add `rust-toolchain.toml` (pin stable) and a
  `justfile` with `test` / `lint` / `run` / `demo` targets.

---

## 10. Milestones

Each milestone compiles, passes tests, and is demoable on its own.

0. **Toolchain + green baseline** — install `rustup`/`cargo`; get
   `cargo test --workspace` passing on the current code; add
   `rust-toolchain.toml`, `justfile`, `fmt`/`clippy` clean; commit.
1. **Extract `ferrum-laya`** — move the decision engine out of the binary into
   the new scored engine; brain consumes it; behavior preserved or improved;
   tests added.
2. **`ferrum-hal` + migrate WROOM** — introduce the traits; rewrite the WROOM
   node as a trait-driven agent; mock-PHY tests. Brain still runs via a
   sim-fed agent.
3. **Migrate C5 + S3** — both node agents trait-driven; retire the
   `main.rs` field-poking.
4. **`ferrum-sim`** — continuous world + adversary models + flagship scenario;
   headless brain runs it and prints the live narrative.
5. **Async server + WebSocket** — brain serves the dashboard and streams
   snapshots; dashboard renders live (read-only).
6. **Interactivity** — operator command intake (inject attack, force policy,
   switch scenario, pause, tick rate).
7. **Polish** — spectrum waterfall / radar animation / pillar FX on the
   dashboard; rewrite `README.md` and `ARCHITECTURE.md`; add a demo script and a
   recorded GIF.

**Phase 2 (separate spec, later):** esp-hal peripheral impls per node, real
ESP-NOW/LoRa transport, `espflash` flashing — drop-in behind the §3 traits.

---

## 11. Dependencies

Heavy dependencies land **only** in the `std` showcase crates (`ferrum-sim`,
`ferrum-brain`): `tokio`, `axum`, `serde` + `serde_json`, a seedable `rand`
(`rand_pcg`), `anyhow`, `tracing`. The `no_std` cores stay dependency-light;
`ferrum-laya` uses **integer/fixed-point math** to avoid even a float
dependency. No dependency is added to a `no_std` crate that would block Phase-2
cross-compilation.

---

## 12. Risks & mitigations

- **HAL refactor churn (milestones 2–3)** is the largest risk → split per node
  so each migration stays small and independently verified by mock-PHY tests;
  the classic narrative output is the regression oracle until the sim replaces
  it.
- **Fixed-point scoring awkwardness** → if integer math proves too fiddly for
  the confidence normalization, fall back to `micromath`/`libm` (still
  `no_std`); decision recorded at implementation time, not silently.
- **Dashboard scope creep** → milestone 5 ships a *working* live view before
  milestone 7 polish; polish is explicitly last so the demo exists early.
- **No toolchain installed** → milestone 0 is literally "make it build on this
  machine" before any change.
