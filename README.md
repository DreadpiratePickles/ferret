# Ferret (`Ferrum CyberSwarm`)

**A living wireless-security swarm you can run on a laptop today, and flash onto ESP32 silicon tomorrow.**

![Ferret tactical dashboard: live spectrum waterfall, trilateration radar, Laya decision feed and the four pillars](./docs/media/dashboard.png)

Ferret is an **AI-adaptive Rust embedded wireless surveillance swarm** organised around **4 Operational Pillars: `DETECT`, `DECEIVE`, `DEFEND`, `PROVE`**. Three radio nodes sense the 2.4 GHz, 5 GHz and BLE/802.15.4 air; a control plane scores what they hear, picks a swarm-wide policy, explains *why*, and re-tasks the radios. Every decision is authenticated, and every piece of evidence lands in a SHA-256 hash chain.

It is built around **two worlds that share one boundary**:

| | World 1: Simulation (works today) | World 2: Firmware (Phase 2) |
| :--- | :--- | :--- |
| Radios | Seeded RF world with path-loss physics and scripted adversaries (`ferrum-sim`) | Real `esp-hal` drivers: nRF24L01+, Wi-Fi 6, BLE, 802.15.4 |
| Node logic | `WroomAgent` / `C5Agent` / `S3Agent` | **The exact same agent code** |
| Decision engine | `ferrum-laya` | **The exact same crate** |
| Control plane | `ferrum-brain` on your laptop, streaming a live web dashboard | `ferrum-brain` on a Raspberry Pi 5 |

The seam is [`ferrum-hal`](./crates/ferrum-hal/src/lib.rs): a handful of `#![no_std]` traits (`SpectrumScanner`, `PacketSniffer`, `Transport`, `Clock`). Node agents are generic over them, so swapping the simulator for real silicon changes the trait *implementations*, not the logic. The decision core builds for bare-metal today (verified on `riscv32imac-unknown-none-elf`).

> **Status:** Phase 1 (the living simulation, dashboard and shared cores) is done. Phase 2 (real `esp-hal` peripheral drivers on the boards) is not started. See [Phase 2](#phase-2-real-hardware).

---

## Quickstart

**1. Install Rust** (skip if `cargo --version` already works):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The repo pins the `stable` channel with `rustfmt` and `clippy` via [`rust-toolchain.toml`](./rust-toolchain.toml); rustup picks that up automatically.

**2. Run the live swarm and open the dashboard:**

```bash
cd ferret   # the repository root
cargo run -p ferrum-brain
```

Then open **<http://127.0.0.1:8787/>**. The default scenario is `red-team-incursion`, seed `42`, ticking at 10 Hz. A guided 60-second tour is in [`docs/DEMO.md`](./docs/DEMO.md).

**3. Or watch the tactical narrative in your terminal** (no browser, no server):

```bash
cargo run -p ferrum-brain -- --headless
```

**4. Run the tests:**

```bash
cargo test --workspace
```

### `ferrum-brain` flags

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `--scenario <name>` | `red-team-incursion` | Scenario timeline to play: `red-team-incursion` or `quiet` |
| `--seed <n>` | `42` | RF-world seed. Same seed + scenario = same run, every time |
| `--port <n>` | `8787` | Dashboard / WebSocket port (binds `127.0.0.1` only) |
| `--tick-hz <n>` | `10` | Initial tick rate. The flagship timeline is authored at 10 Hz |
| `--headless` | off | Print the tactical narrative instead of starting the server |
| `--ticks <n>` | scenario length + a short tail | Number of ticks for `--headless` |

There is also a [`justfile`](./justfile): `just test`, `just lint` (clippy `-D warnings` + `fmt --check`), `just run`, `just demo`.

---

## What you're looking at

The dashboard is a single page served by `ferrum-brain` itself and fed by a WebSocket (`/ws`) that carries one `SwarmSnapshot` JSON frame per tick.

- **Spectrum waterfall:** the WROOM node's 126-channel nRF24 RPD sweep (2400-2525 MHz, including the 2485-2525 MHz "ghost band"), plus the Wi-Fi channels the C5 and S3 are tuned to and any sub-GHz burst the operator deck hears.
- **Trilateration radar:** the three nodes are anchors; the target is placed from their three peak-anomaly RSSI readings.
- **Laya two-tier decision:** the selected policy, a confidence figure, the full six-policy score distribution, the top three signals that drove it (the rationale), and an escalation marker when System-2 (IDS) overrides System-1.
- **The four pillars:** `DETECT` (IDS rules firing), `DECEIVE` (decoy tripwires), `DEFEND` (authenticated command channel counters), `PROVE` (forensic chain).
- **Three node cards:** policy, channel, load and free memory per node, including the S3's 8 MB PSRAM partition and camera / mic power state.
- **Forensic hash chain:** SHA-256 evidence records sealed on `FORENSIC_LOCKDOWN`, with chain verification.
- **IDS detections and event log:** what fired this tick (with MITRE ATT&CK tags), plus a running log of operator actions and security events.
- **Operator controls:** inject any of six adversaries, force or release a policy, switch scenario, pause / resume, and set the tick rate (1 / 2 / 5 / 10 / 20 Hz).

The six adversary models are `jammer`, `evil-twin-deauth`, `mousejack-esb`, `ble-rotating-implant`, `subghz-replay` and `bt-skimmer`.

> **Reading the jammer run:** a confirmed Layer-1 jammer trips IDS rule `FR-JAM-001` at `High`, which agrees with System-1's own pick (and would be adopted by System-2 if it did not): the dashboard reads `FLOOD_JAM_SURVIVAL` for the whole jam, with no escalation marker (a survivable attack is answered by re-tasking the swarm, fail over to 5 GHz and dedup frames, not by locking down). `FORENSIC_LOCKDOWN` is reserved for a `Critical` detection such as a honeypot decoy trip, which freezes the PCAP ring, seals the evidence block and arms the camera / mic. In the flagship scenario you see both: the jam phase shows `FLOOD_JAM_SURVIVAL`, then the close-range intruder trips the decoy and the swarm locks down.

---

## Workspace architecture (13 crates)

| Crate | Target | Pillar / Role |
| :--- | :--- | :--- |
| [`crates/ferrum-proto`](./crates/ferrum-proto/src/lib.rs) | `#![no_std]` | 24B `NodeTelemetry` and 13B `FerrumPolicyCmd` wire protocol, CRC-8, 126-channel nRF24 `RPD` bitmap, 10 `PolicyMode` states (`0x01..=0x0A`) |
| [`crates/ferrum-hal`](./crates/ferrum-hal/src/lib.rs) | `#![no_std]` | **The sim/firmware boundary:** `SpectrumScanner`, `PacketSniffer`, `Transport` and `Clock` traits, `NodeStatus`, plus heapless mock PHYs behind the `mock` feature |
| [`crates/ferrum-laya`](./crates/ferrum-laya/src/lib.rs) | `#![no_std]` core | **Decision engine:** six normalized signals, a transparent integer weight table scored into a distribution that sums to exactly 100, hysteresis (20-point margin or 3-tick dwell) against policy flapping. System-2 IDS escalation sits behind the default-on `ids` feature, so the System-1 core builds bare-metal with `--no-default-features` |
| [`crates/ferrum-wroom-nrf`](./crates/ferrum-wroom-nrf/src/lib.rs) | `#![no_std]` | **Node 1 agent** (ESP32-WROOM + dual nRF24L01+), generic over `ferrum-hal`: split-spectrum waterfall, Ghost-Band hunter-killer, promiscuous ESB / MouseJack sniffing, FNV-1a BLE MAC-randomization de-anonymizer. Degrades to `Offline` on transport error |
| [`crates/ferrum-c5-scout`](./crates/ferrum-c5-scout/src/lib.rs) | `#![no_std]` | **Node 2 agent** (ESP32-C5, RISC-V): 5 GHz UNII-1/2/3 channel scheduler, 802.15.4 reporting, 384 KB SRAM budget guard, 5 GHz failover survival mode |
| [`crates/ferrum-s3-sense`](./crates/ferrum-s3-sense/src/lib.rs) | `#![no_std]` | **Node 3 agent** (XIAO ESP32-S3 Sense): dynamic 8 MB PSRAM partitioning (PCAP ring vs BLE GATT cache vs OV2640 camera + PDM mic FFT) |
| [`crates/ferrum-ids`](./crates/ferrum-ids/src/lib.rs) | `std` | **Pillar 1 (`DETECT`):** 9-rule WIDS engine with MITRE ATT&CK tags, severity ladder, and the System-2 escalation rule |
| [`crates/ferrum-deceive`](./crates/ferrum-deceive/src/lib.rs) | `#![no_std]` | **Pillar 2 (`DECEIVE`):** sink-holed `FakeSoftAp` 802.11 beacon builder, iBeacon / Eddystone-UID / canary GATT decoys, 24B `TripwireEvent` |
| [`crates/ferrum-secure`](./crates/ferrum-secure/src/lib.rs) | `#![no_std]` | **Pillar 3 (`DEFEND`):** FIPS 180-4 SHA-256, RFC 2104 HMAC-SHA256, anti-replay `SecureChannel`, LoRa epoch key rotation |
| [`crates/ferrum-forensics`](./crates/ferrum-forensics/src/lib.rs) | `#![no_std]` | **Pillar 4 (`PROVE`):** SHA-256 hash-chained evidence sealing (`HashChain`, `verify_chain`) and a bounded `StoreForwardQueue` |
| [`crates/ferrum-triage`](./crates/ferrum-triage/src/lib.rs) | `#![no_std]` | **Pillar 3/4 (`SURVIVE`):** 16-bin `RssiHistogram`, sliding `RateWindow`, Shannon channel entropy, 12-byte compressed `FeatureVector` for the LoRa `SX1262` uplink |
| [`crates/ferrum-sim`](./crates/ferrum-sim/src/lib.rs) | `std` | **The simulated world:** seeded `RfWorld`, log-distance path loss and trilateration, six adversary models, named scenario timelines, `SimController`, and the sim implementations of the `ferrum-hal` traits. A golden test pins the flagship run bit-for-bit |
| [`crates/ferrum-brain`](./crates/ferrum-brain/src/main.rs) | `std` | Library + binary. The `Orchestrator` composes the full per-tick pipeline; an axum server streams `SwarmSnapshot` JSON over WebSocket and accepts `OperatorCommand`s; `--headless` prints the narrative |

`ferrum-ids`, `ferrum-sim` and `ferrum-brain` are the host side (`std`). Everything else is `#![no_std]` and is meant to be compiled into both the simulator and the firmware.

The full design, per-tick data flow and policy table are in [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## The reference hardware

- **Control plane:** Raspberry Pi 5 (8GB) running the Ferrum + Laya System-1 / System-2 engine
- **Operator deck:** ClockworkPi uConsole with HackerGadgets AIOv2 (`RTL-SDR` sub-GHz and `LoRa SX1262`)
- **Node 1 (`0x01`):** ESP32-WROOM + dual nRF24L01+ shield (126-channel `2400-2525 MHz` ghost-band and ESB / MouseJack sniffer, decoy SoftAP / BLE honeypot)
- **Node 2 (`0x02`):** ESP32-C5 (RISC-V), dual-band Wi-Fi 6 `Ch 36-165` plus `802.15.4`
- **Node 3 (`0x03`):** Seeed XIAO ESP32-S3 Sense (8MB PSRAM): 2.4 GHz deep PCAP ring, BLE GATT auditor, `OV2640` camera and `PDM` mic

In Phase 1 these are *modelled*: the three nodes are the agents above running against simulated PHYs, and the Pi / uConsole roles are played by `ferrum-brain` on your machine.

---

## Phase 2 (real hardware)

Phase 2 replaces the simulated PHYs with `esp-hal` drivers and flashes the same agent and decision crates onto the boards. The groundwork is already in the tree:

- the node agents and `ferrum-laya` are `#![no_std]` and generic over `ferrum-hal`;
- CI builds the Laya System-1 core for `riscv32imac-unknown-none-elf` (`cargo build -p ferrum-laya --no-default-features --target riscv32imac-unknown-none-elf`);
- HAL transports return `Result`, and each agent degrades to `Offline` on error, which matters on a real radio and never happens in the sim.

What is **not** built yet: the `esp-hal` implementations of `SpectrumScanner` / `PacketSniffer` / `Transport` / `Clock` per board, the ESP-NOW link to a Pi 5, and the firmware binaries. Phase 2 gets its own spec; the Phase 1 design is in [`docs/superpowers/specs/`](./docs/superpowers/specs/2026-10-29-ferret-living-swarm-design.md).

> Ferret is a defensive research platform. Only monitor spectrum and networks you own or are authorised to assess.
