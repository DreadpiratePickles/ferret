# Ferret demo: the 60-second walkthrough

A guided tour of the flagship `red-team-incursion` scenario, then a round of operator controls. Everything below is what the dashboard shows with the defaults (seed `42`, 10 Hz); the run is deterministic, so you will see the same thing every time.

## Setup

```bash
cargo run -p ferrum-brain          # same as: just demo
```

Open **<http://127.0.0.1:8787/>** *immediately after the server prints its URL*. The scenario clock starts when the server starts, and the timeline plays **once**: it lasts 22 seconds of events, after which the last intruders stay in place. To replay from the top, restart the server (see [Gotchas](#gotchas)).

Prefer a terminal? `cargo run -p ferrum-brain -- --headless` prints the same story as text, ending in a summary line (300 ticks, 80 sealed evidence blocks, chain VALID, 300 sealed / 300 accepted / 0 rejected commands).

## Part 1: the scripted incursion (0:00 - 0:30)

Watch the **Laya decision card**, the **spectrum waterfall**, the **radar**, and the **four pillars** together.

| Time | What the adversary does | What the swarm shows |
| :--- | :--- | :--- |
| **0:00 - 0:05** Baseline | Nothing. The air is quiet. | `WIDE_RECON` at ~99% confidence, nRF mode `SPLIT_SPECTRUM_WATERFALL`. Waterfall is a flat noise floor. All pillars idle; S3 camera / mic are `OFF` and the PCAP ring holds the bulk of PSRAM. |
| **0:05 - 0:10** MouseJack + ghost band | A wireless-keyboard injector hops across nRF channels 96-99 while a covert carrier sits at nRF channel 98 (2498 MHz, inside the 2485-2525 MHz ghost band). | The waterfall lights up in the upper part of the nRF range. DETECT fires `ESB/HID INJECTION ATTEMPT` and `GHOST-BAND COVERT TRANSMITTER` (both HIGH, MITRE-tagged). Laya switches to `TRIANGULATE_LOCK` (~98%) with nRF mode `HUNTER_KILLER_ESB`, driven by the `ghost_esb` signal. The radar places the target near the WROOM anchor. |
| **0:10 - 0:17** 5 GHz evil twin + deauth | A rogue AP appears on 5 GHz channel 36 and blasts a deauth burst for its first 4 seconds. | The C5 card shows the 5 GHz channel 36 contact (around -45 dBm) and its deauth counter jumping to about 12 per tick for the first four seconds. That crosses System-1's deauth threshold (more than 5 per window) without reaching the IDS flood rule (more than 50), so Laya re-tasks to **`SURGICAL_CAPTURE`** (~100%, driven by `deauth_eapol`) at 0:10.1. When the burst ends at 0:14 the swarm relaxes back to `WIDE_RECON` while the rogue AP keeps beaconing. |
| **0:17 - 0:22** Layer-1 jammer | A wideband jammer next to the WROOM (centred on nRF channel 45, about -48 dBm at the WROOM) pegs more than 40 nRF channels. | The waterfall floods. DETECT raises `LAYER-1 RF JAMMING` (HIGH), and the decision card flips to **`FLOOD_JAM_SURVIVAL`** (~100%, nRF mode `LAYER1_JAM_TRIAGE`, driven by `jam_ratio`) at 0:17.1: System-1 and the High `FR-JAM-001` detection agree on `FLOOD_JAM_SURVIVAL`, so there is no escalation marker in this phase (the card reads `system1`). The swarm does not lock down because the jam is survivable and, being below the close-range threshold, does not trip the decoy. Camera and mic stay `OFF` and the PCAP ring keeps its full PSRAM share. The LoRa queue climbs until it is full (32), because the jammed 2.4 GHz link is treated as contended and the out-of-band uplink backs up. |
| **0:22 - 0:30** Close-range intruder + sub-GHz + BLE rotation | A Bluetooth skimmer appears next to the S3, a 433 MHz replay burst repeats, and a BLE implant starts rotating its MAC. | The jam clears and the skimmer trips the BLE canary decoy (`DECEIVE: decoy 0x0007 tripped`). That is a CRITICAL `HONEYPOT` detection, so at 0:22.1 System-2 **escalates to `FORENSIC_LOCKDOWN`** (99%) and holds it for the rest of the run: the escalation marker lights up, the S3 PSRAM bar re-partitions (PCAP ring shrinks, camera and mic FFT regions appear, `CAM/MIC` goes on), the LoRa queue drains, and PROVE starts sealing evidence: watch the **forensic hash chain** grow and stay `CHAIN VALID`. System-1's own pick underneath is `SENTINEL_CORRELATE` (~99%, driven by `proximity` and `subghz`). The radar target snaps to the S3 corner, and the sub-GHz burst shows on the waterfall and on the operator-deck view. |

**What to point out:** the decision is never a black box. The card shows the full six-way score distribution, the top three signals behind the choice, and when System-2 overrules System-1 it says so.

## Part 2: take the controls (0:30 - 1:00)

The control panel is above the main grid. Try these in order.

1. **Inject a jammer (0:30).** Click **2.4GHz Jammer**. A `jammer #N` tag appears under **Active**, the waterfall floods within a tick, and the pillars react. This works in any scenario, including `quiet`.
2. **Force a policy (0:38).** Pick `WIDE_RECON (0x01)` in the **Force** dropdown and click **Force Policy**. The swarm is told to relax while the jammer is still screaming. Notice that the IDS **keeps detecting**: the override changes what the swarm *does*, not what it *sees*. Click **Release Override** to hand control back to Laya.
3. **Pause (0:45).** Click **Pause**. The simulation freezes mid-attack, which is the moment to screenshot or to read the rationale and the hash chain at leisure. Click it again (it reads **Resume**) to continue.
4. **Clear one adversary.** Click the `✕` on an adversary tag to remove just that one. Laya's hysteresis means the policy does not flap: a rival must lead by 20 points, or for 3 consecutive ticks, before it replaces the incumbent.
5. **Switch to `quiet` (0:52).** Click **quiet** under **Scenario**. All adversaries are cleared at once and, within a few ticks, the swarm settles back toward `WIDE_RECON` over a flat waterfall. The forensic chain is retained: evidence you have sealed stays sealed.

Other controls worth a click: **MouseJack ESB**, **5GHz Evil-Twin**, **BLE Implant**, **Sub-GHz Replay** and **BT Skimmer** inject the other adversaries; the **Tick Hz** buttons (1 / 2 / 5 / 10 / 20) change how finely the simulation is stepped.

## Gotchas

- **Replaying the scenario.** The timeline is keyed to simulated time since the server started. Clicking **red-team-incursion** after it has already run past its events does not replay it from the top: every due event fires at once, so only the three late adversaries (BT skimmer, sub-GHz replay, BLE implant) remain. For a clean re-run, restart `cargo run -p ferrum-brain`.
- **Tick Hz is resolution, not speed.** Each tick advances simulated time by `1000 / hz` ms, so the scenario runs in roughly real time at any rate. Lower rates give coarse, chunky frames; higher rates give smooth ones. Use **Pause** to slow down.
- **Port already in use.** The server binds `127.0.0.1:8787`; pass `--port <n>` to use another.
- **Determinism.** Same `--seed` and `--scenario` give the same run. Change `--seed` to see different noise and MAC rotations with the same storyline.
