//! `ferrum-brain` — Raspberry Pi 5 (8GB) Ferrum Adaptive Control Plane + Laya Decision Engine.
//!
//! The live swarm runs off a single [`Orchestrator`](ferrum_brain::orchestrator::Orchestrator):
//! one `tick()` advances the seeded RF world, drives the three trait-driven node agents through
//! the sim PHYs, runs the two-tier Laya engine, the IDS, the deception tripwires, the
//! authenticated command channel, forensic sealing and triage, and assembles a `SwarmSnapshot`.
//!
//! This binary just parses flags and plays the tactical narrative:
//!
//! ```text
//! cargo run -p ferrum-brain
//! cargo run -p ferrum-brain -- --headless --scenario red-team-incursion --seed 42 --ticks 300
//! ```
//!
//! Nodes:
//! 1. **ESP32-WROOM + Dual nRF24L01+:** 126-Ch 2.4 GHz + Ghost Band + ESB/MouseJack + BT/BLE.
//! 2. **ESP32-C5 (RISC-V):** 5 GHz Wi-Fi 6 + 802.15.4 (Zigbee/Thread).
//! 3. **XIAO ESP32-S3 Sense (8 MB PSRAM):** 2.4 GHz Deep PCAP + Active BLE GATT + OV2640 Cam/PDM Mic.
//! 4. **Operator Deck (uConsole + AIOv2):** Sub-GHz (RTL-SDR + LoRa SX1262) + Tactical HUD.

use ferrum_brain::orchestrator::run_headless;

/// Parsed command line for the headless narrative.
struct Args {
    scenario: String,
    seed: u64,
    ticks: Option<u64>,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            scenario: "red-team-incursion".to_string(),
            seed: 42,
            ticks: None,
        }
    }
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            // `--headless` is the only mode today; accept it for forward-compatibility.
            "--headless" => {}
            "--scenario" => {
                args.scenario = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--scenario needs a value"))?;
            }
            "--seed" => {
                args.seed = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--seed needs a value"))?
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid --seed: {e}"))?;
            }
            "--ticks" => {
                args.ticks = Some(
                    it.next()
                        .ok_or_else(|| anyhow::anyhow!("--ticks needs a value"))?
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid --ticks: {e}"))?,
                );
            }
            other => anyhow::bail!("unknown argument {other:?}"),
        }
    }
    Ok(args)
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    run_headless(args.seed, &args.scenario, args.ticks)
}
