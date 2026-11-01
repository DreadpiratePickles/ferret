//! `Orchestrator` — the live tick loop that composes the whole swarm.
//!
//! One [`Orchestrator::tick`] advances the simulated RF world (scenario events + active
//! adversaries + `world.step`), feeds the three trait-driven node agents through the sim PHYs,
//! runs the two-tier Laya decision engine, the IDS, the deception tripwires, the authenticated
//! command channel, forensic sealing and triage, then assembles a [`SwarmSnapshot`].
//!
//! # Data flow for one tick (spec §7)
//! advance sim → each `agent.tick()` reads the world via its sim PHYs →
//! [`signals_from`] → [`LayaEngine::system1`] → [`IdsEngine::evaluate`] →
//! [`LayaEngine::system2`] → build [`FerrumPolicyCmd`] → [`SecureChannel::seal`] → node-side
//! `open` (verify) → `agent.apply_policy_cmd` → on `ForensicLockdown` seal a PCAP block into the
//! [`HashChain`]; always maintain a [`FeatureVector`] + LoRa [`StoreForwardQueue`] → assemble the
//! snapshot. A secure-open failure (replay / bad MAC) is recorded as an [`EventView`], never a panic.
//!
//! # Sim ownership
//! Task 7's `SimController` owns `RfWorld` by value; Task 6's sim PHYs need a shared
//! `Rc<RefCell<RfWorld>>`. The orchestrator owns the shared world and drives the scenario /
//! adversaries with [`ferrum_sim::ScenarioDriver`] (the bookkeeping extracted from `SimController`,
//! so no scenario/adversary logic is duplicated). Borrows of the world are always scoped — never
//! held across an `agent.tick()` — to avoid a `RefCell` double-borrow panic.

use std::cell::RefCell;
use std::rc::Rc;

use ferrum_deceive::{BleDecoyBeacon, DecoyKind, FakeSoftAp, TripwireEvent, TripwireKind};
use ferrum_forensics::{
    verify_chain, EvidenceRecord, HashChain, StoreForwardQueue, EVIDENCE_BLOCK_BYTES,
};
use ferrum_hal::NodeStatus;
use ferrum_ids::IdsEngine;
use ferrum_laya::{signals_from, LayaEngine};
use ferrum_proto::{FerrumPolicyCmd, NodeId, NodeTelemetry, PolicyMode};
use ferrum_secure::{OpenError, SealedPolicyFrame, SecureChannel};
use ferrum_sim::phys::ANCHORS;
use ferrum_sim::{
    scenario_by_name, trilaterate, Adversary, AdversaryId, RfWorld, ScenarioDriver, SharedWorld,
    SimClock, SimScanner, SimSniffer, SimTransport,
};
use ferrum_triage::{flags, FeatureVector, RssiHistogram};

use ferrum_c5_scout::C5Agent;
use ferrum_s3_sense::S3Agent;
use ferrum_wroom_nrf::WroomAgent;

use crate::snapshot::{
    AdversaryView, DecisionView, EventView, ForensicsView, NodeView, OperatorCommand, PillarView,
    PsramView, RadarView, ScenarioView, SecureView, SpectrumView, SwarmSnapshot,
};

/// 32-byte swarm root key (provisioned at manufacturing, rotated per LoRa epoch).
const SWARM_KEY: [u8; 32] = [0xFE; 32];
/// Capacity of the LoRa store-and-forward queue (one `FeatureVector` per tick under contention).
const LORA_CAP: usize = 32;
/// RPD-pegged nRF channel count above which the 2.4 GHz link is considered jammed (LoRa contended).
const JAM_CHANNELS: u8 = 40;
/// A node's anomaly RSSI stronger than this is "close range" (proximity actuation threshold, dBm).
const CLOSE_RANGE_DBM: i8 = -42;
/// Default tick rate (Hz): the flagship scenario timeline is authored at 10 Hz (100 ms per tick).
const DEFAULT_TICK_HZ: u8 = 10;

type Scanner = SimScanner;
type Sniffer = SimSniffer;
type Txport = SimTransport;
type ClockT = SimClock;
type Wroom = WroomAgent<Scanner, Sniffer, Txport, ClockT>;
type C5 = C5Agent<Scanner, Sniffer, Txport, ClockT>;
type S3 = S3Agent<Scanner, Sniffer, Txport, ClockT>;

/// Live control plane: advances the sim, the agents and the Laya/IDS/secure/forensic pipeline.
pub struct Orchestrator {
    world: SharedWorld,
    driver: ScenarioDriver,
    wroom: Wroom,
    c5: C5,
    s3: S3,
    laya: LayaEngine,
    ids: IdsEngine,

    // Pillar 2 (DECEIVE): a standing decoy AP + BLE canary.
    decoy_ap: FakeSoftAp,
    ble_decoy: BleDecoyBeacon,

    // Pillar 3 (DEFEND): authenticated command channel (brain seals, node opens).
    brain_ch: SecureChannel,
    node_ch: SecureChannel,
    secure: SecureView,

    // Pillar 4 (PROVE): forensic hash chain + triage store-and-forward.
    chain: HashChain,
    records: Vec<EvidenceRecord>,
    lora_queue: StoreForwardQueue<[u8; FeatureVector::SIZE], LORA_CAP>,
    rssi_hist: RssiHistogram,

    tick_no: u64,
    tripwire_trips: u32,

    // Run control (reported in the scenario view / honoured by `tick`).
    scenario_name: String,
    tick_hz: u8,
    paused: bool,
    forced_policy: Option<PolicyMode>,

    pending_events: Vec<EventView>,
    last_snapshot: Option<SwarmSnapshot>,
}

/// Four sim PHYs for one node, all sharing the same world handle.
fn phys(world: &SharedWorld, node: NodeId) -> (Scanner, Sniffer, Txport, ClockT) {
    (
        SimScanner::new(world.clone(), node),
        SimSniffer::new(world.clone(), node),
        SimTransport::new(world.clone(), node),
        SimClock::new(world.clone()),
    )
}

/// A quiet telemetry stand-in for a node that produced no telemetry this tick (keeps the IDS /
/// signal math total even when a transport is down — the sim transport is infallible, so this is
/// only a safety net).
fn quiet_tele(node: NodeId) -> NodeTelemetry {
    NodeTelemetry {
        node_id: node as u8,
        active_policy: PolicyMode::WideRecon as u8,
        sub_policy: 0,
        primary_channel: 0,
        cpu_load_pct: 0,
        free_sram_kb: 0,
        free_psram_kb: 0,
        ringbuf_drops: 0,
        wifi_mgmt_fps: 0,
        deauth_disassoc_cnt: 0,
        eapol_handshake_cnt: 0,
        ble_adv_fps: 0,
        bt_classic_inq_cnt: 0,
        ghost_band_hits: 0,
        esb_hid_frames: 0,
        zigbee_pan_frames: 0,
        peak_anomaly_rssi: -100,
        crc8: 0,
    }
}

fn tele_of(status: NodeStatus) -> Option<NodeTelemetry> {
    match status {
        NodeStatus::Online(t) => Some(t),
        NodeStatus::Offline => None,
    }
}

/// Map an [`Adversary::name`] label to a default-positioned adversary for `InjectAdversary`.
fn adversary_by_name(name: &str) -> Option<Adversary> {
    Some(match name {
        "jammer" => Adversary::jammer((1.5, 1.0), 62),
        "evil-twin-deauth" => Adversary::evil_twin_deauth((5.0, 1.5), 36, 4_000),
        "mousejack-esb" => Adversary::mousejack((1.0, 1.5), 96, 4, Some(98)),
        "ble-rotating-implant" => Adversary::ble_rotating_implant((2.4, 4.0), 3_000),
        "subghz-replay" => Adversary::subghz_replay(433, 2_000, 600),
        "bt-skimmer" => Adversary::bt_skimmer((3.0, 4.6)),
        _ => return None,
    })
}

impl Orchestrator {
    /// Build an orchestrator seeded with `seed`, playing `scenario`.
    ///
    /// Returns an error for an unknown scenario name (see [`ferrum_sim::SCENARIO_NAMES`]).
    pub fn new(seed: u64, scenario: &str) -> anyhow::Result<Self> {
        if scenario_by_name(scenario).is_none() {
            anyhow::bail!(
                "unknown scenario {scenario:?}; known: {:?}",
                ferrum_sim::SCENARIO_NAMES
            );
        }
        let world: SharedWorld = Rc::new(RefCell::new(RfWorld::new(seed)));

        let (sc, sn, tx, ck) = phys(&world, NodeId::WroomDualNrf);
        let wroom = WroomAgent::new(sc, sn, tx, ck);
        let (sc, sn, tx, ck) = phys(&world, NodeId::Esp32C5Scout);
        let c5 = C5Agent::new(sc, sn, tx, ck);
        let (sc, sn, tx, ck) = phys(&world, NodeId::XiaoS3Sense);
        let s3 = S3Agent::new(sc, sn, tx, ck);

        let decoy_ap = FakeSoftAp::new(
            "Corp-Guest-IoT-Setup",
            6,
            [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
        );
        let ble_decoy = BleDecoyBeacon {
            kind: DecoyKind::IBeacon,
            canary_id: 0x0007,
            uuid: [0x11; 16],
            major: 1,
            minor: 1,
            tx_power_dbm: -59,
        };

        Ok(Self {
            driver: ScenarioDriver::new(scenario),
            world,
            wroom,
            c5,
            s3,
            laya: LayaEngine::new(),
            ids: IdsEngine::default(),
            decoy_ap,
            ble_decoy,
            brain_ch: SecureChannel::new(SWARM_KEY),
            node_ch: SecureChannel::new(SWARM_KEY),
            secure: SecureView::default(),
            chain: HashChain::new(NodeId::XiaoS3Sense),
            records: Vec::new(),
            lora_queue: StoreForwardQueue::new(),
            rssi_hist: RssiHistogram::new(),
            tick_no: 0,
            tripwire_trips: 0,
            scenario_name: scenario.to_string(),
            tick_hz: DEFAULT_TICK_HZ,
            paused: false,
            forced_policy: None,
            pending_events: Vec::new(),
            last_snapshot: None,
        })
    }

    /// Read-only view of the authenticated-channel counters.
    pub fn secure_counters(&self) -> SecureView {
        self.secure.clone()
    }

    /// Seal a command on the brain channel (the authenticated downlink). Exposed so an operator /
    /// test can obtain a real sealed frame to replay or tamper with via [`feed_sealed_command`].
    ///
    /// [`feed_sealed_command`]: Self::feed_sealed_command
    pub fn seal_command(&mut self, cmd: &FerrumPolicyCmd) -> SealedPolicyFrame {
        self.secure.frames_sealed = self.secure.frames_sealed.saturating_add(1);
        self.brain_ch.seal(cmd)
    }

    /// Run a sealed frame through the node-side verifier, exactly as the tick loop does. A
    /// replay / bad-MAC / corrupt frame is counted and logged as an alert event (surfaced in the
    /// next snapshot); the swarm keeps running. A valid frame is applied to all three agents.
    pub fn feed_sealed_command(&mut self, frame: SealedPolicyFrame) {
        self.open_and_apply(&frame);
    }

    /// Node-side open + apply with full accounting; never panics.
    fn open_and_apply(&mut self, frame: &SealedPolicyFrame) {
        match self.node_ch.open(frame) {
            Ok(cmd) => {
                self.secure.frames_accepted = self.secure.frames_accepted.saturating_add(1);
                self.wroom.apply_policy_cmd(&cmd);
                self.c5.apply_policy_cmd(&cmd);
                self.s3.apply_policy_cmd(&cmd);
            }
            Err(e) => {
                let (msg, counter): (String, &mut u32) = match e {
                    OpenError::BadMac => (
                        format!(
                            "SECURE: rejected forged command (bad MAC, seq {})",
                            frame.seq
                        ),
                        &mut self.secure.rejected_bad_mac,
                    ),
                    OpenError::Replay => (
                        format!("SECURE: rejected replayed command (seq {})", frame.seq),
                        &mut self.secure.rejected_replay,
                    ),
                    OpenError::CorruptPayload => (
                        format!(
                            "SECURE: rejected corrupt command payload (seq {})",
                            frame.seq
                        ),
                        &mut self.secure.rejected_bad_mac,
                    ),
                };
                *counter = counter.saturating_add(1);
                self.pending_events.push(EventView {
                    tick: self.tick_no,
                    level: "alert",
                    message: msg,
                });
            }
        }
    }

    /// Apply an operator command (dashboard → brain).
    pub fn apply_command(&mut self, cmd: OperatorCommand) {
        match cmd {
            OperatorCommand::InjectAdversary(name) => match adversary_by_name(&name) {
                Some(a) => {
                    let id = self.driver.inject(a);
                    self.log(
                        "info",
                        format!("operator injected {name} as adversary {}", id.0),
                    );
                }
                None => self.log("warn", format!("unknown adversary {name:?}")),
            },
            OperatorCommand::ClearAdversary(id) => {
                {
                    let mut w = self.world.borrow_mut();
                    self.driver.clear(&mut w, AdversaryId(id));
                }
                self.log("info", format!("operator cleared adversary {id}"));
            }
            OperatorCommand::ForcePolicy(0) => {
                self.forced_policy = None;
                self.log(
                    "info",
                    "operator released forced-policy override".to_string(),
                );
            }
            OperatorCommand::ForcePolicy(byte) => match PolicyMode::from_u8(byte) {
                Some(p) => {
                    self.forced_policy = Some(p);
                    self.log("warn", format!("operator forced policy {}", p.as_str()));
                }
                None => self.log("warn", format!("invalid forced policy byte 0x{byte:02X}")),
            },
            OperatorCommand::SetScenario(name) => match scenario_by_name(&name) {
                Some(_) => {
                    self.world.borrow_mut().clear_emitters();
                    self.driver = ScenarioDriver::new(&name);
                    self.scenario_name = name.clone();
                    self.log("info", format!("operator set scenario {name}"));
                }
                None => self.log("warn", format!("unknown scenario {name:?}")),
            },
            OperatorCommand::Pause => {
                self.paused = true;
                self.log("info", "operator paused the simulation".to_string());
            }
            OperatorCommand::Resume => {
                self.paused = false;
                self.log("info", "operator resumed the simulation".to_string());
            }
            OperatorCommand::SetTickHz(hz) => {
                // Clamp to a sane minimum; 0 Hz would stall the loop / divide by zero.
                self.tick_hz = hz.max(1);
                self.log(
                    "info",
                    format!("operator set tick rate to {} Hz", self.tick_hz),
                );
            }
        }
    }

    fn log(&mut self, level: &'static str, message: String) {
        self.pending_events.push(EventView {
            tick: self.tick_no,
            level,
            message,
        });
    }

    /// Advance the whole swarm by one tick and return the assembled snapshot.
    pub fn tick(&mut self) -> SwarmSnapshot {
        self.tick_no = self.tick_no.saturating_add(1);

        if self.paused {
            let mut snap = self
                .last_snapshot
                .clone()
                .unwrap_or_else(|| SwarmSnapshot::empty(self.tick_no));
            snap.tick = self.tick_no;
            snap.scenario = self.scenario_view();
            snap.events = std::mem::take(&mut self.pending_events);
            self.last_snapshot = Some(snap.clone());
            return snap;
        }

        let dt_ms = (1000u64 / u64::from(self.tick_hz.max(1))).max(1);

        // 1. Advance the simulated world (scoped borrow — dropped before any agent tick).
        {
            let mut w = self.world.borrow_mut();
            self.driver.advance(&mut w, dt_ms);
        }
        let subghz = self.driver.subghz_burst_mhz();

        // 2. Each agent reads the stepped world via its sim PHYs.
        let wroom_t = tele_of(self.wroom.tick());
        let c5_t = tele_of(self.c5.tick());
        let s3_t = tele_of(self.s3.tick());

        let wt = wroom_t.unwrap_or_else(|| quiet_tele(NodeId::WroomDualNrf));
        let ct = c5_t.unwrap_or_else(|| quiet_tele(NodeId::Esp32C5Scout));
        let st = s3_t.unwrap_or_else(|| quiet_tele(NodeId::XiaoS3Sense));

        // 3. rpd_jammed: nRF channels reading RPD-hot in the WROOM's latest sweep.
        let rpd_jammed = (0u8..126)
            .filter(|&c| self.wroom.spectrum().get_channel(c))
            .count()
            .min(u8::MAX as usize) as u8;

        // 4. Telemetry → signals → System-1.
        let signals = signals_from(&wt, &ct, &st, rpd_jammed, subghz);
        let s1 = self.laya.system1(&signals);

        // 5. Deception: synthesize a tripwire when an intruder is close / associating with a decoy.
        let close_range = self
            .driver
            .active()
            .iter()
            .any(|(_, a)| matches!(a, Adversary::BtSkimmer { .. }))
            || st.peak_anomaly_rssi > CLOSE_RANGE_DBM
            || wt.peak_anomaly_rssi > CLOSE_RANGE_DBM;
        let mut trips: Vec<TripwireEvent> = Vec::new();
        if close_range {
            self.tripwire_trips = self.tripwire_trips.saturating_add(1);
            let ts = (self.world.borrow().time_ms() / 1000) as u32;
            let rssi = st.peak_anomaly_rssi.max(wt.peak_anomaly_rssi);
            trips.push(TripwireEvent::new(
                self.ble_decoy.canary_id,
                TripwireKind::Association,
                [0x64, 0xA2, 0x11, 0x09, 0xBC, 0x01],
                rssi,
                ts,
                NodeId::WroomDualNrf as u8,
            ));
            // Keep the decoy beacon sequence advancing (records interactions while lured).
            let _ = self.decoy_ap.build_beacon_frame();
            self.log(
                "alert",
                format!(
                    "DECEIVE: decoy 0x{:04X} tripped at {rssi}dBm",
                    self.ble_decoy.canary_id
                ),
            );
        }

        // 6. IDS evaluation over the telemetry + tripwires.
        let detections = self.ids.evaluate(&wt, &ct, &st, rpd_jammed, &trips);

        // 7. System-2 escalation, then an optional operator forced-policy override.
        let mut decision = self.laya.system2(s1, &detections);
        if let Some(forced) = self.forced_policy {
            decision.selected_policy = forced;
        }
        let escalated = decision.selected_policy != decision.distribution[0].0;
        let selected = decision.selected_policy;

        // 8. Build the policy command and dispatch it over the authenticated channel.
        let cmd = FerrumPolicyCmd {
            target_node: NodeId::Broadcast as u8,
            policy_mode: selected as u8,
            dual_nrf_mode: decision.selected_nrf_policy as u8,
            pinned_channels: [0, 6, 149, 0],
            dwell_time_ms: if selected == PolicyMode::SurgicalCapture {
                500
            } else {
                35
            },
            cpu_freq_mhz: if selected == PolicyMode::WideRecon {
                80
            } else {
                240
            },
            s3_psram_pcap_quota_kb: if decision.trigger_s3_camera_mic {
                4096
            } else {
                7424
            },
            crc8: 0,
        };
        let frame = self.seal_command(&cmd);
        self.open_and_apply(&frame);

        // 9. Forensic sealing on lockdown: freeze a PCAP block into the hash chain.
        if selected == PolicyMode::ForensicLockdown {
            let mut block = [0u8; EVIDENCE_BLOCK_BYTES];
            // A deterministic stand-in for the frozen S3 PCAP window (tick + rssi as a marker).
            block[0] = self.tick_no as u8;
            block[1] = st.peak_anomaly_rssi as u8;
            block[2] = rpd_jammed;
            let ts = (self.world.borrow().time_ms() / 1000) as u32;
            let rec = self.chain.seal(&block, ts, selected as u8);
            self.records.push(rec);
        }

        // 10. Triage: maintain a compressed FeatureVector + LoRa store-and-forward queue.
        self.rssi_hist
            .update(st.peak_anomaly_rssi.max(wt.peak_anomaly_rssi));
        let mut alarm_flags = 0u8;
        if rpd_jammed > JAM_CHANNELS {
            alarm_flags |= flags::JAM;
        }
        if ct
            .deauth_disassoc_cnt
            .saturating_add(st.deauth_disassoc_cnt)
            > 40
        {
            alarm_flags |= flags::DEAUTH_FLOOD;
        }
        if wt.ghost_band_hits > 0 {
            alarm_flags |= flags::GHOST_BAND;
        }
        if wt.esb_hid_frames > 0 {
            alarm_flags |= flags::ESB_HID;
        }
        let fv = FeatureVector {
            mean_rssi_q: self.rssi_hist.mean_q(),
            rssi_std_q: self.rssi_hist.stdev_q(),
            mgmt_rate_q: ct.wifi_mgmt_fps.saturating_mul(4),
            deauth_rate_q: ct
                .deauth_disassoc_cnt
                .saturating_add(st.deauth_disassoc_cnt)
                .saturating_mul(4),
            entropy_q: 0,
            alarm_flags,
            node_id: NodeId::Esp32C5Scout as u8,
            crc8: 0,
        };
        self.lora_queue.push(fv.to_bytes());
        let link_contended = rpd_jammed > JAM_CHANNELS;
        if !link_contended {
            // Link is healthy: flush the backlog over the out-of-band LoRa SX1262 uplink.
            while self.lora_queue.pop().is_some() {}
        }
        let lora_depth = self.lora_queue.len().min(u8::MAX as usize) as u8;

        // 11. Assemble the snapshot (after apply, so node resource views reflect the response).
        let snap = self.assemble(
            &wt,
            wroom_t.is_some(),
            &ct,
            c5_t.is_some(),
            &st,
            s3_t.is_some(),
            &decision,
            escalated,
            selected,
            &detections,
            subghz,
            lora_depth,
        );
        self.last_snapshot = Some(snap.clone());
        snap
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        &mut self,
        wt: &NodeTelemetry,
        wroom_online: bool,
        ct: &NodeTelemetry,
        c5_online: bool,
        st: &NodeTelemetry,
        s3_online: bool,
        decision: &ferrum_laya::TypedDecision,
        escalated: bool,
        selected: PolicyMode,
        detections: &[ferrum_ids::Detection],
        subghz: Option<u16>,
        lora_depth: u8,
    ) -> SwarmSnapshot {
        let wroom_node = if wroom_online {
            NodeView::from_telemetry(wt)
        } else {
            NodeView::offline(NodeId::WroomDualNrf)
        };
        let c5_node = if c5_online {
            NodeView::from_telemetry(ct)
        } else {
            NodeView::offline(NodeId::Esp32C5Scout)
        };
        let s3_node = if s3_online {
            NodeView::from_telemetry(st).with_psram(PsramView::from_partition(
                &self.s3.psram(),
                self.s3.camera_powered(),
                self.s3.pdm_mic_active(),
            ))
        } else {
            NodeView::offline(NodeId::XiaoS3Sense)
        };

        // Radar: trilaterate from the three anchor RSSIs; only show a target when one is audible.
        let anchor_rssi = [
            wt.peak_anomaly_rssi,
            ct.peak_anomaly_rssi,
            st.peak_anomaly_rssi,
        ];
        let target = if anchor_rssi.iter().any(|&r| r > -80) {
            Some(trilaterate(anchor_rssi))
        } else {
            None
        };
        let radar = RadarView::new(target, ANCHORS);

        // Spectrum: the WROOM's nRF sweep + the Wi-Fi channels the C5 / S3 are tuned to.
        let wifi5 = if c5_online && ct.primary_channel >= 36 {
            vec![(ct.primary_channel, ct.peak_anomaly_rssi)]
        } else {
            Vec::new()
        };
        let wifi24 = if s3_online && st.primary_channel >= 1 && st.primary_channel <= 14 {
            vec![(st.primary_channel, st.peak_anomaly_rssi)]
        } else {
            Vec::new()
        };
        let spectrum = SpectrumView::new(self.wroom.spectrum(), wifi24, wifi5, subghz);

        let chain_valid = verify_chain(NodeId::XiaoS3Sense, &self.records);
        let forensics = ForensicsView::from_records(&self.records, chain_valid);

        let scenario = self.scenario_view();

        SwarmSnapshot {
            tick: self.tick_no,
            nodes: [wroom_node, c5_node, s3_node],
            decision: DecisionView::from_decision(decision, escalated),
            radar,
            spectrum,
            pillars: PillarView::derive(
                selected,
                detections,
                self.tripwire_trips,
                self.records.len() as u32,
            ),
            detections: detections.iter().map(Into::into).collect(),
            forensics,
            secure: self.secure.clone(),
            lora_queue_depth: lora_depth,
            scenario,
            events: std::mem::take(&mut self.pending_events),
        }
    }

    fn scenario_view(&self) -> ScenarioView {
        ScenarioView {
            name: self.scenario_name.clone(),
            elapsed_ms: self.world.borrow().time_ms(),
            paused: self.paused,
            tick_hz: self.tick_hz,
            active_adversaries: self
                .driver
                .active()
                .iter()
                .map(|(id, a)| AdversaryView {
                    id: id.0,
                    name: a.name(),
                })
                .collect(),
        }
    }
}

/// Run the tactical narrative headless, printing one block per tick plus a closing summary.
///
/// `ticks` defaults to the scenario length plus a short tail when `None`.
pub fn run_headless(seed: u64, scenario: &str, ticks: Option<u64>) -> anyhow::Result<()> {
    let mut orch = Orchestrator::new(seed, scenario)?;
    let dt_ms = 1000u64 / u64::from(DEFAULT_TICK_HZ);
    let total = ticks.unwrap_or_else(|| {
        let scenario_ms = orch.driver.scenario().last_event_ms();
        (scenario_ms / dt_ms) + 80
    });

    println!("================================================================================");
    println!(" FERRUM CYBERSWARM — AI-ADAPTIVE UNIKERNEL CONTROL PLANE (Pi 5 + 3x ESP + uConsole)");
    println!(" Orchestrator | seed {seed} | scenario {scenario:?} | {total} ticks @ {DEFAULT_TICK_HZ} Hz");
    println!("================================================================================");

    let (mut detect_ticks, mut lockdown_ticks) = (0u64, 0u64);
    let mut last_policy = String::new();

    for _ in 0..total {
        let s = orch.tick();

        if !s.detections.is_empty() {
            detect_ticks += 1;
        }
        if s.decision.selected_policy == PolicyMode::ForensicLockdown.as_str() {
            lockdown_ticks += 1;
        }

        let elapsed_s = s.scenario.elapsed_ms as f32 / 1000.0;
        let drivers: Vec<String> = s
            .decision
            .top_signals
            .iter()
            .filter(|(_, share)| *share > 0)
            .map(|(k, share)| format!("{k}={share}%"))
            .collect();
        let policy_changed = s.decision.selected_policy != last_policy;
        let marker = if policy_changed { "»" } else { " " };
        last_policy = s.decision.selected_policy.to_string();

        println!(
            "\n[t{:>3} {:>5.1}s] {marker} {} ({}% {}) nRF={}",
            s.tick,
            elapsed_s,
            s.decision.selected_policy,
            s.decision.confidence_pct,
            s.decision.source,
            s.decision.selected_nrf_policy,
        );
        println!("            drivers [{}]", drivers.join(", "));
        println!(
            "            radar: target @ ({:.2}m, {:.2}m) d=[{:.1},{:.1},{:.1}]m | pillars DET={} DECEIVE={}({}) DEFEND={} PROVE={}({})",
            s.radar.target_x,
            s.radar.target_y,
            s.radar.anchor_dist_m[0],
            s.radar.anchor_dist_m[1],
            s.radar.anchor_dist_m[2],
            s.pillars.detect_level,
            s.pillars.deceive,
            s.pillars.deceive_trips,
            s.pillars.defend,
            s.pillars.prove,
            s.pillars.prove_records,
        );
        let s3 = &s.nodes[2];
        if let Some(ps) = &s3.psram {
            println!(
                "            resources: C5 free SRAM={}KB ch={} | S3 PCAP={}KB Cam={}KB MicFFT={}KB (cam={}) | LoRaQ={}",
                s.nodes[1].free_sram_kb,
                s.nodes[1].primary_channel,
                ps.pcap_ringbuf_kb,
                ps.camera_fb_kb,
                ps.pdm_audio_fft_kb,
                ps.camera_powered,
                s.lora_queue_depth,
            );
        }
        for d in &s.detections {
            println!(
                "            [DETECT] {} ({}) [{}] -> {}",
                d.title, d.severity, d.mitre, d.recommended_policy
            );
        }
        for e in &s.events {
            println!("            [{}] {}", e.level.to_uppercase(), e.message);
        }
    }

    let final_snap = orch.tick_no;
    println!("\n--------------------------------------------------------------------------------");
    println!(
        "SUMMARY: {final_snap} ticks | detect on {detect_ticks} ticks | lockdown on {lockdown_ticks} ticks | sealed {} evidence blocks (chain {}) | secure sealed/accepted/rejected = {}/{}/{}",
        orch.records.len(),
        if verify_chain(NodeId::XiaoS3Sense, &orch.records) { "VALID" } else { "TAMPERED" },
        orch.secure.frames_sealed,
        orch.secure.frames_accepted,
        orch.secure.rejected_bad_mac + orch.secure.rejected_replay,
    );
    println!("--------------------------------------------------------------------------------");
    Ok(())
}
