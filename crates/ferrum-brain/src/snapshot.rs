//! Wire format for the live dashboard (`SwarmSnapshot`, streamed every tick) and the inbound
//! operator command format (`OperatorCommand`).
//!
//! **Field names are a contract** with the dashboard: stable `snake_case`, never renamed casually.
//! Policy / severity / signal enums serialize as the readable strings from their `as_str()`
//! (e.g. `"FORENSIC_LOCKDOWN"`, `"HIGH"`, `"jam_ratio"`), never as integers.
//!
//! The views are plain serializable mirrors; the `from_*` / `From` helpers build them from the
//! engine types so the orchestrator stays thin.
//!
//! # `OperatorCommand` JSON shapes (serde externally-tagged)
//! ```text
//! {"InjectAdversary":"jammer"}     {"ClearAdversary":3}      {"ForcePolicy":9}
//! {"SetScenario":"quiet"}          "Pause"                   "Resume"
//! {"SetTickHz":4}
//! ```
//! `ForcePolicy` carries a `PolicyMode` wire byte (`0x01..=0x0A`); `0` is not a policy and is
//! interpreted by the orchestrator as "release the override".

use ferrum_forensics::EvidenceRecord;
use ferrum_ids::Detection;
use ferrum_laya::TypedDecision;
use ferrum_proto::{NodeId, NodeTelemetry, NrfSpectrumBitmap, PolicyMode};
use ferrum_s3_sense::S3PsramPartition;
use serde::{Deserialize, Serialize};

/// Number of nRF24 RPD channels (`2400..=2525 MHz`).
pub const NRF_CHANNELS: usize = 126;
/// Max recent evidence records carried in [`ForensicsView::recent`].
pub const FORENSICS_RECENT: usize = 8;

fn policy_str(raw: u8) -> &'static str {
    PolicyMode::from_u8(raw).map_or("UNKNOWN", |p| p.as_str())
}

fn node_name(raw: u8) -> &'static str {
    match NodeId::from_u8(raw) {
        Some(NodeId::WroomDualNrf) => "WROOM",
        Some(NodeId::Esp32C5Scout) => "C5",
        Some(NodeId::XiaoS3Sense) => "S3",
        Some(NodeId::UConsoleAio2) => "UCONSOLE",
        Some(NodeId::Pi5Brain) => "BRAIN",
        Some(NodeId::Broadcast) => "BROADCAST",
        None => "UNKNOWN",
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Operator -> brain command. JSON shapes are documented at the module level.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub enum OperatorCommand {
    /// Inject an adversary by its `Adversary::name()` label (e.g. `"jammer"`).
    InjectAdversary(String),
    /// Clear a previously injected/spawned adversary by `AdversaryId`.
    ClearAdversary(u32),
    /// Force a `PolicyMode` wire byte (`0` = release the override).
    ForcePolicy(u8),
    /// Switch to a named scenario (`ferrum_sim::SCENARIO_NAMES`).
    SetScenario(String),
    Pause,
    Resume,
    /// Tick rate in Hz.
    SetTickHz(u8),
}

/// PSRAM partition of the S3 node (kB) plus peripheral power state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PsramView {
    pub pcap_ringbuf_kb: u16,
    pub ble_gatt_cache_kb: u16,
    pub camera_fb_kb: u16,
    pub pdm_audio_fft_kb: u16,
    pub unallocated_kb: u16,
    pub camera_powered: bool,
    pub pdm_mic_active: bool,
}

impl PsramView {
    pub fn from_partition(
        p: &S3PsramPartition,
        camera_powered: bool,
        pdm_mic_active: bool,
    ) -> Self {
        Self {
            pcap_ringbuf_kb: p.pcap_ringbuf_kb,
            ble_gatt_cache_kb: p.ble_gatt_cache_kb,
            camera_fb_kb: p.camera_fb_kb,
            pdm_audio_fft_kb: p.pdm_audio_fft_kb,
            unallocated_kb: p.unallocated_kb,
            camera_powered,
            pdm_mic_active,
        }
    }
}

/// One sensor node as the dashboard shows it. `psram` is `null` except for the S3 node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NodeView {
    pub node_id: u8,
    /// `"WROOM"`, `"C5"` or `"S3"`.
    pub name: &'static str,
    /// False when no telemetry arrived this tick (all counters are then zero).
    pub online: bool,
    pub active_policy: &'static str,
    pub sub_policy: u8,
    pub primary_channel: u8,
    pub cpu_load_pct: u8,
    pub free_sram_kb: u16,
    pub free_psram_kb: u16,
    pub ringbuf_drops: u16,
    pub wifi_mgmt_fps: u16,
    pub deauth_disassoc_cnt: u16,
    pub eapol_handshake_cnt: u8,
    pub ble_adv_fps: u16,
    pub bt_classic_inq_cnt: u8,
    pub ghost_band_hits: u8,
    pub esb_hid_frames: u8,
    pub zigbee_pan_frames: u8,
    pub peak_anomaly_rssi: i8,
    pub psram: Option<PsramView>,
}

impl NodeView {
    /// An online node built from this tick's telemetry.
    pub fn from_telemetry(t: &NodeTelemetry) -> Self {
        Self {
            node_id: t.node_id,
            name: node_name(t.node_id),
            online: true,
            active_policy: policy_str(t.active_policy),
            sub_policy: t.sub_policy,
            primary_channel: t.primary_channel,
            cpu_load_pct: t.cpu_load_pct,
            free_sram_kb: t.free_sram_kb,
            free_psram_kb: t.free_psram_kb,
            ringbuf_drops: t.ringbuf_drops,
            wifi_mgmt_fps: t.wifi_mgmt_fps,
            deauth_disassoc_cnt: t.deauth_disassoc_cnt,
            eapol_handshake_cnt: t.eapol_handshake_cnt,
            ble_adv_fps: t.ble_adv_fps,
            bt_classic_inq_cnt: t.bt_classic_inq_cnt,
            ghost_band_hits: t.ghost_band_hits,
            esb_hid_frames: t.esb_hid_frames,
            zigbee_pan_frames: t.zigbee_pan_frames,
            peak_anomaly_rssi: t.peak_anomaly_rssi,
            psram: None,
        }
    }

    /// A node that produced no telemetry this tick.
    pub fn offline(node_id: NodeId) -> Self {
        Self {
            node_id: node_id as u8,
            name: node_name(node_id as u8),
            active_policy: "UNKNOWN",
            ..Self::default()
        }
    }

    /// Attach the S3 PSRAM partition.
    pub fn with_psram(mut self, psram: PsramView) -> Self {
        self.psram = Some(psram);
        self
    }
}

/// The Laya decision. The headline is `selected_policy`; after System-2 escalation `distribution`
/// and `top_signals` still describe the overridden System-1 evidence (`escalated == true`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DecisionView {
    pub selected_policy: &'static str,
    pub selected_nrf_policy: &'static str,
    pub confidence_pct: u8,
    /// True when System-2 (IDS) overrode System-1, i.e. `selected_policy != distribution[0]`.
    pub escalated: bool,
    /// `"system1"` or `"system2"`.
    pub source: &'static str,
    pub cooperative_band_split: bool,
    pub trigger_s3_camera_mic: bool,
    /// `[policy, pct]` pairs (6 entries, summing to 100) of the System-1 scoring.
    pub distribution: Vec<(&'static str, u8)>,
    /// `[signal, share_pct]` pairs (3 entries) explaining the System-1 scoring.
    pub top_signals: Vec<(&'static str, u8)>,
}

impl DecisionView {
    pub fn from_decision(d: &TypedDecision, escalated: bool) -> Self {
        Self {
            selected_policy: d.selected_policy.as_str(),
            selected_nrf_policy: d.selected_nrf_policy.as_str(),
            confidence_pct: d.confidence_pct,
            escalated,
            source: if escalated { "system2" } else { "system1" },
            cooperative_band_split: d.cooperative_band_split,
            trigger_s3_camera_mic: d.trigger_s3_camera_mic,
            distribution: d
                .distribution
                .iter()
                .map(|(p, pct)| (p.as_str(), *pct))
                .collect(),
            top_signals: d
                .rationale
                .top_signals
                .iter()
                .map(|(k, pct)| (k.as_str(), *pct))
                .collect(),
        }
    }
}

/// Infers `escalated` from the invariant that System-1 puts the selected policy at `distribution[0]`.
impl From<&TypedDecision> for DecisionView {
    fn from(d: &TypedDecision) -> Self {
        Self::from_decision(d, d.selected_policy != d.distribution[0].0)
    }
}

impl Default for DecisionView {
    fn default() -> Self {
        Self {
            selected_policy: PolicyMode::WideRecon.as_str(),
            selected_nrf_policy: "SPLIT_SPECTRUM_WATERFALL",
            confidence_pct: 0,
            escalated: false,
            source: "system1",
            cooperative_band_split: false,
            trigger_s3_camera_mic: false,
            distribution: Vec::new(),
            top_signals: Vec::new(),
        }
    }
}

/// Trilaterated target position and the anchors it was computed from (metres).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct RadarView {
    /// False when there is no target to show (`target_*` are then 0).
    pub has_target: bool,
    pub target_x: f32,
    pub target_y: f32,
    /// Distances from anchors `[WROOM, C5, S3]` in metres.
    pub anchor_dist_m: [f32; 3],
    /// Anchor positions `[WROOM, C5, S3]` as `[x, y]` metres.
    pub anchors: [[f32; 2]; 3],
}

impl RadarView {
    /// From `ferrum_sim::trilaterate`'s `(x, y, dists)` and `ferrum_sim::phys::ANCHORS`.
    pub fn new(target: Option<(f32, f32, [f32; 3])>, anchors: [(f32, f32); 3]) -> Self {
        let (has_target, x, y, d) = match target {
            Some((x, y, d)) => (true, x, y, d),
            None => (false, 0.0, 0.0, [0.0; 3]),
        };
        Self {
            has_target,
            target_x: x,
            target_y: y,
            anchor_dist_m: d,
            anchors: anchors.map(|(ax, ay)| [ax, ay]),
        }
    }
}

/// Waterfall row: 2.4 GHz nRF RPD (126 ch) + Wi-Fi RSSI per channel on 2.4 / 5 GHz.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SpectrumView {
    /// Length 126; index `ch` is `2400 + ch` MHz; true if carrier energy > -64 dBm.
    pub nrf_active: Vec<bool>,
    /// Active channels in the ghost band (nRF ch 85..=125, 2485..=2525 MHz).
    pub ghost_band_active: u8,
    /// `[wifi_channel, rssi_dbm]` pairs seen on 2.4 GHz.
    pub wifi24: Vec<(u8, i8)>,
    /// `[wifi_channel, rssi_dbm]` pairs seen on 5 GHz.
    pub wifi5: Vec<(u8, i8)>,
    /// Sub-GHz burst frequency (MHz) if one is in progress.
    pub subghz_burst_mhz: Option<u16>,
}

impl SpectrumView {
    pub fn new(
        nrf: &NrfSpectrumBitmap,
        wifi24: Vec<(u8, i8)>,
        wifi5: Vec<(u8, i8)>,
        subghz_burst_mhz: Option<u16>,
    ) -> Self {
        Self {
            nrf_active: (0..NRF_CHANNELS as u8)
                .map(|c| nrf.get_channel(c))
                .collect(),
            ghost_band_active: nrf.ghost_band_active_count(),
            wifi24,
            wifi5,
            subghz_burst_mhz,
        }
    }
}

impl Default for SpectrumView {
    fn default() -> Self {
        Self::new(&NrfSpectrumBitmap::empty(), Vec::new(), Vec::new(), None)
    }
}

/// The four pillars. Booleans light the pillar; the `*_` counters/levels give it texture.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PillarView {
    /// DETECT: any IDS detection this tick.
    pub detect: bool,
    /// Highest detection severity rank + 1 (`0` = none, `1` = INFO .. `5` = CRITICAL).
    pub detect_level: u8,
    /// DECEIVE: honeypot active or a tripwire has fired.
    pub deceive: bool,
    pub deceive_trips: u32,
    /// DEFEND: a defensive policy is selected.
    pub defend: bool,
    /// PROVE: at least one evidence record sealed.
    pub prove: bool,
    pub prove_records: u32,
}

impl PillarView {
    /// Derive the pillar state from the decision, detections, tripwire count and chain length.
    pub fn derive(
        selected: PolicyMode,
        detections: &[Detection],
        tripwire_trips: u32,
        evidence_records: u32,
    ) -> Self {
        let detect_level = detections
            .iter()
            .map(|d| d.severity.rank() + 1)
            .max()
            .unwrap_or(0);
        Self {
            detect: !detections.is_empty(),
            detect_level,
            deceive: selected == PolicyMode::HoneypotLure || tripwire_trips > 0,
            deceive_trips: tripwire_trips,
            defend: matches!(
                selected,
                PolicyMode::FloodJamSurvival
                    | PolicyMode::IdsEnforce
                    | PolicyMode::ForensicLockdown
                    | PolicyMode::MeshSurvive
            ),
            prove: evidence_records > 0,
            prove_records: evidence_records,
        }
    }
}

/// One IDS detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DetectionView {
    pub rule_id: &'static str,
    /// `"INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"`.
    pub severity: &'static str,
    /// 0 (INFO) ..= 4 (CRITICAL).
    pub severity_rank: u8,
    pub title: &'static str,
    pub explanation: String,
    pub mitre: &'static str,
    pub recommended_policy: &'static str,
}

impl From<&Detection> for DetectionView {
    fn from(d: &Detection) -> Self {
        Self {
            rule_id: d.rule_id,
            severity: d.severity.as_str(),
            severity_rank: d.severity.rank(),
            title: d.title,
            explanation: d.explanation.clone(),
            mitre: d.mitre,
            recommended_policy: d.recommended_policy.as_str(),
        }
    }
}

/// One sealed evidence-chain link (hashes hex-encoded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceView {
    pub seq: u32,
    pub timestamp_s: u32,
    pub policy: &'static str,
    pub block_hash: String,
    pub chain_hash: String,
}

impl From<&EvidenceRecord> for EvidenceView {
    fn from(r: &EvidenceRecord) -> Self {
        Self {
            seq: r.seq,
            timestamp_s: r.timestamp_s,
            policy: policy_str(r.policy_mode),
            block_hash: hex(&r.block_hash),
            chain_hash: hex(&r.chain_hash),
        }
    }
}

/// Pillar 4 evidence chain summary.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ForensicsView {
    pub sealed_records: u32,
    /// Hex of the chain tip (latest `chain_hash`), empty before the first seal.
    pub chain_tip: String,
    /// Result of `ferrum_forensics::verify_chain` over the whole chain.
    pub chain_valid: bool,
    /// Last [`FORENSICS_RECENT`] records, oldest first.
    pub recent: Vec<EvidenceView>,
}

impl ForensicsView {
    pub fn from_records(records: &[EvidenceRecord], chain_valid: bool) -> Self {
        let start = records.len().saturating_sub(FORENSICS_RECENT);
        Self {
            sealed_records: records.len() as u32,
            chain_tip: records
                .last()
                .map_or_else(String::new, |r| hex(&r.chain_hash)),
            chain_valid,
            recent: records[start..].iter().map(EvidenceView::from).collect(),
        }
    }
}

/// Authenticated command-channel counters (orchestrator-maintained).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SecureView {
    pub epoch: u32,
    pub frames_sealed: u32,
    pub frames_accepted: u32,
    pub rejected_bad_mac: u32,
    pub rejected_replay: u32,
}

/// An active adversary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AdversaryView {
    pub id: u32,
    /// `Adversary::name()` label, e.g. `"jammer"`.
    pub name: &'static str,
}

/// Simulation / run-control state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScenarioView {
    pub name: String,
    pub elapsed_ms: u64,
    pub paused: bool,
    pub tick_hz: u8,
    pub active_adversaries: Vec<AdversaryView>,
}

impl Default for ScenarioView {
    fn default() -> Self {
        Self {
            name: "quiet".to_string(),
            elapsed_ms: 0,
            paused: false,
            tick_hz: 4,
            active_adversaries: Vec::new(),
        }
    }
}

/// A log line for the dashboard event feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventView {
    pub tick: u64,
    /// `"info" | "warn" | "alert"`.
    pub level: &'static str,
    pub message: String,
}

/// Everything the dashboard renders for one tick.
#[derive(Clone, Debug, Serialize)]
pub struct SwarmSnapshot {
    pub tick: u64,
    /// Order: `[WROOM, C5, S3]`.
    pub nodes: [NodeView; 3],
    pub decision: DecisionView,
    pub radar: RadarView,
    pub spectrum: SpectrumView,
    pub pillars: PillarView,
    pub detections: Vec<DetectionView>,
    pub forensics: ForensicsView,
    pub secure: SecureView,
    pub lora_queue_depth: u8,
    pub scenario: ScenarioView,
    pub events: Vec<EventView>,
}

impl SwarmSnapshot {
    /// A quiet, all-nodes-offline snapshot for `tick` (orchestrator overwrites the fields).
    pub fn empty(tick: u64) -> Self {
        Self {
            tick,
            nodes: [
                NodeView::offline(NodeId::WroomDualNrf),
                NodeView::offline(NodeId::Esp32C5Scout),
                NodeView::offline(NodeId::XiaoS3Sense),
            ],
            decision: DecisionView::default(),
            radar: RadarView::default(),
            spectrum: SpectrumView::default(),
            pillars: PillarView::default(),
            detections: Vec::new(),
            forensics: ForensicsView::default(),
            secure: SecureView::default(),
            lora_queue_depth: 0,
            scenario: ScenarioView::default(),
            events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_ids::Severity;
    use ferrum_laya::{LayaEngine, SignalVector};
    use serde_json::{json, Value};

    fn tele(id: NodeId) -> NodeTelemetry {
        NodeTelemetry {
            node_id: id as u8,
            active_policy: PolicyMode::SurgicalCapture as u8,
            sub_policy: 2,
            primary_channel: 6,
            cpu_load_pct: 40,
            free_sram_kb: 300,
            free_psram_kb: 7000,
            ringbuf_drops: 1,
            wifi_mgmt_fps: 210,
            deauth_disassoc_cnt: 5,
            eapol_handshake_cnt: 2,
            ble_adv_fps: 30,
            bt_classic_inq_cnt: 1,
            ghost_band_hits: 4,
            esb_hid_frames: 3,
            zigbee_pan_frames: 0,
            peak_anomaly_rssi: -34,
            crc8: 0,
        }
    }

    fn det(sev: Severity) -> Detection {
        Detection {
            rule_id: "T-001",
            severity: sev,
            title: "test",
            mitre: "T0000",
            explanation: "because".to_string(),
            recommended_policy: PolicyMode::ForensicLockdown,
        }
    }

    #[test]
    fn test_snapshot_roundtrips_json() {
        let snap = SwarmSnapshot::empty(7);
        let json = serde_json::to_string(&snap).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["tick"].is_number());
        assert!(v["nodes"][0]["online"].is_boolean());
        assert_eq!(v["nodes"].as_array().unwrap().len(), 3);
        assert!(v["decision"]["selected_policy"].is_string());
        assert!(v["pillars"]["detect"].is_boolean());
        assert_eq!(v["spectrum"]["nrf_active"].as_array().unwrap().len(), 126);
        assert!(v["lora_queue_depth"].is_number());
        assert!(v["events"].is_array());
    }

    #[test]
    fn test_populated_snapshot_serializes_engine_views() {
        let mut snap = SwarmSnapshot::empty(9);
        snap.nodes[2] = NodeView::from_telemetry(&tele(NodeId::XiaoS3Sense)).with_psram(
            PsramView::from_partition(
                &S3PsramPartition {
                    pcap_ringbuf_kb: 4096,
                    ble_gatt_cache_kb: 512,
                    camera_fb_kb: 1024,
                    pdm_audio_fft_kb: 256,
                    unallocated_kb: 2304,
                },
                true,
                true,
            ),
        );
        snap.detections = vec![DetectionView::from(&det(Severity::Critical))];
        snap.pillars = PillarView::derive(
            PolicyMode::ForensicLockdown,
            &[det(Severity::Critical)],
            0,
            2,
        );
        snap.radar = RadarView::new(
            Some((3.0, 2.0, [4.0, 4.5, 3.5])),
            [(0.0, 0.0), (6.0, 0.0), (3.0, 5.2)],
        );
        let rec = EvidenceRecord {
            seq: 1,
            timestamp_s: 5,
            policy_mode: 9,
            block_hash: [0xab; 32],
            chain_hash: [0x01; 32],
        };
        snap.forensics = ForensicsView::from_records(&[rec], true);
        let v: Value = serde_json::to_value(&snap).unwrap();
        assert_eq!(v["nodes"][2]["name"], "S3");
        assert_eq!(v["nodes"][2]["online"], true);
        assert_eq!(v["nodes"][2]["peak_anomaly_rssi"], -34);
        assert_eq!(v["nodes"][2]["psram"]["camera_fb_kb"], 1024);
        assert_eq!(v["nodes"][2]["active_policy"], "SURGICAL_CAPTURE");
        assert!(v["nodes"][0]["psram"].is_null());
        assert_eq!(v["nodes"][0]["online"], false);
        assert_eq!(v["detections"][0]["severity"], "CRITICAL");
        assert_eq!(
            v["detections"][0]["recommended_policy"],
            "FORENSIC_LOCKDOWN"
        );
        assert_eq!(v["pillars"]["detect"], true);
        assert_eq!(v["pillars"]["detect_level"], 5);
        assert_eq!(v["pillars"]["defend"], true);
        assert_eq!(v["pillars"]["prove"], true);
        assert_eq!(v["radar"]["anchors"][1], json!([6.0, 0.0]));
        assert_eq!(v["forensics"]["recent"][0]["block_hash"], "ab".repeat(32));
        assert_eq!(v["forensics"]["chain_tip"], "01".repeat(32));
    }

    #[test]
    fn test_decision_view_headline_is_selected_policy_after_escalation() {
        let mut eng = LayaEngine::new();
        let s1 = eng.system1(&SignalVector::default());
        let plain = DecisionView::from(&s1);
        assert!(!plain.escalated);
        assert_eq!(plain.source, "system1");
        assert_eq!(plain.distribution.len(), 6);
        assert_eq!(
            plain
                .distribution
                .iter()
                .map(|(_, p)| u32::from(*p))
                .sum::<u32>(),
            100
        );
        assert_eq!(plain.top_signals.len(), 3);

        let s2 = eng.system2(s1, &[det(Severity::Critical)]);
        let v = DecisionView::from(&s2);
        assert!(v.escalated);
        assert_eq!(v.source, "system2");
        assert_eq!(v.selected_policy, "FORENSIC_LOCKDOWN");
        assert_ne!(v.distribution[0].0, v.selected_policy);
        let j: Value = serde_json::to_value(&v).unwrap();
        assert!(j["distribution"][0].is_array());
        assert_eq!(j["confidence_pct"], 99);
    }

    #[test]
    fn test_operator_command_parses() {
        let p = |s: &str| serde_json::from_str::<OperatorCommand>(s).unwrap();
        assert_eq!(
            p(r#"{"InjectAdversary":"jammer"}"#),
            OperatorCommand::InjectAdversary("jammer".into())
        );
        assert_eq!(
            p(r#"{"ClearAdversary":3}"#),
            OperatorCommand::ClearAdversary(3)
        );
        assert_eq!(p(r#"{"ForcePolicy":9}"#), OperatorCommand::ForcePolicy(9));
        assert_eq!(
            p(r#"{"SetScenario":"quiet"}"#),
            OperatorCommand::SetScenario("quiet".into())
        );
        assert_eq!(p(r#""Pause""#), OperatorCommand::Pause);
        assert_eq!(p(r#""Resume""#), OperatorCommand::Resume);
        assert_eq!(p(r#"{"SetTickHz":8}"#), OperatorCommand::SetTickHz(8));
        assert!(serde_json::from_str::<OperatorCommand>(r#"{"Bogus":1}"#).is_err());
        assert!(serde_json::from_str::<OperatorCommand>(r#"{"ForcePolicy":300}"#).is_err());
    }
}
