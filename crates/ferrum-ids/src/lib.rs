//! `ferrum-ids` — Wireless intrusion detection rule engine (Raspberry Pi 5, `std`).
//!
//! Pillar 1 (DETECT). Consumes rolling `NodeTelemetry` from all three nodes plus
//! `TripwireEvent`s from the deception layer, and emits `Detection`s with severity,
//! approximate MITRE ATT&CK mapping, and the policy mode that best responds.

use ferrum_deceive::{TripwireEvent, TripwireKind};
use ferrum_proto::{NodeTelemetry, PolicyMode};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn rank(&self) -> u8 {
        *self as u8
    }
}

#[derive(Clone, Debug)]
pub struct Detection {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    /// Approximate MITRE ATT&CK technique ID (wireless coverage is sparse in ATT&CK).
    pub mitre: &'static str,
    pub explanation: String,
    pub recommended_policy: PolicyMode,
}

/// Tunable thresholds. Defaults are conservative for a busy office environment.
#[derive(Copy, Clone, Debug)]
pub struct IdsEngine {
    pub deauth_flood_per_window: u16, // combined 2.4+5 GHz deauth/disassoc per 250ms window
    pub ble_spam_fps: u16,
    pub rpd_jam_channel_threshold: u8,
}

impl Default for IdsEngine {
    fn default() -> Self {
        Self {
            deauth_flood_per_window: 50,
            ble_spam_fps: 500,
            rpd_jam_channel_threshold: 40,
        }
    }
}

impl IdsEngine {
    pub fn evaluate(
        &self,
        wroom: &NodeTelemetry,
        c5: &NodeTelemetry,
        s3: &NodeTelemetry,
        rpd_jammed_channels: u8,
        trips: &[TripwireEvent],
    ) -> Vec<Detection> {
        let mut out = Vec::new();

        // --- Pillar 2 trips: any interaction with a decoy is Critical by construction.
        for t in trips {
            let (title, mitre) = match t.kind() {
                Some(TripwireKind::DeauthAgainstDecoy) => (
                    "HONEYPOT: deauth attack against decoy AP",
                    "T1498", // Network DoS
                ),
                Some(TripwireKind::CanaryProbedExternally) => (
                    "CANARY TOKEN LEAK: decoy ID probed outside swarm envelope",
                    "T1046", // Network Service Discovery
                ),
                _ => ("HONEYPOT: decoy interaction", "T1557"), // Adversary-in-the-Middle
            };
            out.push(Detection {
                rule_id: "FR-HP-001",
                severity: Severity::Critical,
                title,
                mitre,
                explanation: format!(
                    "decoy 0x{:04X} tripped by {:02X?} @ {}dBm on node 0x{:02X}",
                    t.decoy_id, t.intruder_mac, t.rssi_dbm, t.node_id
                ),
                recommended_policy: PolicyMode::ForensicLockdown,
            });
        }

        // --- Layer-1 jammer / flood survival.
        if rpd_jammed_channels > self.rpd_jam_channel_threshold {
            out.push(Detection {
                rule_id: "FR-JAM-001",
                severity: Severity::Critical,
                title: "LAYER-1 RF JAMMING",
                mitre: "T1498",
                explanation: format!(
                    "nRF24 RPD carrier energy pegged on {} channels (>{} threshold)",
                    rpd_jammed_channels, self.rpd_jam_channel_threshold
                ),
                recommended_policy: PolicyMode::FloodJamSurvival,
            });
        }

        // --- Deauth / disassoc flood (2.4 + 5 GHz combined).
        let total_deauth = s3.deauth_disassoc_cnt as u32 + c5.deauth_disassoc_cnt as u32;
        if total_deauth > self.deauth_flood_per_window as u32 {
            out.push(Detection {
                rule_id: "FR-WIFI-001",
                severity: Severity::High,
                title: "DEAUTH/DISASSOC FLOOD",
                mitre: "T1498",
                explanation: format!("{} deauth/disassoc frames in one 250ms window", total_deauth),
                recommended_policy: PolicyMode::SurgicalCapture,
            });
        }

        // --- Evil twin heuristic: EAPOL capture preceded by deauth burst on 5 GHz.
        if c5.eapol_handshake_cnt > 0 && c5.deauth_disassoc_cnt > 5 {
            out.push(Detection {
                rule_id: "FR-WIFI-002",
                severity: Severity::High,
                title: "EVIL TWIN (captive PMK harvest pattern)",
                mitre: "T1557",
                explanation: format!(
                    "C5 captured {} EAPOL frames amid a {}-frame deauth burst — classic forced-roam pattern",
                    c5.eapol_handshake_cnt, c5.deauth_disassoc_cnt
                ),
                recommended_policy: PolicyMode::TriangulateLock,
            });
        }

        // --- Wireless HID injection attempt against the operator's own devices.
        if wroom.esb_hid_frames > 0 {
            out.push(Detection {
                rule_id: "FR-ESB-001",
                severity: Severity::High,
                title: "ESB/HID INJECTION ATTEMPT",
                mitre: "T1056", // Input Capture
                explanation: format!(
                    "WROOM nRF#2 captured {} promiscuous Enhanced ShockBurst frames (MouseJack-class)",
                    wroom.esb_hid_frames
                ),
                recommended_policy: PolicyMode::TriangulateLock,
            });
        }

        // --- Covert ghost-band transmitter.
        if wroom.ghost_band_hits > 0 {
            out.push(Detection {
                rule_id: "FR-GHOST-001",
                severity: Severity::High,
                title: "GHOST-BAND COVERT TRANSMITTER (2485-2525 MHz)",
                mitre: "T1011", // Exfiltration over other network medium
                explanation: format!(
                    "{} non-Wi-Fi/non-BLE carriers detected in the 2485-2525 MHz ghost band",
                    wroom.ghost_band_hits
                ),
                recommended_policy: ProtocolModeOrTriangulate(),
            });
        }

        // --- BLE spam / stalker flood.
        if wroom.ble_adv_fps > self.ble_spam_fps {
            out.push(Detection {
                rule_id: "FR-BLE-001",
                severity: Severity::Medium,
                title: "BLE ADVERTISEMENT SPAM",
                mitre: "T1498",
                explanation: format!("{} BLE adv/sec (Flipper/SourApple-class flood)", wroom.ble_adv_fps),
                recommended_policy: PolicyMode::IdsEnforce,
            });
        }

        // --- 802.15.4 (Zigbee/Thread) activity on C5.
        if c5.zigbee_pan_frames > 0 {
            out.push(Detection {
                rule_id: "FR-ZB-001",
                severity: Severity::Medium,
                title: "802.15.4 PAN ACTIVITY",
                mitre: "T1011",
                explanation: format!("{} 802.15.4 frames observed on C5 (verify against known PAN inventory)", c5.zigbee_pan_frames),
                recommended_policy: PolicyMode::AnomalyTriage,
            });
        }

        // --- Sensor health (so a blinded node is itself an alert).
        if s3.ringbuf_drops > 100 || c5.ringbuf_drops > 100 {
            out.push(Detection {
                rule_id: "FR-HEALTH-001",
                severity: Severity::Low,
                title: "SENSOR DEGRADATION",
                mitre: "T1498",
                explanation: "Ring-buffer drops spiking — node may be blinded or overloaded; coverage gap risk.".to_string(),
                recommended_policy: PolicyMode::AnomalyTriage,
            });
        }

        out
    }

    /// Policy to enter if any Critical detection fired.
    pub fn escalate(&self, detections: &[Detection]) -> Option<PolicyMode> {
        if detections.iter().any(|d| d.severity == Severity::Critical) {
            Some(PolicyMode::ForensicLockdown)
        } else {
            detections
                .iter()
                .filter(|d| d.severity.rank() >= Severity::High.rank())
                .max_by_key(|d| d.severity.rank())
                .map(|d| d.recommended_policy)
        }
    }
}

// Helper to keep the ghost-band rule readable.
#[allow(non_snake_case)]
fn ProtocolModeOrTriangulate() -> PolicyMode {
    PolicyMode::TriangulateLock
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet(node: u8) -> NodeTelemetry {
        NodeTelemetry {
            node_id: node, active_policy: 0x01, sub_policy: 0x01, primary_channel: 6,
            cpu_load_pct: 30, free_sram_kb: 300, free_psram_kb: 0, ringbuf_drops: 0,
            wifi_mgmt_fps: 60, deauth_disassoc_cnt: 0, eapol_handshake_cnt: 0,
            ble_adv_fps: 120, bt_classic_inq_cnt: 0, ghost_band_hits: 0,
            esb_hid_frames: 0, zigbee_pan_frames: 0, peak_anomaly_rssi: -70, crc8: 0,
        }
    }

    #[test]
    fn quiet_environment_produces_no_detections() {
        let eng = IdsEngine::default();
        let d = eng.evaluate(&quiet(1), &quiet(2), &quiet(3), 3, &[]);
        assert!(d.is_empty(), "unexpected: {:?}", d.iter().map(|x| x.title).collect::<Vec<_>>());
    }

    #[test]
    fn honeypot_trip_is_critical_and_escalates_to_lockdown() {
        let eng = IdsEngine::default();
        let trip = TripwireEvent::new(7, TripwireKind::Association, [0x64; 6], -45, 1_700_000_000, 0x01);
        let d = eng.evaluate(&quiet(1), &quiet(2), &quiet(3), 3, &[trip]);
        assert_eq!(d[0].severity, Severity::Critical);
        assert_eq!(eng.escalate(&d), Some(PolicyMode::ForensicLockdown));
    }

    #[test]
    fn deauth_flood_and_evil_twin_fire() {
        let eng = IdsEngine::default();
        let mut w = quiet(1);
        let mut c = quiet(2);
        let s = quiet(3);
        c.deauth_disassoc_cnt = 60;
        c.eapol_handshake_cnt = 4;
        w.ghost_band_hits = 3;
        let d = eng.evaluate(&w, &c, &s, 3, &[]);
        let rules: Vec<&str> = d.iter().map(|x| x.rule_id).collect();
        assert!(rules.contains(&"FR-WIFI-001"));
        assert!(rules.contains(&"FR-WIFI-002"));
        assert!(rules.contains(&"FR-GHOST-001"));
        assert_eq!(eng.escalate(&d), Some(PolicyMode::TriangulateLock)); // top High wins
    }

    #[test]
    fn jammer_beats_deauth_in_escalation() {
        let eng = IdsEngine::default();
        let mut c = quiet(2);
        c.deauth_disassoc_cnt = 80;
        let d = eng.evaluate(&quiet(1), &c, &quiet(3), 72, &[]);
        assert_eq!(eng.escalate(&d), Some(PolicyMode::ForensicLockdown));
    }
}
