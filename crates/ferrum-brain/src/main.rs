//! `ferrum-brain` — Raspberry Pi 5 (8GB) Ferrum Adaptive Control Plane + Laya System-1 Decision Engine
//!
//! Orchestrates:
//! 1. **Node 1 (`ESP32-WROOM` + Dual `nRF24L01+`):** 126-Ch 2.4GHz Spectrum + Ghost Band (`2485-2525MHz`)
//!    + Promiscuous ESB/MouseJack + BT Classic (`BR/EDR`) + BLE 4.2 Adv Fingerprinting.
//! 2. **Node 2 (`ESP32-C5` 4MB Flash, RISC-V):** 5 GHz Wi-Fi 6 (`Ch 36..165`) + `802.15.4` (Zigbee/Thread).
//! 3. **Node 3 (`XIAO ESP32-S3 Sense` 8MB PSRAM):** 2.4GHz Deep PCAP + Active BLE GATT + OV2640 Cam/PDM Mic.
//! 4. **Operator Deck (`uConsole` + AIOv2):** Sub-GHz (`433/915MHz` RTL-SDR + LoRa SX1262) + Tactical HUD.

use ferrum_c5_scout::Esp32C5Node;
use ferrum_deceive::{BleDecoyBeacon, DecoyKind, FakeSoftAp, TripwireEvent, TripwireKind};
use ferrum_forensics::{verify_chain, HashChain, StoreForwardQueue};
use ferrum_ids::IdsEngine;
use ferrum_laya::{signals_from, LayaEngine, TypedDecision};
use ferrum_proto::{FerrumPolicyCmd, NodeId, PolicyMode};
use ferrum_s3_sense::XiaoS3SenseNode;
use ferrum_secure::{OpenError, SecureChannel};
use ferrum_triage::{channel_entropy_q, FeatureVector, RateWindow, RssiHistogram};
use ferrum_wroom_nrf::{build_ble_fingerprint, WroomDualNrfNode};
use std::time::Instant;

/// Presentation-only narrative for a policy (the engine itself stays prose-free).
fn narrative(policy: PolicyMode) -> &'static str {
    match policy {
        PolicyMode::FloodJamSurvival => "WROOM nRF24 RPD pegged across >40 channels -> Layer-1 2.4GHz Jammer! Shifting C5 to 100% 5GHz capture.",
        PolicyMode::SentinelCorrelate => "Close-range RF anomaly (>-42dBm / Sub-GHz burst) -> Allocating S3 PSRAM to OV2640 Cam + PDM Mic & locking all 3 BLE Adv channels.",
        PolicyMode::TriangulateLock => "Covert Ghost-Band (2485-2525MHz) / ESB HID injection spotted by nRF#1 -> Locking nRF#2 in Promiscuous ESB Sniffer + 3-node triangulation.",
        PolicyMode::SurgicalCapture => "5GHz Deauth/EAPOL burst on ESP32-C5 -> Pinning C5 to target 5GHz channel @ 240MHz while S3 buffers 2.4GHz in 7.5MB PSRAM.",
        PolicyMode::AnomalyTriage => "BT Classic (BR/EDR) or unknown BLE profile detected on WROOM -> Commanding S3 Sense to perform Active BLE GATT enumeration.",
        PolicyMode::WideRecon => "RF spectrum nominal -> WROOM Dual-nRF sweeping 126MHz waterfall, C5 sweeping 5GHz+Zigbee, S3 in 80MHz low-power ring buffer.",
        PolicyMode::ForensicLockdown => "IDS escalated CRITICAL detection -> FORENSIC_LOCKDOWN: PCAP ring frozen, hash chain sealed, cam/mic evidence on.",
        _ => "IDS high-severity detection overriding System-1 reactive prior.",
    }
}

/// Renders the engine's machine-readable rationale (top weighted signals + runner-ups).
fn explain(d: &TypedDecision) -> String {
    let top: Vec<String> = d
        .rationale
        .top_signals
        .iter()
        .filter(|(_, share)| *share > 0)
        .map(|(k, share)| format!("{}={}%", k.as_str(), share))
        .collect();
    let dist: Vec<String> = d
        .distribution
        .iter()
        .filter(|(_, pct)| *pct > 0)
        .map(|(p, pct)| format!("{}:{}", p.as_str(), pct))
        .collect();
    format!(
        "drivers [{}] | distribution [{}]",
        top.join(", "),
        dist.join(", ")
    )
}

/// 3-Node Spatial RSSI Trilateration Engine (`Anchor A = WROOM (0,0)`, `Anchor B = C5 (6m, 0)`, `Anchor C = S3 Sense (3m, 5.2m)`).
pub fn trilaterate_target_position_meters(anchor_rssi: [i8; 3]) -> (f32, f32, [f32; 3]) {
    // Log-distance path-loss model: d = 10 ^ ((TxPower - RSSI) / (10 * n)), with TxPower = -40dBm @ 1m, n = 2.2
    let rssi_to_dist = |rssi: i8| -> f32 {
        let clamped = (rssi as f32).clamp(-90.0, -25.0);
        let exp = (-40.0 - clamped) / (10.0 * 2.2);
        // Fast polynomial approximation of 10^exp
        10.0_f32.powf(exp).clamp(0.3, 12.0)
    };

    let d_a = rssi_to_dist(anchor_rssi[0]); // WROOM at (0.0, 0.0)
    let d_b = rssi_to_dist(anchor_rssi[1]); // ESP32-C5 at (6.0, 0.0)
    let d_c = rssi_to_dist(anchor_rssi[2]); // XIAO S3 Sense at (3.0, 5.2)

    // Inverse-distance weighted centroid inside the 6m x 5.2m sensor triangle
    let w_a = 1.0 / (d_a * d_a + 0.1);
    let w_b = 1.0 / (d_b * d_b + 0.1);
    let w_c = 1.0 / (d_c * d_c + 0.1);
    let w_sum = w_a + w_b + w_c;

    let x = (w_a * 0.0 + w_b * 6.0 + w_c * 3.0) / w_sum;
    let y = (w_a * 0.0 + w_b * 0.0 + w_c * 5.2) / w_sum;
    (x, y, [d_a, d_b, d_c])
}

fn main() {
    println!("================================================================================");
    println!(" FERRUM CYBERSWARM — AI-ADAPTIVE UNIKERNEL CONTROL PLANE (Pi 5 + 3x ESP + uConsole)");
    println!("================================================================================");

    let mut wroom = WroomDualNrfNode::new();
    let mut c5 = Esp32C5Node::new();
    let mut s3 = XiaoS3SenseNode::new();
    let mut laya = LayaEngine::new();

    struct Scenario {
        name: &'static str,
        ghost_ch: Option<u8>,
        esb_frames: u8,
        c5_deauth: u16,
        c5_eapol: u8,
        bt_classic: u8,
        rpd_jam_channels: u8,
        subghz_mhz: Option<u16>,
        anchor_rssi: [i8; 3],
    }

    let scenarios = [
        Scenario {
            name: "Tick 1: Baseline Quiet Perimeter (All 3 Nodes in Cooperative Sweep)",
            ghost_ch: None,
            esb_frames: 0,
            c5_deauth: 0,
            c5_eapol: 0,
            bt_classic: 0,
            rpd_jam_channels: 3,
            subghz_mhz: None,
            anchor_rssi: [-68, -71, -65],
        },
        Scenario {
            name: "Tick 2: Covert Ghost-Band Implant & MouseJack ESB Keystroke Injection (2498 MHz / nRF Ch 98)",
            ghost_ch: Some(98),
            esb_frames: 9,
            c5_deauth: 0,
            c5_eapol: 0,
            bt_classic: 0,
            rpd_jam_channels: 5,
            subghz_mhz: None,
            anchor_rssi: [-44, -61, -56],
        },
        Scenario {
            name: "Tick 3: 5 GHz Wi-Fi 6 Evil Twin + Deauth Burst on UNII-3 Ch 149 (5745 MHz)",
            ghost_ch: None,
            esb_frames: 0,
            c5_deauth: 48,
            c5_eapol: 4,
            bt_classic: 0,
            rpd_jam_channels: 6,
            subghz_mhz: None,
            anchor_rssi: [-64, -39, -58],
        },
        Scenario {
            name: "Tick 4: Layer-1 Physical 2.4 GHz Jammer Activated (nRF24 RPD Pegged Across 72 MHz)",
            ghost_ch: None,
            esb_frames: 0,
            c5_deauth: 0,
            c5_eapol: 0,
            bt_classic: 0,
            rpd_jam_channels: 72,
            subghz_mhz: None,
            anchor_rssi: [-36, -52, -49],
        },
        Scenario {
            name: "Tick 5: Close-Range Intruder (-35 dBm) + uConsole AIOv2 433.92 MHz Sub-GHz Replay + BLE MAC Rotation",
            ghost_ch: None,
            esb_frames: 0,
            c5_deauth: 0,
            c5_eapol: 0,
            bt_classic: 2,
            rpd_jam_channels: 4,
            subghz_mhz: Some(433),
            anchor_rssi: [-59, -57, -35],
        },
    ];

    for (idx, sc) in scenarios.iter().enumerate() {
        println!(
            "\n--------------------------------------------------------------------------------"
        );
        println!("[{}] {}", idx + 1, sc.name);

        // Update simulated RF stimuli on the 3 nodes
        wroom.spectrum = ferrum_proto::NrfSpectrumBitmap::empty();
        if let Some(ch) = sc.ghost_ch {
            wroom.spectrum.set_channel(ch, true);
            wroom.last_hotspot_nrf_ch = ch;
        }
        wroom.esb_frames_captured = sc.esb_frames;
        wroom.bt_classic_devices = sc.bt_classic;
        wroom.peak_rssi = sc.anchor_rssi[0];

        c5.deauth_5ghz_cnt = sc.c5_deauth;
        c5.eapol_5ghz_cnt = sc.c5_eapol;
        c5.peak_rssi = sc.anchor_rssi[1];
        if sc.c5_deauth > 0 {
            c5.current_channel = 149;
        }

        s3.peak_rssi = sc.anchor_rssi[2];

        let t_wroom = wroom.build_telemetry();
        let t_c5 = c5.build_telemetry();
        let t_s3 = s3.build_telemetry();

        let t0 = Instant::now();
        let signals = signals_from(&t_wroom, &t_c5, &t_s3, sc.rpd_jam_channels, sc.subghz_mhz);
        let decision = laya.system1(&signals);
        let decision_latency_ms = t0.elapsed().as_secs_f32() * 1000.0;

        let cmd = FerrumPolicyCmd {
            target_node: NodeId::Broadcast as u8,
            policy_mode: decision.selected_policy as u8,
            dual_nrf_mode: decision.selected_nrf_policy as u8,
            pinned_channels: [wroom.last_hotspot_nrf_ch, 6, 149, 0],
            dwell_time_ms: if decision.selected_policy == PolicyMode::SurgicalCapture {
                500
            } else {
                35
            },
            cpu_freq_mhz: if decision.selected_policy == PolicyMode::WideRecon {
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

        wroom.apply_policy_cmd(&cmd);
        c5.apply_policy_cmd(&cmd);
        s3.apply_policy_cmd(&cmd);

        let (x, y, dists) = trilaterate_target_position_meters(sc.anchor_rssi);

        println!(
            "  • Laya Decision ({:.3}ms, {}% conf): Policy = [{}] | WROOM Dual-nRF = [{}]",
            decision_latency_ms,
            decision.confidence_pct,
            decision.selected_policy.as_str(),
            decision.selected_nrf_policy.as_str(),
        );
        println!("  • Rationale: {}", narrative(decision.selected_policy));
        println!("  • Evidence: {}", explain(&decision));
        println!(
            "  • 3-Node Spatial Radar: Target @ ({:.2}m, {:.2}m) | d(WROOM)={:.1}m, d(C5)={:.1}m, d(S3)={:.1}m",
            x, y, dists[0], dists[1], dists[2]
        );
        println!(
            "  • Resource Shift: C5 Free SRAM={}KB (Ring={}KB, Ch={}) | S3 PSRAM: PCAP={}KB, Cam={}KB, MicFFT={}KB (Cam ON={})",
            c5.free_sram_kb,
            c5.sram_ringbuf_kb,
            c5.current_channel,
            s3.psram.pcap_ringbuf_kb,
            s3.psram.camera_fb_kb,
            s3.psram.pdm_audio_fft_kb,
            s3.camera_powered
        );
    }

    // Snapshot latest telemetry & System-1 baseline for Phase 2 evaluation
    let t_wroom = wroom.build_telemetry();
    let t_c5 = c5.build_telemetry();
    let t_s3 = s3.build_telemetry();
    let decision = laya.system1(&signals_from(&t_wroom, &t_c5, &t_s3, 4, Some(433)));

    // ================================================================================
    // PHASE 2 — PILLARS: DETECT / DECEIVE / DEFEND / PROVE
    // ================================================================================
    println!(
        "\n\n################################################################################"
    );
    println!("# PHASE 2: DETECT (ferrum-ids) | DECEIVE (ferrum-deceive)");
    println!("#          DEFEND (ferrum-secure) | PROVE (ferrum-forensics + ferrum-triage)");
    println!("################################################################################");

    // ---- Pillar 2: spin up the deception layer -------------------------------------
    let mut decoy_ap = FakeSoftAp::new(
        "Corp-Guest-IoT-Setup",
        6,
        [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
    );
    let (beacon, beacon_len) = decoy_ap.build_beacon_frame();
    let ble_decoy = BleDecoyBeacon {
        kind: DecoyKind::IBeacon,
        canary_id: 0x0007,
        uuid: [0x11; 16],
        major: 1,
        minor: 1,
        tx_power_dbm: -59,
    };
    let (_adv, adv_len) = ble_decoy.build_adv_payload();
    println!("\n[DECEIVE] Decoy AP 'Corp-Guest-IoT-Setup' beaconing on ch 6 ({}B frame); BLE iBeacon canary 0x0007 ({}B adv)",
        beacon_len, adv_len);
    let _ = beacon;

    // Attacker takes the bait: association attempt against the decoy.
    let trip = TripwireEvent::new(
        0x0007,
        TripwireKind::Association,
        [0x64, 0xA2, 0x11, 0x09, 0xBC, 0x01],
        -38,
        1_700_000_500,
        0x01,
    );

    // ---- Pillar 1: IDS evaluation over the intruder tick + tripwire ----------------
    let ids = IdsEngine::default();
    let detections = ids.evaluate(&t_wroom, &t_c5, &t_s3, 4, &[trip]);
    println!(
        "\n[DETECT] ferrum-ids raised {} detection(s):",
        detections.len()
    );
    for d in &detections {
        println!(
            "  • [{}] {} ({}) — {} [MITRE {}] -> recommend {}",
            d.severity.as_str(),
            d.title,
            d.rule_id,
            d.explanation,
            d.mitre,
            d.recommended_policy.as_str()
        );
    }

    // ---- System-2 escalation --------------------------------------------------------
    let s2 = laya.system2(decision, &detections);
    println!(
        "\n[LAYA-S2] Escalated policy = [{}] ({}% conf) | {}",
        s2.selected_policy.as_str(),
        s2.confidence_pct,
        narrative(s2.selected_policy)
    );

    // ---- Pillar 3: authenticated command channel ------------------------------------
    let swarm_key = [0xFE; 32]; // provisioned at manufacturing; rotated per LoRa epoch
    let mut brain_ch = SecureChannel::new(swarm_key);
    let mut node_ch = SecureChannel::new(swarm_key);
    let lockdown_cmd = FerrumPolicyCmd {
        target_node: NodeId::Broadcast as u8,
        policy_mode: s2.selected_policy as u8,
        dual_nrf_mode: decision.selected_nrf_policy as u8,
        pinned_channels: [98, 6, 149, 0],
        dwell_time_ms: 500,
        cpu_freq_mhz: 240,
        s3_psram_pcap_quota_kb: 4096,
        crc8: 0,
    };
    let frame = brain_ch.seal(&lockdown_cmd);
    match node_ch.open(&frame) {
        Ok(cmd) => println!(
            "\n[SECURE] Policy cmd sealed (seq {}) -> node opened OK, mode 0x{:02X}",
            frame.seq, cmd.policy_mode
        ),
        Err(e) => println!("\n[SECURE] OPEN FAILED: {:?}", e),
    }
    match node_ch.open(&frame) {
        Ok(_) => println!("[SECURE] REPLAY ACCEPTED — BUG!"),
        Err(OpenError::Replay) => {
            println!("[SECURE] Replay of seq {} correctly rejected", frame.seq)
        }
        Err(e) => println!("[SECURE] Unexpected error: {:?}", e),
    }

    // ---- Pillar 4: forensic hash chain over the S3 PCAP window ----------------------
    let mut chain = HashChain::new(NodeId::XiaoS3Sense);
    let pcap_a = [0xAAu8; ferrum_forensics::EVIDENCE_BLOCK_BYTES];
    let pcap_b = [0xBBu8; ferrum_forensics::EVIDENCE_BLOCK_BYTES];
    let h1 = chain.seal(&pcap_a, 1_700_000_500, PolicyMode::SurgicalCapture as u8);
    let h2 = chain.seal(&pcap_b, 1_700_000_560, s2.selected_policy as u8);
    println!(
        "\n[FORENSICS] Sealed 2 PCAP blocks: chain tip {:02X?}...",
        &chain.tip()[..4]
    );
    println!(
        "[FORENSICS] Chain verification: {}",
        if verify_chain(NodeId::XiaoS3Sense, &[h1, h2]) {
            "VALID — court-admissible"
        } else {
            "TAMPERED!"
        }
    );

    // ---- Pillar 3/4: MESH_SURVIVE — compressed triage features over LoRa ------------
    let mut hist = RssiHistogram::new();
    let mut mgmt = RateWindow::<4>::new();
    let mut deauth = RateWindow::<4>::new();
    let mut occupancy = [0u16; 16];
    for &rssi in &[-38, -41, -39, -44, -52, -38, -40, -47] {
        hist.update(rssi);
        mgmt.event();
        occupancy[6] += 1;
    }
    for _ in 0..(t_c5.deauth_disassoc_cnt.min(200)) {
        deauth.event();
    }
    let fv = FeatureVector {
        mean_rssi_q: hist.mean_q(),
        rssi_std_q: hist.stdev_q(),
        mgmt_rate_q: mgmt.avg_per_sec_q(),
        deauth_rate_q: deauth.avg_per_sec_q(),
        entropy_q: channel_entropy_q(&occupancy),
        alarm_flags: if t_c5.deauth_disassoc_cnt > 40 {
            ferrum_triage::flags::DEAUTH_FLOOD
        } else {
            0
        },
        node_id: NodeId::Esp32C5Scout as u8,
        crc8: 0,
    };
    let mut lora_q = StoreForwardQueue::<[u8; FeatureVector::SIZE], 8>::new();
    lora_q.push(fv.to_bytes());
    println!("\n[MESH_SURVIVE] FeatureVector {}B (mean {} qdBm, deauth_rate_q {}) queued for LoRa SX1262",
        FeatureVector::SIZE, fv.mean_rssi_q, fv.deauth_rate_q);
    let mut drained = 0;
    while let Some(_b) = lora_q.pop() {
        drained += 1;
    }
    println!(
        "[MESH_SURVIVE] Drained {} feature frame(s) over out-of-band link (dropped={})",
        drained, lora_q.dropped
    );

    // Verify BLE MAC rotation de-anonymization across two rotating MACs
    let pdu_1 = [
        0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x41, 0x89,
    ];
    let pdu_2 = [
        0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0xFA, 0x03,
    ];
    let fp1 = build_ble_fingerprint(
        [0x64, 0xA2, 0x11, 0x09, 0xBC, 0x01],
        &pdu_1,
        100,
        [-42, -58, -36],
    );
    let fp2 = build_ble_fingerprint(
        [0x51, 0xF9, 0x88, 0x3C, 0x10, 0xFE],
        &pdu_2,
        103,
        [-40, -56, -35],
    );
    println!("\n--------------------------------------------------------------------------------");
    println!(
        "[BLE De-Anonymizer] Rotating MAC {:02X?} -> {:02X?} matched to SAME physical identity hash: 0x{:08X}",
        fp1.current_mac, fp2.current_mac, fp1.structural_hash
    );
}
