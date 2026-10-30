//! Storyline integration test: one `Orchestrator` composes the whole swarm and walks the
//! flagship `red-team-incursion` scenario end-to-end, lighting every pillar without panicking.
use ferrum_brain::orchestrator::Orchestrator;
use ferrum_brain::snapshot::SwarmSnapshot;
use ferrum_proto::{FerrumPolicyCmd, NodeId, PolicyMode};

/// Run the whole scenario (300 × 100 ms ticks, as the golden sim test does) collecting a snapshot
/// per tick. The loop itself is the panic-free assertion.
fn run(ticks: u64) -> Vec<SwarmSnapshot> {
    let mut orch = Orchestrator::new(42, "red-team-incursion").expect("scenario builds");
    (0..ticks).map(|_| orch.tick()).collect()
}

#[test]
fn test_red_team_incursion_hits_all_pillars() {
    let snaps = run(300);
    assert_eq!(snaps.len(), 300);

    // DETECT: the IDS raised at least one detection somewhere in the run.
    assert!(
        snaps.iter().any(|s| !s.detections.is_empty()),
        "DETECT: no IDS detection fired over the whole run"
    );

    // DECEIVE: a tripwire fired against a decoy.
    assert!(
        snaps
            .iter()
            .any(|s| s.pillars.deceive_trips > 0 && s.pillars.deceive),
        "DECEIVE: no tripwire ever fired"
    );

    // DEFEND / PROVE: a FORENSIC_LOCKDOWN tick occurs and the evidence chain verifies from there on.
    let first_lockdown = snaps
        .iter()
        .position(|s| s.decision.selected_policy == PolicyMode::ForensicLockdown.as_str())
        .expect("a FORENSIC_LOCKDOWN tick must occur");
    for s in &snaps[first_lockdown..] {
        if s.forensics.sealed_records > 0 {
            assert!(
                s.forensics.chain_valid,
                "forensic chain failed to verify at tick {}",
                s.tick
            );
        }
    }
    let last = snaps.last().unwrap();
    assert!(
        last.forensics.sealed_records > 0 && last.forensics.chain_valid,
        "PROVE: evidence chain empty or invalid at end of run"
    );
    assert!(
        last.pillars.prove && last.pillars.defend,
        "DEFEND/PROVE pillars never lit by end of run"
    );

    // MESH_SURVIVE: the LoRa store-and-forward queue backs up under contention then drains to empty.
    assert!(
        snaps.iter().any(|s| s.lora_queue_depth > 0),
        "LoRa queue never backed up"
    );
    assert_eq!(
        last.lora_queue_depth, 0,
        "LoRa queue did not drain by end of run"
    );

    // The pipeline stayed self-consistent: three nodes, a selected policy every tick.
    for s in &snaps {
        assert_eq!(s.nodes.len(), 3);
        assert!(!s.decision.selected_policy.is_empty());
    }
}

#[test]
fn test_forged_command_surfaces_event() {
    let mut orch = Orchestrator::new(42, "red-team-incursion").expect("scenario builds");
    for _ in 0..5 {
        orch.tick();
    }

    // Seal a legitimate command on the brain channel, then tamper a payload byte so the node-side
    // HMAC verification must reject it.
    let cmd = FerrumPolicyCmd {
        target_node: NodeId::Broadcast as u8,
        policy_mode: PolicyMode::ForensicLockdown as u8,
        dual_nrf_mode: 0x02,
        pinned_channels: [98, 6, 149, 0],
        dwell_time_ms: 500,
        cpu_freq_mhz: 240,
        s3_psram_pcap_quota_kb: 4096,
        crc8: 0,
    };
    let mut frame = orch.seal_command(&cmd);
    frame.payload[0] ^= 0xFF; // flip a byte -> MAC mismatch

    let rejected_before = orch.secure_counters().rejected_bad_mac;
    orch.feed_sealed_command(frame);

    // The rejection surfaces as an event in the next snapshot and the loop keeps running.
    let snap = orch.tick();
    assert!(
        snap.events
            .iter()
            .any(|e| e.level == "alert" && e.message.to_lowercase().contains("reject")),
        "forged command did not surface a secure-rejection event: {:?}",
        snap.events
    );
    assert!(
        snap.secure.rejected_bad_mac > rejected_before,
        "rejected_bad_mac counter did not advance"
    );

    // Loop continues: subsequent ticks still advance and do not panic.
    let snap2 = orch.tick();
    assert!(snap2.tick > snap.tick);
}
