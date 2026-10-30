//! One test per adversary: the signal it drives must show up in the world's readouts / frames.
use ferrum_hal::FrameKind;
use ferrum_proto::NodeId;
use ferrum_sim::{
    scenario_by_name, Adversary, AdversaryId, RfWorld, ScenarioEvent, SimController, SimFrame,
};
use ferrum_wroom_nrf::build_ble_fingerprint;

const WROOM: NodeId = NodeId::WroomDualNrf;
const C5: NodeId = NodeId::Esp32C5Scout;
const S3: NodeId = NodeId::XiaoS3Sense;

/// Apply `a` then step the world `ticks` x 100 ms, draining `node`'s frames.
fn run(a: &mut Adversary, w: &mut RfWorld, ticks: u64, node: NodeId) -> Vec<SimFrame> {
    let mut out = Vec::new();
    for _ in 0..ticks {
        let t = w.time_ms();
        a.apply(w, t);
        w.step(100);
        while let Some(f) = w.next_frame(node) {
            out.push(f);
        }
    }
    out
}

#[test]
fn jammer_makes_over_40_nrf_channels_rpd_hot() {
    let mut w = RfWorld::new(1);
    w.step(100);
    let quiet = (0..=125u8).filter(|&c| w.rpd_at(WROOM, c)).count();
    assert_eq!(quiet, 0);
    let mut j = Adversary::jammer((1.5, 1.0), 62);
    run(&mut j, &mut w, 3, WROOM);
    let hot = (0..=125u8).filter(|&c| w.rpd_at(WROOM, c)).count();
    assert!(hot > 40, "only {hot} channels RPD-hot");
}

#[test]
fn evil_twin_deauth_burst_rises_on_5ghz_then_stops() {
    let mut w = RfWorld::new(2);
    let mut a = Adversary::evil_twin_deauth((5.0, 1.5), 36, 2_000);
    let frames = run(&mut a, &mut w, 20, C5);
    let in_burst = frames
        .iter()
        .filter(|f| f.kind == FrameKind::Deauth && f.channel == 36 && f.t_ms <= 2_000)
        .count();
    let after = frames
        .iter()
        .filter(|f| f.kind == FrameKind::Deauth && f.t_ms > 2_100)
        .count();
    assert!(in_burst >= 40, "deauth frames in burst: {in_burst}");
    assert_eq!(after, 0, "burst must end");
    assert!(frames
        .iter()
        .any(|f| f.kind == FrameKind::WifiMgmt && f.channel == 36));
}

#[test]
fn mousejack_drives_esb_frames_and_ghost_band_carrier() {
    let mut w = RfWorld::new(3);
    let mut a = Adversary::mousejack((1.0, 1.5), 96, 4, Some(98));
    let frames = run(&mut a, &mut w, 20, WROOM);
    let esb: Vec<_> = frames.iter().filter(|f| f.kind == FrameKind::Esb).collect();
    assert!(esb.len() >= 30, "esb frames: {}", esb.len());
    assert!(esb.iter().all(|f| (96..100).contains(&f.channel)));
    let channels: std::collections::HashSet<_> = esb.iter().map(|f| f.channel).collect();
    assert!(channels.len() > 1, "ESB should hop across channels");
    assert!(w.rpd_at(WROOM, 98), "ghost-band implant carrier");
}

#[test]
fn ble_rotating_implant_keeps_one_identity_across_mac_rotation() {
    let mut w = RfWorld::new(4);
    let mut a = Adversary::ble_rotating_implant((2.4, 4.0), 1_000);
    let frames = run(&mut a, &mut w, 40, S3);
    let Adversary::BleRotatingImplant { rotations, .. } = &a else {
        unreachable!()
    };
    assert!(*rotations >= 4, "rotations: {rotations}");
    // Sim-level identity: every BLE frame, before and after rotation, comes from one EmitterId.
    let ids: std::collections::HashSet<_> = frames
        .iter()
        .filter(|f| f.kind == FrameKind::BleAdv)
        .map(|f| f.src)
        .collect();
    assert_eq!(ids.len(), 1, "one persistent emitter across rotations");
    assert_eq!(a.emitter_ids().len(), 1);

    // MAC differs per rotation, yet the structural fingerprint resolves to one device.
    let mac1 = a.current_mac().unwrap();
    run(&mut a, &mut w, 11, S3);
    let mac2 = a.current_mac().unwrap();
    assert_ne!(mac1, mac2, "MAC must rotate");
    let pdu = [
        0x02, 0x01, 0x1A, 0x02, 0x0A, 0x0C, 0x07, 0xFF, 0x4C, 0x00, 0x10, 0x05, 0x11, 0x22,
    ];
    let fp1 = build_ble_fingerprint(mac1, &pdu, 100, [-60, -60, -45]);
    let fp2 = build_ble_fingerprint(mac2, &pdu, 100, [-60, -60, -45]);
    assert_ne!(fp1.current_mac, fp2.current_mac);
    assert_eq!(fp1.structural_hash, fp2.structural_hash);
}

#[test]
fn subghz_replay_bursts_periodically() {
    let mut w = RfWorld::new(5);
    let mut a = Adversary::subghz_replay(433, 2_000, 600);
    let mut seen = Vec::new();
    for _ in 0..40 {
        let t = w.time_ms();
        a.apply(&mut w, t);
        seen.push(a.subghz_burst_mhz());
        w.step(100);
    }
    assert_eq!(seen[0], Some(433));
    assert_eq!(seen[5], Some(433));
    assert_eq!(seen[6], None);
    assert_eq!(seen[20], Some(433), "periodic repeat");
    assert_eq!(seen[26], None);
    assert_eq!(w.emitters().count(), 0, "sub-GHz adds no 2.4/5 GHz emitter");
}

#[test]
fn bt_skimmer_is_a_strong_close_range_ble_source_at_s3() {
    let mut w = RfWorld::new(6);
    let mut a = Adversary::bt_skimmer((3.0, 4.6));
    let frames = run(&mut a, &mut w, 10, S3);
    let ble: Vec<_> = frames
        .iter()
        .filter(|f| f.kind == FrameKind::BleAdv)
        .collect();
    assert!(ble.len() >= 30, "ble frames: {}", ble.len());
    assert!(ble.iter().all(|f| f.rssi > -42), "close-range: > -42 dBm");
}

#[test]
fn despawn_removes_emitters() {
    let mut w = RfWorld::new(7);
    let mut a = Adversary::evil_twin_deauth((5.0, 1.5), 36, 1_000);
    run(&mut a, &mut w, 2, C5);
    assert_eq!(w.emitters().count(), 2);
    a.despawn(&mut w);
    assert_eq!(w.emitters().count(), 0);
}

#[test]
fn controller_quiet_scenario_stays_quiet_and_unknown_falls_back() {
    for name in ["quiet", "no-such-scenario"] {
        let mut c = SimController::new(9, name);
        assert_eq!(c.scenario().name, "quiet");
        for _ in 0..50 {
            c.advance(100);
        }
        assert_eq!(c.world.time_ms(), 5_000);
        assert_eq!(c.world().emitters().count(), 0);
        assert!(c.active().is_empty());
    }
}

#[test]
fn controller_inject_and_clear() {
    let mut c = SimController::new(10, "quiet");
    let id = c.inject(Adversary::jammer((1.5, 1.0), 62));
    c.advance(100);
    c.advance(100);
    assert_eq!(c.active().len(), 1);
    assert!(c.world().rpd_at(WROOM, 62));
    c.clear(id);
    c.advance(100);
    assert!(c.active().is_empty());
    assert!(!c.world().rpd_at(WROOM, 62));
    c.clear(id); // idempotent
    c.clear(AdversaryId(999));
}

#[test]
fn red_team_incursion_walks_all_phases() {
    let mut c = SimController::new(42, "red-team-incursion");
    let (mut esb_ghost, mut deauth, mut jam, mut skim, mut sub, mut ble) =
        (false, false, false, false, false, false);
    let mut quiet_until_5s = true;
    for tick in 0..300u64 {
        c.advance(100);
        let t = (tick + 1) * 100;
        let hot = (0..=125u8)
            .filter(|&ch| c.world().rpd_at(WROOM, ch))
            .count();
        if t <= 4_900 && (hot > 0 || c.world().emitters().count() > 0) {
            quiet_until_5s = false;
        }
        esb_ghost |= (5_200..10_000).contains(&t) && c.world().rpd_at(WROOM, 98);
        jam |= (17_200..22_000).contains(&t) && hot > 40;
        sub |= c.subghz_burst_mhz() == Some(433);
        while let Some(f) = c.world.next_frame(C5) {
            deauth |=
                f.kind == FrameKind::Deauth && f.channel == 36 && (10_000..17_000).contains(&t);
        }
        while let Some(f) = c.world.next_frame(S3) {
            if f.kind == FrameKind::BleAdv && t >= 22_000 {
                skim |= f.rssi > -42;
                ble = true;
            }
        }
        c.world.next_frame(WROOM);
    }
    assert!(quiet_until_5s, "baseline must be quiet");
    assert!(esb_ghost && deauth && jam && skim && sub && ble);
    assert_eq!(c.active().len(), 3, "final phase holds three adversaries");
}

#[test]
fn red_team_scenario_ids_are_consistent() {
    let s = scenario_by_name("red-team-incursion").unwrap();
    let mut spawned = 0u32;
    for (_, ev) in s.timeline() {
        match ev {
            ScenarioEvent::Spawn(_) => spawned += 1,
            ScenarioEvent::Clear(AdversaryId(n)) => assert!(*n < spawned, "clear before spawn"),
        }
    }
    assert_eq!(spawned, s.spawn_count());
    assert!(scenario_by_name("nope").is_none());
}
