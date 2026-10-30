//! End-to-end: the real node agents driven by the sim PHYs turn world stimuli into telemetry.
use ferrum_c5_scout::C5Agent;
use ferrum_hal::NodeStatus;
use ferrum_proto::NodeId;
use ferrum_s3_sense::S3Agent;
use ferrum_sim::world::{Emitter, EmitterKind};
use ferrum_sim::{RfWorld, SharedWorld, SimClock, SimScanner, SimSniffer, SimTransport};
use ferrum_wroom_nrf::WroomAgent;
use std::cell::RefCell;
use std::rc::Rc;

fn world(seed: u64) -> SharedWorld {
    Rc::new(RefCell::new(RfWorld::new(seed)))
}

macro_rules! phys {
    ($w:expr, $node:expr) => {
        (
            SimScanner::new($w.clone(), $node),
            SimSniffer::new($w.clone(), $node),
            SimTransport::new($w.clone(), $node),
            SimClock::new($w.clone()),
        )
    };
}

fn online(s: NodeStatus) -> ferrum_proto::NodeTelemetry {
    match s {
        NodeStatus::Online(t) => t,
        NodeStatus::Offline => panic!("sim transport is infallible"),
    }
}

#[test]
fn quiet_world_yields_quiet_telemetry() {
    let w = world(1);
    let (a, b, c, d) = phys!(w, NodeId::WroomDualNrf);
    let mut wroom = WroomAgent::new(a, b, c, d);
    let (a, b, c, d) = phys!(w, NodeId::Esp32C5Scout);
    let mut c5 = C5Agent::new(a, b, c, d);
    let (a, b, c, d) = phys!(w, NodeId::XiaoS3Sense);
    let mut s3 = S3Agent::new(a, b, c, d);
    w.borrow_mut().step(1000);
    let t = online(wroom.tick());
    assert_eq!(
        (t.ghost_band_hits, t.esb_hid_frames, t.deauth_disassoc_cnt),
        (0, 0, 0)
    );
    assert!(t.peak_anomaly_rssi <= -90);
    let t = online(c5.tick());
    assert_eq!((t.deauth_disassoc_cnt, t.eapol_handshake_cnt), (0, 0));
    let t = online(s3.tick());
    assert_eq!((t.deauth_disassoc_cnt, t.ble_adv_fps), (0, 0));
}

#[test]
fn ghost_band_implant_and_mousejack_reach_wroom_telemetry() {
    let w = world(2);
    let (a, b, c, d) = phys!(w, NodeId::WroomDualNrf);
    let mut wroom = WroomAgent::new(a, b, c, d);
    {
        let mut wb = w.borrow_mut();
        wb.add_emitter(Emitter {
            pos: (1.0, 0.5),
            tx_dbm: -40,
            channel: 98,
            kind: EmitterKind::Carrier,
        });
        wb.add_emitter(Emitter {
            pos: (1.0, 0.5),
            tx_dbm: -40,
            channel: 98,
            kind: EmitterKind::Esb { fps: 8 },
        });
        wb.step(1000);
    }
    let t = online(wroom.tick());
    assert!(t.ghost_band_hits >= 1, "ghost hits {}", t.ghost_band_hits);
    assert_eq!(t.esb_hid_frames, 8);
    assert!(t.peak_anomaly_rssi > -64);
}

#[test]
fn deauth_and_eapol_reach_c5_and_ble_reaches_s3() {
    let w = world(3);
    let (a, b, c, d) = phys!(w, NodeId::Esp32C5Scout);
    let mut c5 = C5Agent::new(a, b, c, d);
    let (a, b, c, d) = phys!(w, NodeId::XiaoS3Sense);
    let mut s3 = S3Agent::new(a, b, c, d);
    {
        let mut wb = w.borrow_mut();
        wb.add_emitter(Emitter {
            pos: (6.5, 0.5),
            tx_dbm: -40,
            channel: 36,
            kind: EmitterKind::Deauth { fps: 40 },
        });
        wb.add_emitter(Emitter {
            pos: (6.5, 0.5),
            tx_dbm: -40,
            channel: 36,
            kind: EmitterKind::Eapol { fps: 4 },
        });
        wb.add_emitter(Emitter {
            pos: (3.0, 4.5),
            tx_dbm: -40,
            channel: 37,
            kind: EmitterKind::BleAdv { fps: 60 },
        });
        wb.step(1000);
    }
    let t = online(c5.tick());
    assert_eq!(t.deauth_disassoc_cnt, 40);
    assert_eq!(t.eapol_handshake_cnt, 4);
    assert_eq!(t.primary_channel, 36);
    let t = online(s3.tick());
    assert_eq!(t.ble_adv_fps, 60);
    // The agents relayed sealed telemetry through the sim mesh.
    let mut senders = Vec::new();
    while let Some((n, bytes)) = w.borrow_mut().pop_uplink() {
        assert_eq!(bytes.len(), ferrum_proto::NodeTelemetry::SIZE);
        senders.push(n);
    }
    assert_eq!(senders, vec![NodeId::Esp32C5Scout, NodeId::XiaoS3Sense]);
}
