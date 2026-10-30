//! Adversary models: scripted attackers that perturb an [`RfWorld`] over time.
//!
//! Each [`Adversary`] lazily spawns its emitter(s) on the first [`Adversary::apply`] and keeps
//! them updated (hopping, MAC rotation, burst envelopes) on later calls. All randomness comes
//! from [`RfWorld::rng_mut`], so a given world seed always yields the same attack.
//! [`Adversary::despawn`] removes whatever the adversary put in the world.
use crate::world::{Emitter, EmitterId, EmitterKind, RfWorld};
use rand_core::Rng;

/// Stable handle for an adversary inside a `SimController` (or a [`Scenario`](crate::Scenario)
/// timeline), usable to clear it later.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdversaryId(pub u32);

/// A scripted attacker. Config fields are public; the `Option` / counter fields at the end of
/// each variant are runtime state owned by [`Adversary::apply`] (leave them at their
/// constructor defaults).
#[derive(Clone, Debug, PartialEq)]
pub enum Adversary {
    /// Layer-1 wideband jammer (80 MHz wide) centred on nRF channel `center_ch`.
    Jammer {
        pos: (f32, f32),
        tx_dbm: i8,
        center_ch: u8,
        emitter: Option<EmitterId>,
    },
    /// Wi-Fi evil twin on `wifi_ch` (5 GHz when >= 36) plus a deauth flood that runs at
    /// `deauth_fps` for the first `burst_ms` after spawning, then falls silent.
    EvilTwinDeauth {
        pos: (f32, f32),
        tx_dbm: i8,
        wifi_ch: u8,
        beacon_fps: u16,
        deauth_fps: u16,
        burst_ms: u64,
        start_ms: Option<u64>,
        ap: Option<EmitterId>,
        deauth: Option<EmitterId>,
    },
    /// MouseJack: an ESB keystroke injector hopping over `base_ch..base_ch + hop_span` every
    /// `hop_ms`, optionally with a ghost-band carrier implant on `ghost_ch`.
    MouseJackEsb {
        pos: (f32, f32),
        tx_dbm: i8,
        base_ch: u8,
        hop_span: u8,
        fps: u16,
        hop_ms: u64,
        ghost_ch: Option<u8>,
        next_hop_ms: u64,
        esb: Option<EmitterId>,
        carrier: Option<EmitterId>,
    },
    /// A BLE implant that rotates its (private) MAC every `rotate_ms`. The sim frame model does
    /// not carry MAC bytes, so the identity that persists across rotations is the world
    /// [`EmitterId`] ([`Adversary::emitter_ids`]); the current MAC is exposed via `mac`.
    BleRotatingImplant {
        pos: (f32, f32),
        tx_dbm: i8,
        fps: u16,
        rotate_ms: u64,
        mac: [u8; 6],
        rotations: u32,
        next_rotate_ms: u64,
        emitter: Option<EmitterId>,
    },
    /// Sub-GHz (e.g. 433 MHz) replay burst: `burst_ms` of every `period_ms`. Sub-GHz lies
    /// outside the 2.4/5 GHz world, so it adds no emitter; the operator-deck RTL-SDR view is
    /// [`Adversary::subghz_burst_mhz`].
    SubGhzReplay {
        freq_mhz: u16,
        period_ms: u64,
        burst_ms: u64,
        start_ms: Option<u64>,
        active: bool,
    },
    /// Close-range Bluetooth skimmer: a strong, chatty BLE advertiser right next to a sensor.
    BtSkimmer {
        pos: (f32, f32),
        tx_dbm: i8,
        fps: u16,
        adv_ch: u8,
        emitter: Option<EmitterId>,
    },
}

/// Get the live emitter in `slot`, (re-)adding `emitter` to the world if absent.
fn ensure(world: &mut RfWorld, slot: &mut Option<EmitterId>, emitter: Emitter) -> EmitterId {
    match *slot {
        Some(id) if world.emitter(id).is_some() => id,
        _ => {
            let id = world.add_emitter(emitter);
            *slot = Some(id);
            id
        }
    }
}

fn remove(world: &mut RfWorld, slot: &mut Option<EmitterId>) {
    if let Some(id) = slot.take() {
        world.remove_emitter(id);
    }
}

fn random_mac(world: &mut RfWorld) -> [u8; 6] {
    let r = world.rng_mut().next_u64().to_le_bytes();
    // Locally-administered, unicast (resolvable-private-address style).
    [(r[0] & 0xFC) | 0x02, r[1], r[2], r[3], r[4], r[5]]
}

impl Adversary {
    /// Wideband jammer near the WROOM, centred on nRF ch 62 (2462 MHz): >40 channels RPD-hot.
    pub fn jammer(pos: (f32, f32), center_ch: u8) -> Self {
        Self::Jammer {
            pos,
            tx_dbm: -30,
            center_ch,
            emitter: None,
        }
    }

    /// Evil twin AP + deauth burst on 5 GHz channel `wifi_ch`.
    pub fn evil_twin_deauth(pos: (f32, f32), wifi_ch: u8, burst_ms: u64) -> Self {
        Self::EvilTwinDeauth {
            pos,
            tx_dbm: -40,
            wifi_ch,
            beacon_fps: 10,
            deauth_fps: 40,
            burst_ms,
            start_ms: None,
            ap: None,
            deauth: None,
        }
    }

    /// MouseJack injector hopping over `base_ch..base_ch + hop_span`, with a ghost-band carrier
    /// implant on `ghost_ch` when given.
    pub fn mousejack(pos: (f32, f32), base_ch: u8, hop_span: u8, ghost_ch: Option<u8>) -> Self {
        Self::MouseJackEsb {
            pos,
            tx_dbm: -40,
            base_ch,
            hop_span: hop_span.max(1),
            fps: 20,
            hop_ms: 200,
            ghost_ch,
            next_hop_ms: 0,
            esb: None,
            carrier: None,
        }
    }

    /// BLE implant that rotates its MAC every `rotate_ms`.
    pub fn ble_rotating_implant(pos: (f32, f32), rotate_ms: u64) -> Self {
        Self::BleRotatingImplant {
            pos,
            tx_dbm: -40,
            fps: 10,
            rotate_ms,
            mac: [0x02, 0, 0, 0, 0, 0],
            rotations: 0,
            next_rotate_ms: 0,
            emitter: None,
        }
    }

    /// Sub-GHz replay of `burst_ms` every `period_ms` on `freq_mhz`.
    pub fn subghz_replay(freq_mhz: u16, period_ms: u64, burst_ms: u64) -> Self {
        Self::SubGhzReplay {
            freq_mhz,
            period_ms: period_ms.max(1),
            burst_ms,
            start_ms: None,
            active: false,
        }
    }

    /// Close-range BLE skimmer at `pos`.
    pub fn bt_skimmer(pos: (f32, f32)) -> Self {
        Self::BtSkimmer {
            pos,
            tx_dbm: -40,
            fps: 40,
            adv_ch: 37,
            emitter: None,
        }
    }

    /// Short stable label.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Jammer { .. } => "jammer",
            Self::EvilTwinDeauth { .. } => "evil-twin-deauth",
            Self::MouseJackEsb { .. } => "mousejack-esb",
            Self::BleRotatingImplant { .. } => "ble-rotating-implant",
            Self::SubGhzReplay { .. } => "subghz-replay",
            Self::BtSkimmer { .. } => "bt-skimmer",
        }
    }

    /// Spawn / update this adversary's emitter(s) for the interval starting at `t_ms`.
    pub fn apply(&mut self, world: &mut RfWorld, t_ms: u64) {
        match self {
            Self::Jammer {
                pos,
                tx_dbm,
                center_ch,
                emitter,
            } => {
                ensure(
                    world,
                    emitter,
                    Emitter {
                        pos: *pos,
                        tx_dbm: *tx_dbm,
                        channel: *center_ch,
                        kind: EmitterKind::Jammer,
                    },
                );
            }
            Self::EvilTwinDeauth {
                pos,
                tx_dbm,
                wifi_ch,
                beacon_fps,
                deauth_fps,
                burst_ms,
                start_ms,
                ap,
                deauth,
            } => {
                let start = *start_ms.get_or_insert(t_ms);
                ensure(
                    world,
                    ap,
                    Emitter {
                        pos: *pos,
                        tx_dbm: *tx_dbm,
                        channel: *wifi_ch,
                        kind: EmitterKind::WifiAp {
                            beacon_fps: *beacon_fps,
                        },
                    },
                );
                let fps = if t_ms.saturating_sub(start) < *burst_ms {
                    *deauth_fps
                } else {
                    0
                };
                let id = ensure(
                    world,
                    deauth,
                    Emitter {
                        pos: *pos,
                        tx_dbm: *tx_dbm,
                        channel: *wifi_ch,
                        kind: EmitterKind::Deauth { fps },
                    },
                );
                if let Some(e) = world.emitter_mut(id) {
                    e.kind = EmitterKind::Deauth { fps };
                }
            }
            Self::MouseJackEsb {
                pos,
                tx_dbm,
                base_ch,
                hop_span,
                fps,
                hop_ms,
                ghost_ch,
                next_hop_ms,
                esb,
                carrier,
            } => {
                if let Some(g) = *ghost_ch {
                    ensure(
                        world,
                        carrier,
                        Emitter {
                            pos: *pos,
                            tx_dbm: *tx_dbm,
                            channel: g,
                            kind: EmitterKind::Carrier,
                        },
                    );
                }
                let fresh = esb.is_none_or(|id| world.emitter(id).is_none());
                if fresh || t_ms >= *next_hop_ms {
                    let hop = (world.rng_mut().next_u32() % u32::from(*hop_span)) as u8;
                    let channel = base_ch.saturating_add(hop).min(125);
                    let id = ensure(
                        world,
                        esb,
                        Emitter {
                            pos: *pos,
                            tx_dbm: *tx_dbm,
                            channel,
                            kind: EmitterKind::Esb { fps: *fps },
                        },
                    );
                    if let Some(e) = world.emitter_mut(id) {
                        e.channel = channel;
                    }
                    *next_hop_ms = t_ms + *hop_ms;
                }
            }
            Self::BleRotatingImplant {
                pos,
                tx_dbm,
                fps,
                rotate_ms,
                mac,
                rotations,
                next_rotate_ms,
                emitter,
            } => {
                ensure(
                    world,
                    emitter,
                    Emitter {
                        pos: *pos,
                        tx_dbm: *tx_dbm,
                        channel: 37,
                        kind: EmitterKind::BleAdv { fps: *fps },
                    },
                );
                if *rotations == 0 || t_ms >= *next_rotate_ms {
                    *mac = random_mac(world);
                    *rotations += 1;
                    *next_rotate_ms = t_ms + *rotate_ms;
                }
            }
            Self::SubGhzReplay {
                period_ms,
                burst_ms,
                start_ms,
                active,
                ..
            } => {
                let start = *start_ms.get_or_insert(t_ms);
                *active = (t_ms.saturating_sub(start) % *period_ms) < *burst_ms;
            }
            Self::BtSkimmer {
                pos,
                tx_dbm,
                fps,
                adv_ch,
                emitter,
            } => {
                ensure(
                    world,
                    emitter,
                    Emitter {
                        pos: *pos,
                        tx_dbm: *tx_dbm,
                        channel: *adv_ch,
                        kind: EmitterKind::BleAdv { fps: *fps },
                    },
                );
            }
        }
    }

    /// Remove everything this adversary put into `world` and reset its runtime state.
    pub fn despawn(&mut self, world: &mut RfWorld) {
        match self {
            Self::Jammer { emitter, .. }
            | Self::BleRotatingImplant { emitter, .. }
            | Self::BtSkimmer { emitter, .. } => remove(world, emitter),
            Self::EvilTwinDeauth {
                start_ms,
                ap,
                deauth,
                ..
            } => {
                remove(world, ap);
                remove(world, deauth);
                *start_ms = None;
            }
            Self::MouseJackEsb {
                next_hop_ms,
                esb,
                carrier,
                ..
            } => {
                remove(world, esb);
                remove(world, carrier);
                *next_hop_ms = 0;
            }
            Self::SubGhzReplay {
                start_ms, active, ..
            } => {
                *start_ms = None;
                *active = false;
            }
        }
    }

    /// World emitters currently owned by this adversary.
    pub fn emitter_ids(&self) -> Vec<EmitterId> {
        match self {
            Self::Jammer { emitter, .. }
            | Self::BleRotatingImplant { emitter, .. }
            | Self::BtSkimmer { emitter, .. } => emitter.iter().copied().collect(),
            Self::EvilTwinDeauth { ap, deauth, .. } => {
                ap.iter().chain(deauth.iter()).copied().collect()
            }
            Self::MouseJackEsb { esb, carrier, .. } => {
                esb.iter().chain(carrier.iter()).copied().collect()
            }
            Self::SubGhzReplay { .. } => Vec::new(),
        }
    }

    /// Frequency (MHz) of an in-progress sub-GHz burst, if this is a replaying `SubGhzReplay`.
    pub fn subghz_burst_mhz(&self) -> Option<u16> {
        match self {
            Self::SubGhzReplay {
                freq_mhz, active, ..
            } if *active => Some(*freq_mhz),
            _ => None,
        }
    }

    /// Current BLE MAC for a `BleRotatingImplant`.
    pub fn current_mac(&self) -> Option<[u8; 6]> {
        match self {
            Self::BleRotatingImplant { mac, .. } => Some(*mac),
            _ => None,
        }
    }
}
