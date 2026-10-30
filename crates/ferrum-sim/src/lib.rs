//! `ferrum-sim` — seeded RF-world simulator for the Ferret swarm (`std`).
//!
//! * [`phys`] — log-distance path-loss and RSSI trilateration.
//! * [`world`] — [`RfWorld`]: emitters, a seeded `Pcg64`, simulated time, and the per-node
//!   readouts (RPD / RSSI / sniffed frames) the node agents consume.
//! * [`phy_impl`] — [`SimScanner`], [`SimSniffer`], [`SimTransport`], [`SimClock`]: the
//!   `ferrum-hal` traits implemented on top of a shared [`RfWorld`].

pub mod phy_impl;
pub mod phys;
pub mod world;

pub use phy_impl::{SharedWorld, SimClock, SimScanner, SimSniffer, SimTransport};
pub use phys::{rssi_from_distance, trilaterate};
pub use world::{Emitter, EmitterId, EmitterKind, RfWorld, SimFrame};
