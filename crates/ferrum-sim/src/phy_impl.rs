//! Simulated PHYs: the `ferrum-hal` traits implemented over a shared [`RfWorld`].
//!
//! All four PHYs of one node hold a clone of the same [`SharedWorld`] handle (single-threaded;
//! callers must not hold a `borrow_mut` on the world across an agent `tick()`).
use crate::world::RfWorld;
use ferrum_hal::{Clock, PacketSniffer, SpectrumScanner, Transport};
use ferrum_proto::NodeId;
use std::cell::RefCell;
use std::convert::Infallible;
use std::rc::Rc;

use crate::world::SimFrame;

/// A world shared between the orchestrator (which steps it) and the node PHYs (which read it).
pub type SharedWorld = Rc<RefCell<RfWorld>>;

/// Spectrum scanner for one node: reads RPD / RSSI of the tuned channel from the world.
pub struct SimScanner {
    world: SharedWorld,
    node: NodeId,
    channel: u8,
}

impl SimScanner {
    pub fn new(world: SharedWorld, node: NodeId) -> Self {
        Self {
            world,
            node,
            channel: 0,
        }
    }
}

impl SpectrumScanner for SimScanner {
    fn set_channel(&mut self, ch: u8) {
        self.channel = ch;
    }
    fn read_rpd(&mut self) -> bool {
        self.world.borrow().rpd_at(self.node, self.channel)
    }
    fn sample_rssi(&mut self) -> i8 {
        self.world.borrow().rssi_at(self.node, self.channel)
    }
}

/// Packet sniffer for one node: drains the frames the world generated for it.
pub struct SimSniffer {
    world: SharedWorld,
    node: NodeId,
}

impl SimSniffer {
    pub fn new(world: SharedWorld, node: NodeId) -> Self {
        Self { world, node }
    }
}

impl PacketSniffer for SimSniffer {
    type Frame = SimFrame;
    fn next_frame(&mut self) -> Option<SimFrame> {
        self.world.borrow_mut().next_frame(self.node)
    }
}

/// ESP-NOW stand-in: `send` queues an uplink datagram in the world
/// ([`RfWorld::pop_uplink`]), `recv` pops a downlink datagram ([`RfWorld::push_downlink`]).
/// Infallible: always `Ok`.
pub struct SimTransport {
    world: SharedWorld,
    node: NodeId,
}

impl SimTransport {
    pub fn new(world: SharedWorld, node: NodeId) -> Self {
        Self { world, node }
    }
}

impl Transport for SimTransport {
    type Error = Infallible;

    fn send(&mut self, buf: &[u8]) -> Result<(), Infallible> {
        self.world.borrow_mut().push_uplink(self.node, buf);
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        match self.world.borrow_mut().pop_downlink(self.node) {
            Some(d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
}

/// Clock reading the world's simulated time.
pub struct SimClock {
    world: SharedWorld,
}

impl SimClock {
    pub fn new(world: SharedWorld) -> Self {
        Self { world }
    }
}

impl Clock for SimClock {
    fn now_ms(&self) -> u64 {
        self.world.borrow().time_ms()
    }
}
