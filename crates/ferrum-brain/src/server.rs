//! Web server: drives the [`Orchestrator`] on a dedicated tick thread and streams every
//! [`SwarmSnapshot`] as a JSON text frame over WebSocket to the dashboard, which this server
//! also serves at `/`.
//!
//! # Concurrency
//! `Orchestrator` owns `Rc<RefCell<RfWorld>>` handles, so it is `!Send` and cannot live inside a
//! `tokio::spawn`ed task. Instead a single `std::thread` *constructs* it (from a `Send` factory
//! closure) and owns it for its whole life, so it never crosses a thread boundary:
//!
//! ```text
//!   tick thread ── watch::Sender<SwarmSnapshot> ──▶ axum /ws handlers (one per client)
//!   tick thread ◀── mpsc::Receiver<OperatorCommand> ── axum state (inbound commands)
//! ```
//!
//! Snapshots are owned `Serialize + Clone` data, so they cross the thread boundary freely. A
//! `watch` channel means a slow or new client always sees the *latest* snapshot (intermediate
//! ones are coalesced) and there is no lagged-receiver error path. A client that errors or
//! disconnects ends only its own handler task.

use std::net::SocketAddr;
use std::sync::mpsc::{self, TryRecvError};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::orchestrator::Orchestrator;
use crate::snapshot::{OperatorCommand, SwarmSnapshot};

/// The operator dashboard, embedded at compile time.
const DASHBOARD_HTML: &str = include_str!("../../../dashboard/ferrum_cyberswarm_deck.html");

/// Shared axum state.
#[derive(Clone)]
struct AppState {
    /// Latest snapshot published by the tick thread.
    snapshots: watch::Receiver<Option<SwarmSnapshot>>,
    /// Inbound operator commands for the tick thread (populated by the WS handler in Task 11).
    #[allow(dead_code)]
    commands: mpsc::Sender<OperatorCommand>,
}

/// Run `orch` on the tick thread: apply queued commands, tick, publish, then sleep to the
/// orchestrator's current tick rate. Exits when the command channel's sender is dropped (the
/// server has shut down).
fn tick_loop(
    mut orch: Orchestrator,
    tick_hz: u8,
    snapshots: watch::Sender<Option<SwarmSnapshot>>,
    commands: mpsc::Receiver<OperatorCommand>,
) {
    orch.apply_command(OperatorCommand::SetTickHz(tick_hz));
    let mut next = Instant::now();
    loop {
        loop {
            match commands.try_recv() {
                Ok(cmd) => orch.apply_command(cmd),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        let snap = orch.tick();
        let hz = u64::from(snap.scenario.tick_hz.max(1));
        // `send_replace` stores the value even when no receiver is currently subscribed.
        snapshots.send_replace(Some(snap));

        let period = Duration::from_millis((1000 / hz).max(1));
        next += period;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            // Fell behind (slow tick or a rate change): do not burst to catch up.
            next = now;
        }
    }
}

async fn index() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| client_loop(socket, state))
}

/// Per-client loop: forward each new snapshot until the client goes away.
async fn client_loop(socket: WebSocket, state: AppState) {
    let (mut tx, mut rx) = socket.split();
    let mut snapshots = state.snapshots.clone();
    // Treat the current value as unseen so a new client gets a frame immediately.
    snapshots.mark_changed();
    loop {
        tokio::select! {
            changed = snapshots.changed() => {
                if changed.is_err() {
                    break; // tick thread gone
                }
                let json = match &*snapshots.borrow_and_update() {
                    None => continue, // tick thread has not produced a first snapshot yet
                    Some(snap) => match serde_json::to_string(snap) {
                        Ok(j) => j,
                        Err(e) => {
                            tracing::error!("snapshot serialisation failed: {e}");
                            continue;
                        }
                    },
                };
                if tx.send(Message::Text(json)).await.is_err() {
                    break; // client write failed: drop only this client
                }
            }
            incoming = rx.next() => match incoming {
                // Inbound operator commands are wired up in Task 11; ignore other frames.
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ws", get(ws_upgrade))
        .with_state(state)
}

/// Handle to a running tick thread: the state the HTTP side needs.
pub struct SwarmHandle {
    state: AppState,
}

/// Start the tick thread, which builds the orchestrator itself via `make` (so the `!Send`
/// value never crosses threads), and return the channels to talk to it.
///
/// Blocks briefly until construction finishes so a bad scenario name (or any other build error)
/// is returned here instead of leaving a dead thread behind. Synchronous on purpose: the
/// orchestrator never enters an async context, so the futures below stay `Send`.
pub fn spawn_tick_thread<F>(make: F, tick_hz: u8) -> anyhow::Result<SwarmHandle>
where
    F: FnOnce() -> anyhow::Result<Orchestrator> + Send + 'static,
{
    let (snap_tx, snap_rx) = watch::channel(None);
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel::<anyhow::Result<()>>();
    std::thread::Builder::new()
        .name("ferrum-tick".into())
        .spawn(move || match make() {
            Ok(orch) => {
                let _ = ready_tx.send(Ok(()));
                tick_loop(orch, tick_hz, snap_tx, cmd_rx);
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
            }
        })?;
    ready_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("tick thread exited before reporting startup"))??;
    Ok(SwarmHandle {
        state: AppState {
            snapshots: snap_rx,
            commands: cmd_tx,
        },
    })
}

/// Serve `/` and `/ws` for a running swarm on an already-bound listener (tests pass an
/// ephemeral-port listener). Returns only on a server error.
pub async fn serve_listener(listener: TcpListener, swarm: SwarmHandle) -> anyhow::Result<()> {
    axum::serve(listener, router(swarm.state)).await?;
    Ok(())
}

/// Bind `127.0.0.1:port`, build the orchestrator on the tick thread with `make`, run it at
/// `tick_hz` and serve `/` and `/ws`. Errors (bind failure, unknown scenario) are returned.
pub async fn serve<F>(make: F, port: u16, tick_hz: u8) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<Orchestrator> + Send + 'static,
{
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;
    let swarm = spawn_tick_thread(make, tick_hz)?;
    tracing::info!(
        "ferrum-brain listening on http://{}",
        listener.local_addr()?
    );
    serve_listener(listener, swarm).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_tungstenite::connect_async;

    async fn start(tick_hz: u8) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let swarm =
            spawn_tick_thread(|| Orchestrator::new(42, "red-team-incursion"), tick_hz).unwrap();
        tokio::spawn(async move {
            let _ = serve_listener(listener, swarm).await;
        });
        addr
    }

    async fn next_json<S>(ws: &mut S) -> serde_json::Value
    where
        S: futures_util::Stream<
                Item = Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        loop {
            let msg = timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("timed out waiting for a snapshot")
                .expect("stream ended")
                .expect("ws error");
            if let tokio_tungstenite::tungstenite::Message::Text(t) = msg {
                return serde_json::from_str(&t).expect("snapshot is valid JSON");
            }
        }
    }

    #[tokio::test]
    async fn test_two_clients_one_drop() {
        let addr = start(50).await;
        let url = format!("ws://{addr}/ws");
        let (mut a, _) = connect_async(&url).await.unwrap();
        let (mut b, _) = connect_async(&url).await.unwrap();

        let a1 = next_json(&mut a).await;
        let b1 = next_json(&mut b).await;
        assert!(a1.get("tick").is_some() && b1.get("tick").is_some());

        drop(a);

        let t1 = next_json(&mut b).await["tick"].as_u64().unwrap();
        // Keep reading well past the drop: B must keep advancing.
        let mut last = t1;
        for _ in 0..10 {
            last = next_json(&mut b).await["tick"].as_u64().unwrap();
        }
        assert!(last > t1, "client B stopped advancing after A dropped");
    }

    #[tokio::test]
    async fn test_unknown_scenario_is_a_startup_error() {
        let r = spawn_tick_thread(|| Orchestrator::new(1, "no-such-scenario"), 10);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn test_index_serves_dashboard() {
        let addr = start(10).await;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&buf).to_string();
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "{}",
            &resp[..60.min(resp.len())]
        );
        assert!(resp.to_lowercase().contains("content-type: text/html"));
        assert!(resp.to_lowercase().contains("ferrum"));
    }
}
