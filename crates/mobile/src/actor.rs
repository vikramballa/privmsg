//! The loop that owns the messenger. It runs on a thread of its own; the
//! app talks to it with [`Command`]s and hears back through the shared view
//! and the [`Listener`].
//!
//! It does what the desktop app's event loop does (receive, keep addresses
//! maintained, decoys, auto-sleep, disappearing messages), plus what a phone
//! needs: it never gives up. Tor or the mixnet failing to connect, the
//! connections dying when the phone changes networks, or the app coming
//! back after iOS froze it all end in another attempt, not an exit.

use std::future::Future;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use privmsg_node::app::{Event, Node, MAX_TEXT};
use privmsg_node::decoy::Scheduler;
use privmsg_node::store::Settings;
use privmsg_node::wire::MessageId;
use privmsg_transport::{Mux, Network};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::view::View;
use crate::{ConnectionStatus, Listener};

/// How long after a failed connection it tries again by itself.
pub(crate) const RETRY_AFTER: Duration = Duration::from_secs(20);

/// How often addresses are checked for rotation and retirement, and
/// disappearing messages for expiry.
const MAINTENANCE_EVERY: Duration = Duration::from_secs(60);

/// Away from the screen this long (iOS freezes apps in the background),
/// the connections are assumed dead and made again.
const STALE_AFTER: Duration = Duration::from_secs(30);

/// How long closing connections may take before they are dropped.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The decoy interval used when the app turns decoys on, as the desktop's
/// `privmsg decoys on` does.
pub(crate) const DEFAULT_DECOY_INTERVAL: u32 = 10;

type Reply<T> = oneshot::Sender<Result<T>>;

pub(crate) enum Command {
    Invite(String, Reply<String>),
    Accept {
        code: String,
        name: String,
        reply: Reply<()>,
    },
    Send {
        name: String,
        text: String,
        reply: Reply<()>,
    },
    SetTimer {
        name: String,
        after: Option<u64>,
        reply: Reply<()>,
    },
    Delete {
        name: String,
        id: MessageId,
        everyone: bool,
        reply: Reply<()>,
    },
    Clear {
        name: String,
        everyone: bool,
        reply: Reply<()>,
    },
    Remove(String, Reply<()>),
    Rotate(String, Reply<()>),
    SafetyNumber(String, Reply<String>),
    MarkRead(String),
    SetSettings(Settings, Reply<()>),
    CheckPassphrase(String, oneshot::Sender<bool>),
    /// The app is on screen again after `away` in the background.
    Foreground {
        away: Duration,
    },
    /// Try connecting now rather than waiting for the next attempt.
    Retry,
    Shutdown(oneshot::Sender<()>),
}

impl Command {
    /// Whether it can be answered without the network.
    fn is_local(&self) -> bool {
        matches!(
            self,
            Command::SafetyNumber(..)
                | Command::Delete {
                    everyone: false,
                    ..
                }
                | Command::Clear {
                    everyone: false,
                    ..
                }
                | Command::MarkRead(_)
                | Command::SetSettings(..)
                | Command::CheckPassphrase(..)
                | Command::Foreground { .. }
                | Command::Retry
        )
    }

    /// Answer a command that needs the network while there is none.
    fn refuse(self, why: &str) {
        fn error<T>(why: &str) -> Result<T> {
            Err(anyhow!("Not connected yet ({why}). Try again in a moment."))
        }
        match self {
            Command::Invite(_, reply) => drop(reply.send(error(why))),
            Command::Accept { reply, .. }
            | Command::Send { reply, .. }
            | Command::SetTimer { reply, .. }
            | Command::Delete { reply, .. }
            | Command::Clear { reply, .. }
            | Command::Remove(_, reply)
            | Command::Rotate(_, reply) => drop(reply.send(error(why))),
            other => debug_assert!(other.is_local(), "refused a local command"),
        }
    }
}

/// The view and the app's listener, shared with the [`Messenger`](crate::Messenger).
pub(crate) struct Shared {
    pub view: Mutex<View>,
    pub listener: Arc<dyn Listener>,
}

impl Shared {
    pub(crate) fn status(&self, status: ConnectionStatus) {
        self.view.lock().expect("view lock").status = status.clone();
        self.listener.status(status);
    }

    /// Refresh the view from `node`; tell the app if anything changed.
    fn publish(&self, node: &Node, scheduler: Option<&Scheduler>) {
        let changed = self
            .view
            .lock()
            .expect("view lock")
            .refresh(node, scheduler.map_or(0, Scheduler::queued));
        if changed {
            self.listener.changed();
        }
    }

    fn notice(&self, text: String) {
        self.listener.notice(text);
    }
}

/// What the loop does after a command.
enum Flow {
    Continue,
    /// Close the connections and make them again.
    Reconnect,
    Stop(oneshot::Sender<()>),
}

/// Run until shut down. `network` makes the network (starting Tor first,
/// for the real one); it is called again if it fails.
pub(crate) async fn run<N, F, Fut>(
    mut node: Node,
    mut network: F,
    mut commands: UnboundedReceiver<Command>,
    shared: Arc<Shared>,
) where
    N: Network,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<N>>,
{
    let mut scheduler = new_scheduler(&node);
    shared.publish(&node, scheduler.as_ref());

    // The network. Nothing borrows the node while it comes up.
    let net = loop {
        let making = network();
        tokio::pin!(making);
        let result = loop {
            tokio::select! {
                result = &mut making => break result,
                cmd = commands.recv() => match local(&mut node, cmd, "starting Tor") {
                    ControlFlow::Continue(()) => shared.publish(&node, scheduler.as_ref()),
                    ControlFlow::Break(stop) => return finish(stop, &shared),
                },
            }
        };
        match result {
            Ok(net) => break net,
            Err(e) => {
                tracing::warn!("network did not start: {e:#}");
                if let ControlFlow::Break(stop) =
                    wait_to_retry(&mut node, scheduler.as_ref(), &shared, &mut commands, &e).await
                {
                    return finish(stop, &shared);
                }
            }
        }
    };

    let mut mux = Mux::new(net);
    let stop = 'session: loop {
        shared.status(ConnectionStatus::Connecting);
        let slots = node.all_slots();
        let mut deferred = Vec::new();
        let mut stopping = None;
        let connected = {
            let connecting = node.connect(&mut mux, &slots);
            tokio::pin!(connecting);
            loop {
                tokio::select! {
                    result = &mut connecting => break Some(result),
                    cmd = commands.recv() => match cmd {
                        // Shutting down doesn't wait for the mixnet.
                        None => {
                            stopping = Some(None);
                            break None;
                        }
                        Some(Command::Shutdown(stop)) => {
                            stopping = Some(Some(stop));
                            break None;
                        }
                        Some(cmd) if cmd.is_local() => deferred.push(cmd),
                        Some(cmd) => cmd.refuse("connecting to the mixnet"),
                    },
                }
            }
        };
        for cmd in deferred {
            // Shutdown is never deferred, so this only answers.
            let _ = local(&mut node, Some(cmd), "connecting");
        }
        if let Some(stop) = stopping {
            break 'session stop;
        }
        match connected {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                tracing::warn!("could not connect: {e:#}");
                mux.reset(CLOSE_TIMEOUT).await;
                match wait_to_retry(&mut node, scheduler.as_ref(), &shared, &mut commands, &e).await
                {
                    ControlFlow::Continue(()) => continue 'session,
                    ControlFlow::Break(stop) => break 'session stop,
                }
            }
            None => unreachable!("only a shutdown stops connecting early"),
        }
        if let Err(e) = node.maintain(&mut mux).await {
            tracing::warn!("address maintenance failed: {e:#}");
        }
        shared.status(ConnectionStatus::Online);

        match online(&mut node, &mut mux, &mut scheduler, &mut commands, &shared).await {
            Flow::Continue => unreachable!("the online loop only returns to reconnect or stop"),
            Flow::Reconnect => {
                mux.reset(CLOSE_TIMEOUT).await;
                continue 'session;
            }
            Flow::Stop(stop) => break 'session Some(stop),
        }
    };

    if let Some(s) = scheduler.as_mut() {
        for (name, text) in s.drain() {
            if let Err(e) = node.send_text(&mut mux, &name, &text).await {
                tracing::warn!("queued message to {name} not sent: {e:#}");
            }
        }
    }
    mux.close().await;
    finish(stop, &shared);
}

/// Connected: receive and act until the connections need making again, or
/// the app shuts down.
async fn online<N: Network>(
    node: &mut Node,
    mux: &mut Mux<N>,
    scheduler: &mut Option<Scheduler>,
    commands: &mut UnboundedReceiver<Command>,
    shared: &Shared,
) -> Flow {
    let mut maintenance =
        tokio::time::interval_at(Instant::now() + MAINTENANCE_EVERY, MAINTENANCE_EVERY);
    let mut last_active = Instant::now();
    loop {
        shared.publish(node, scheduler.as_ref());

        let next_tick = scheduler.as_ref().and_then(Scheduler::next_due);
        let tick_at = next_tick.as_ref().map_or_else(far_future, |(_, at)| *at);
        // Decoys keep sending by design, so they keep the sender up.
        let idle_limit = node
            .settings()
            .auto_sleep
            .filter(|_| scheduler.is_none())
            .map(|mins| Duration::from_secs(u64::from(mins) * 60));
        let sleep_at = idle_limit.map_or_else(far_future, |limit| last_active + limit);

        tokio::select! {
            msg = mux.recv() => match msg {
                Ok((slot, msg)) => match node.handle_incoming(mux, &slot, &msg.payload).await {
                    Ok(events) => {
                        for event in events {
                            announce(shared, scheduler, event);
                        }
                    }
                    Err(e) => tracing::info!("ignored an incoming message: {e:#}"),
                },
                Err(e) => {
                    tracing::warn!("connection lost: {e:#}");
                    return Flow::Reconnect;
                }
            },
            cmd = commands.recv() => {
                let Some(cmd) = cmd else {
                    let (stop, _) = oneshot::channel();
                    return Flow::Stop(stop);
                };
                if !matches!(cmd, Command::MarkRead(_) | Command::Foreground { .. }) {
                    last_active = Instant::now();
                }
                let waking = !mux.is_awake() && !cmd.is_local();
                if waking {
                    shared.status(ConnectionStatus::Connecting);
                }
                let flow = command(node, mux, scheduler, shared, cmd).await;
                if waking {
                    shared.status(if mux.is_awake() {
                        ConnectionStatus::Online
                    } else {
                        ConnectionStatus::Resting
                    });
                }
                match flow {
                    Flow::Continue => {}
                    other => return other,
                }
            }
            _ = tokio::time::sleep_until(tick_at), if next_tick.is_some() => {
                let (name, _) = next_tick.expect("tick scheduled");
                let s = scheduler.as_mut().expect("decoys on");
                match s.tick(&name) {
                    Some(text) => {
                        if let Err(e) = node.send_text(mux, &name, &text).await {
                            shared.notice(format!("A message to {} was not sent: {e:#}", clean(&name)));
                        }
                    }
                    None => {
                        if let Err(e) = node.send_decoy(mux, &name).await {
                            tracing::warn!("decoy to {name} not sent: {e:#}");
                        }
                    }
                }
            }
            _ = maintenance.tick() => {
                if let Err(e) = node.maintain(mux).await {
                    tracing::warn!("address maintenance failed: {e:#}");
                }
            }
            _ = tokio::time::sleep_until(sleep_at), if idle_limit.is_some() && mux.is_awake() => {
                mux.sleep().await;
                shared.status(ConnectionStatus::Resting);
            }
        }
    }
}

/// Act on a command while connected.
async fn command<N: Network>(
    node: &mut Node,
    mux: &mut Mux<N>,
    scheduler: &mut Option<Scheduler>,
    shared: &Shared,
    cmd: Command,
) -> Flow {
    match cmd {
        Command::Invite(name, reply) => {
            let result = match valid_name(&name) {
                Ok(name) => node.create_invite(mux, name).await,
                Err(e) => Err(e),
            };
            drop(reply.send(result));
        }
        Command::Accept { code, name, reply } => {
            let result = match valid_name(&name) {
                Ok(name) => node.accept_invite(mux, code.trim(), name).await.map(|()| {
                    if let Some(s) = scheduler.as_mut() {
                        s.add(name.to_string());
                    }
                }),
                Err(e) => Err(e),
            };
            drop(reply.send(result));
        }
        Command::Send { name, text, reply } => {
            let result = if text.trim().is_empty() {
                Err(anyhow!("Type a message first."))
            } else if text.len() > MAX_TEXT {
                Err(anyhow!(
                    "That message is too long ({} bytes; the limit is {MAX_TEXT}). Split it up.",
                    text.len()
                ))
            } else {
                match scheduler.as_mut() {
                    Some(s) => node.contact(&name).map(|_| s.queue(&name, text)),
                    None => node.send_text(mux, &name, &text).await,
                }
            };
            drop(reply.send(result));
        }
        Command::SetTimer { name, after, reply } => {
            drop(reply.send(node.set_timer(mux, &name, after).await));
        }
        Command::Delete {
            name,
            id,
            everyone: true,
            reply,
        } => drop(reply.send(node.delete_for_everyone(mux, &name, id).await)),
        Command::Clear {
            name,
            everyone: true,
            reply,
        } => drop(reply.send(node.clear_for_everyone(mux, &name).await)),
        Command::Remove(name, reply) => drop(reply.send(node.remove(mux, &name).await)),
        Command::Rotate(name, reply) => drop(reply.send(node.rotate(mux, &name).await)),
        Command::SetSettings(settings, reply) => {
            let decoys_before = node.settings().decoy_interval;
            let result = node.set_settings(settings);
            if result.is_ok() && node.settings().decoy_interval != decoys_before {
                // Send what decoys were holding back before changing the clock.
                if let Some(mut s) = scheduler.take() {
                    for (name, text) in s.drain() {
                        if let Err(e) = node.send_text(mux, &name, &text).await {
                            shared.notice(format!(
                                "A message to {} was not sent: {e:#}",
                                clean(&name)
                            ));
                        }
                    }
                }
                *scheduler = new_scheduler(node);
            }
            drop(reply.send(result));
        }
        Command::Foreground { away } if away >= STALE_AFTER => return Flow::Reconnect,
        Command::Shutdown(stop) => return Flow::Stop(stop),
        cmd => {
            if let ControlFlow::Break(stop) = local(node, Some(cmd), "") {
                return stop.map_or(Flow::Continue, Flow::Stop);
            }
        }
    }
    Flow::Continue
}

/// Act on a command without the network: answer the local ones, refuse the
/// rest. `Break` means shut down (with whom to tell, if anyone asked).
fn local(
    node: &mut Node,
    cmd: Option<Command>,
    why: &str,
) -> ControlFlow<Option<oneshot::Sender<()>>> {
    let Some(cmd) = cmd else {
        return ControlFlow::Break(None);
    };
    match cmd {
        Command::SafetyNumber(name, reply) => drop(reply.send(node.safety_number(&name))),
        Command::Delete {
            name,
            id,
            everyone: false,
            reply,
        } => drop(reply.send(node.delete_here(&name, id))),
        Command::Clear {
            name,
            everyone: false,
            reply,
        } => drop(reply.send(node.clear_here(&name))),
        Command::MarkRead(name) => {
            if let Err(e) = node.mark_read(&name) {
                tracing::debug!("mark read: {e:#}");
            }
        }
        Command::SetSettings(settings, reply) => {
            // Decoys start with the next connection.
            drop(reply.send(node.set_settings(settings)));
        }
        Command::CheckPassphrase(passphrase, reply) => {
            let _ = reply.send(node.check_passphrase(&passphrase));
        }
        Command::Foreground { .. } | Command::Retry => {}
        Command::Shutdown(stop) => return ControlFlow::Break(Some(stop)),
        other => other.refuse(why),
    }
    ControlFlow::Continue(())
}

/// Say it didn't work, then wait [`RETRY_AFTER`] (or until the app asks to
/// retry, or comes back on screen), answering commands meanwhile.
async fn wait_to_retry(
    node: &mut Node,
    scheduler: Option<&Scheduler>,
    shared: &Shared,
    commands: &mut UnboundedReceiver<Command>,
    error: &anyhow::Error,
) -> ControlFlow<Option<oneshot::Sender<()>>> {
    shared.status(ConnectionStatus::Offline {
        reason: format!("{error:#}"),
        retry_in_secs: RETRY_AFTER.as_secs() as u32,
    });
    let deadline = tokio::time::sleep(RETRY_AFTER);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return ControlFlow::Continue(()),
            cmd = commands.recv() => {
                let now = matches!(cmd, Some(Command::Retry | Command::Foreground { .. }));
                if let ControlFlow::Break(stop) = local(node, cmd, "offline") {
                    return ControlFlow::Break(stop);
                }
                shared.publish(node, scheduler);
                if now {
                    return ControlFlow::Continue(());
                }
            }
        }
    }
}

fn finish(stop: Option<oneshot::Sender<()>>, shared: &Shared) {
    shared.status(ConnectionStatus::Stopped);
    if let Some(stop) = stop {
        let _ = stop.send(());
    }
}

/// Tell the app what an incoming frame did.
fn announce(shared: &Shared, scheduler: &mut Option<Scheduler>, event: Event) {
    match event {
        Event::Joined { contact } => {
            shared.notice(format!("{} joined. Say hi!", clean(&contact)));
            if let Some(s) = scheduler.as_mut() {
                s.add(contact);
            }
        }
        Event::Timer { contact, after } => shared.notice(match after {
            None => format!("{} turned disappearing messages off.", clean(&contact)),
            Some(_) => format!(
                "{} set messages to disappear after {}.",
                clean(&contact),
                privmsg_node::app::describe_timer(after)
            ),
        }),
        Event::Cleared { contact } => {
            shared.notice(format!("{} cleared the chat.", clean(&contact)))
        }
        // The view shows it; a deleted message leaves no trace.
        Event::Message { .. } | Event::Deleted { .. } => {}
    }
}

fn new_scheduler(node: &Node) -> Option<Scheduler> {
    node.settings().decoy_interval.map(|secs| {
        Scheduler::new(
            Duration::from_secs(secs.into()),
            node.contacts().iter().map(|c| c.name.clone()),
        )
    })
}

/// Longest contact name, in characters.
const MAX_NAME: usize = 64;

/// A contact name as typed, trimmed; refused if empty or too long.
fn valid_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Type a name first.");
    }
    if name.chars().count() > MAX_NAME {
        bail!("Use a shorter name (at most {MAX_NAME} characters).");
    }
    Ok(name)
}

fn clean(text: &str) -> String {
    privmsg_node::clean(text)
}

fn far_future() -> Instant {
    Instant::now() + Duration::from_secs(86_400 * 365)
}
