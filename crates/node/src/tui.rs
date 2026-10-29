//! The app people see when they type `privmsg`: contacts on the left with
//! unread counts, the selected conversation on the right, an input line at
//! the bottom. Everything that reaches the screen from the network goes
//! through [`clean`] first.
//!
//! Making contact is guided: Ctrl-N asks for a name and copies a fresh
//! invite to the clipboard; Ctrl-O takes a pasted invite code and asks what
//! to call its sender. (`/invite <name>` and `/add <name> <code>` still work.)
//! Ctrl-D steps the selected conversation's disappearing-message timer
//! through off, 5 minutes, 1 hour, 1 day and 1 week (or `/disappear 1h`).
//! `/clear` empties the selected chat here, `/clear everyone` on both
//! sides; `/unsend` deletes your last message in it on both sides.
//!
//! With auto-sleep on, the sender (and its cover traffic) stops after the
//! set minutes without typing and comes back on the next key press.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as TermEvent, EventStream, KeyCode,
    KeyEventKind, KeyModifiers,
};
use futures::StreamExt;
use privmsg_node::app::{describe_timer, next_timer, parse_timer, Event, Node};
use privmsg_node::decoy::Scheduler;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::time::Instant;

use crate::{
    clean, connect, far_future, flush_held, reconnect, start_decoys, tick, utc, Network,
    MAINTENANCE_EVERY,
};

const HELP: &str = "Ctrl-N invite a friend · Ctrl-O enter an invite code · \
                    Ctrl-D disappearing messages · ↑↓ switch chat · Esc quit";

/// What the input line is for right now.
#[derive(Default, Clone, PartialEq, Debug)]
enum Mode {
    /// A message to the selected contact.
    #[default]
    Chat,
    /// The name for a new invite (Ctrl-N).
    InviteName,
    /// A pasted invite code (Ctrl-O)...
    Code,
    /// ...and then the name to save its sender under.
    CodeName { code: String },
}

#[derive(Default)]
struct App {
    selected: usize,
    mode: Mode,
    input: String,
    /// One line under the input: the last thing that happened.
    status: String,
    /// Shown in place of the conversation until a key is pressed (an
    /// invite code to copy).
    notice: Option<String>,
    /// An invite code we put on the clipboard, and when to take it off.
    copied: Option<(String, Instant)>,
}

/// How long an invite code stays on the clipboard if it isn't used.
const CLIPBOARD_FOR: Duration = Duration::from_secs(180);

/// What a key press asks for, decided without touching the network so it
/// can be tested on its own.
#[derive(Debug, PartialEq)]
enum Action {
    None,
    Quit,
    Move(isize),
    /// Step the selected conversation's disappearing-message timer.
    Timer,
    /// Enter pressed in the given mode, with the trimmed input.
    Submit(Mode, String),
}

impl App {
    fn key(&mut self, code: KeyCode, ctrl: bool) -> Action {
        // Esc or Enter just close a notice; any other key closes it and
        // still counts, so typing straight away loses nothing.
        if self.notice.take().is_some() && matches!(code, KeyCode::Esc | KeyCode::Enter) {
            return Action::None;
        }
        match code {
            KeyCode::Char('c') if ctrl => return Action::Quit,
            KeyCode::Esc if self.mode == Mode::Chat => return Action::Quit,
            KeyCode::Esc => {
                self.mode = Mode::Chat;
                self.input.clear();
                self.status = HELP.into();
            }
            KeyCode::Char('n') if ctrl => {
                self.mode = Mode::InviteName;
                self.input.clear();
                self.status = "Type a name for your friend, then press Enter. Esc cancels.".into();
            }
            KeyCode::Char('o') if ctrl => {
                self.mode = Mode::Code;
                self.input.clear();
                self.status =
                    "Paste the invite code you were sent, then press Enter. Esc cancels.".into();
            }
            KeyCode::Char('d') if ctrl && self.mode == Mode::Chat => return Action::Timer,
            KeyCode::Up if self.mode == Mode::Chat => return Action::Move(-1),
            KeyCode::Down | KeyCode::Tab if self.mode == Mode::Chat => return Action::Move(1),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let line = std::mem::take(&mut self.input).trim().to_string();
                let mode = std::mem::take(&mut self.mode);
                if line.is_empty() && mode != Mode::Chat {
                    self.mode = mode; // keep waiting for input
                    return Action::None;
                }
                if let Mode::Code = mode {
                    // Ask for the name next; nothing to send yet.
                    self.mode = Mode::CodeName { code: line };
                    self.status =
                        "What do you want to call the person who sent it? Type a name, then Enter."
                            .into();
                    return Action::None;
                }
                return Action::Submit(mode, line);
            }
            KeyCode::Char(c) if !ctrl => self.input.push(c),
            _ => {}
        }
        Action::None
    }

    /// Pasted text arrives in one piece; line breaks become spaces (codes
    /// ignore them anyway).
    fn paste(&mut self, text: &str) {
        self.notice = None;
        self.input
            .extend(text.chars().map(|c| if c.is_control() { ' ' } else { c }));
    }

    fn prompt(&self, contact: Option<&str>) -> String {
        match (&self.mode, contact) {
            (Mode::Chat, Some(name)) => format!("message to {}", clean(name)),
            (Mode::Chat, None) => "Ctrl-N to invite a friend · Ctrl-O if you got a code".into(),
            (Mode::InviteName, _) => "who are you inviting? (a name only you will see)".into(),
            (Mode::Code, _) => "paste the invite code".into(),
            (Mode::CodeName { .. }, _) => "what do you want to call them?".into(),
        }
    }
}

pub async fn run(mut node: Node) -> Result<()> {
    let slots = node.all_slots();
    let mut mux = connect(&mut node, &slots).await?;
    let mut scheduler = start_decoys(&mut node);
    node.maintain(&mut mux).await?;

    let mut terminal = ratatui::init();
    // Start from a blank screen even where the terminal keeps old text.
    terminal.clear()?;
    // So a pasted invite code arrives as one piece, not as keystrokes.
    crossterm::execute!(std::io::stdout(), EnableBracketedPaste).ok();
    let mut app = App {
        status: HELP.into(),
        ..App::default()
    };
    let result = event_loop(&mut terminal, &mut node, &mut mux, &mut scheduler, &mut app).await;
    crossterm::execute!(std::io::stdout(), DisableBracketedPaste).ok();
    ratatui::restore();
    uncopy(&mut app);

    flush_held(&mut node, &mut mux).await;
    mux.close().await;
    result
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    node: &mut Node,
    mux: &mut Network,
    scheduler: &mut Option<Scheduler>,
    app: &mut App,
) -> Result<()> {
    let mut keys = EventStream::new();
    let mut maintenance =
        tokio::time::interval_at(Instant::now() + MAINTENANCE_EVERY, MAINTENANCE_EVERY);
    let mut last_typed = Instant::now();
    loop {
        if let Some(name) = selected_name(node, app) {
            node.mark_read(&name)?;
        }
        terminal.draw(|f| draw(f, node, app, scheduler.as_ref(), mux.is_awake()))?;

        let next_tick = scheduler.as_ref().and_then(Scheduler::next_due);
        let tick_at = next_tick.as_ref().map_or_else(far_future, |(_, at)| *at);
        // Decoys keep sending by design, so they keep the sender up.
        let idle_limit = node
            .settings()
            .auto_sleep
            .filter(|_| scheduler.is_none())
            .map(|mins| Duration::from_secs(u64::from(mins) * 60));
        let sleep_at = idle_limit.map_or_else(far_future, |limit| last_typed + limit);
        let uncopy_at = app.copied.as_ref().map_or_else(far_future, |(_, at)| *at);
        tokio::select! {
            msg = mux.recv() => {
                let (slot, msg) = match msg {
                    Ok(arrived) => arrived,
                    Err(e) => {
                        app.status = format!("Connection lost ({e:#}). Reconnecting…");
                        terminal.draw(|f| draw(f, node, app, scheduler.as_ref(), false))?;
                        let slots = node.all_slots();
                        reconnect(node, mux, &slots).await?;
                        app.status = "Reconnected.".into();
                        continue;
                    }
                };
                match node.handle_incoming(mux, &slot, &msg.payload).await {
                    Ok(events) => {
                        for event in events {
                            match event {
                                Event::Joined { contact } => {
                                    // The code has been used; don't leave it lying around.
                                    uncopy(app);
                                    app.status = format!("✓ {} joined. Say hi!", clean(&contact));
                                    if app.mode == Mode::Chat {
                                        // The invite on screen has done its job.
                                        app.notice = None;
                                        select(node, app, &contact);
                                    }
                                    if let Some(s) = scheduler.as_mut() {
                                        s.add(contact);
                                    }
                                }
                                Event::Timer { contact, after } => {
                                    app.status = timer_status(Some(&contact), &contact, after);
                                }
                                // The chat shows it (a deleted message leaves no trace).
                                Event::Message { .. }
                                | Event::Deleted { .. }
                                | Event::Cleared { .. } => {}
                            }
                        }
                    }
                    Err(e) => app.status = format!("ignored an incoming message: {e:#}"),
                }
            }
            key = keys.next() => match key {
                Some(Ok(TermEvent::Key(k))) if k.kind == KeyEventKind::Press => {
                    last_typed = Instant::now();
                    // Windows reports AltGr (how many keyboards type @, € or
                    // {) as Ctrl+Alt; that is typing, not a shortcut.
                    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL)
                        && !k.modifiers.contains(KeyModifiers::ALT);
                    let action = app.key(k.code, ctrl);
                    if action != Action::Quit && !mux.is_awake() && idle_limit.is_some()
                        && !node.contacts().is_empty()
                    {
                        wake(terminal, node, mux, app, scheduler.as_ref()).await?;
                    }
                    match action {
                        Action::None => {}
                        Action::Quit => return Ok(()),
                        Action::Move(step) => move_selection(node, app, step),
                        Action::Timer => step_timer(node, mux, app).await,
                        Action::Submit(mode, line) => {
                            submit(node, mux, scheduler, app, mode, &line).await
                        }
                    }
                }
                Some(Ok(TermEvent::Paste(text))) => {
                    last_typed = Instant::now();
                    app.paste(&text)
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            },
            _ = tokio::time::sleep_until(tick_at), if next_tick.is_some() => {
                let (name, _) = next_tick.expect("tick scheduled");
                let s = scheduler.as_mut().expect("decoys on");
                tick(node, mux, s, &name).await;
            }
            _ = maintenance.tick() => {
                if let Err(e) = node.maintain(mux).await {
                    app.status = format!("address maintenance failed: {e:#}");
                }
            }
            _ = tokio::time::sleep_until(uncopy_at), if app.copied.is_some() => uncopy(app),
            _ = tokio::time::sleep_until(sleep_at), if idle_limit.is_some() && mux.is_awake() => {
                mux.sleep().await;
                app.status =
                    "Resting to save data. You still get messages; typing wakes it up.".into();
            }
        }
    }
}

/// Bring the sender back after auto-sleep, saying so while it connects.
async fn wake(
    terminal: &mut DefaultTerminal,
    node: &Node,
    mux: &mut Network,
    app: &mut App,
    scheduler: Option<&Scheduler>,
) -> Result<()> {
    let before = std::mem::replace(&mut app.status, "waking up (a few seconds)…".into());
    terminal.draw(|f| draw(f, node, app, scheduler, false))?;
    app.status = match mux.wake().await {
        Ok(()) => before,
        Err(e) => format!("✗ could not reconnect: {e:#}. It tries again when you send."),
    };
    Ok(())
}

/// Ctrl-D: the selected conversation's next disappearing-message timer.
async fn step_timer(node: &mut Node, mux: &mut Network, app: &mut App) {
    let Some(contact) = node.contacts().get(app.selected) else {
        app.status = "Pick a conversation first.".into();
        return;
    };
    let (name, after) = (contact.name.clone(), next_timer(contact.disappear_after));
    set_timer(node, mux, app, &name, after).await;
}

async fn set_timer(
    node: &mut Node,
    mux: &mut Network,
    app: &mut App,
    name: &str,
    after: Option<u64>,
) {
    app.status = match node.set_timer(mux, name, after).await {
        Ok(()) => timer_status(None, name, after),
        Err(e) => format!("✗ could not change disappearing messages: {e:#}"),
    };
}

/// What changed, by `by` (the contact) or by us when `None`.
fn timer_status(by: Option<&str>, name: &str, after: Option<u64>) -> String {
    let who = by.map_or("You".to_string(), clean);
    let what = match after {
        None => "turned disappearing messages off".to_string(),
        Some(_) => format!("set messages to disappear after {}", describe_timer(after)),
    };
    format!(
        "{who} {what} in the chat with {}, on both sides. (Ctrl-D changes it)",
        clean(name)
    )
}

/// Act on a line entered in `mode`.
async fn submit(
    node: &mut Node,
    mux: &mut Network,
    scheduler: &mut Option<Scheduler>,
    app: &mut App,
    mode: Mode,
    line: &str,
) {
    let words: Vec<&str> = line.split_whitespace().collect();
    match (mode, words.as_slice()) {
        (Mode::InviteName, _) => invite(node, mux, app, line).await,
        (Mode::CodeName { code }, _) => add(node, mux, scheduler, app, &code, line).await,
        (_, ["/invite", name]) => invite(node, mux, app, name).await,
        (_, ["/add", name, code @ ..]) if !code.is_empty() => {
            add(node, mux, scheduler, app, &code.concat(), name).await
        }
        (_, ["/verify"]) => match selected_name(node, app) {
            Some(name) => match node.safety_number(&name) {
                Ok(number) => {
                    app.notice = Some(format!(
                        "Safety number with {name}\n\n    {number}\n\n\
                         Compare it with {name} in person or on a call (not in a chat\n\
                         app). If it matches, nobody intercepted your invite. If it\n\
                         doesn't, remove the contact and connect again with a new invite.\n\n\
                         (press any key to go back)",
                        name = clean(&name)
                    ))
                }
                Err(e) => app.status = format!("{e:#}"),
            },
            None => app.status = "Pick a conversation first.".into(),
        },
        (_, ["/disappear", word]) => match (parse_timer(word), selected_name(node, app)) {
            (Ok(after), Some(name)) => set_timer(node, mux, app, &name, after).await,
            (Err(e), _) => app.status = format!("{e:#}"),
            (_, None) => app.status = "Pick a conversation first.".into(),
        },
        (_, ["/clear"]) => match selected_name(node, app) {
            Some(name) => {
                app.status = match node.clear_here(&name) {
                    Ok(()) => format!(
                    "Chat emptied here. {} still has their copy (/clear everyone empties both).",
                    clean(&name)
                ),
                    Err(e) => format!("✗ {e:#}"),
                }
            }
            None => app.status = "Pick a conversation first.".into(),
        },
        (_, ["/clear", "everyone"]) => match selected_name(node, app) {
            Some(name) => {
                app.status = match node.clear_for_everyone(mux, &name).await {
                    Ok(()) => format!("Chat emptied, here and for {}.", clean(&name)),
                    Err(e) => format!("✗ not cleared: {e:#}"),
                }
            }
            None => app.status = "Pick a conversation first.".into(),
        },
        (_, ["/unsend"]) => match selected_name(node, app) {
            Some(name) => app.status = unsend(node, mux, &name).await,
            None => app.status = "Pick a conversation first.".into(),
        },
        (_, [cmd, ..]) if cmd.starts_with('/') => app.status = HELP.into(),
        (_, []) => {}
        _ => {
            let Some(name) = selected_name(node, app) else {
                app.status =
                    "No one to send to yet. Ctrl-N invites a friend; Ctrl-O enters a code you got."
                        .into();
                app.input = line.to_string();
                return;
            };
            match node.send_text(mux, &name, line).await {
                Ok(()) if scheduler.is_some() => {
                    app.status = "queued; it leaves with the next decoy".into()
                }
                Ok(()) => app.status = format!("✓ sent to {}", clean(&name)),
                Err(e) => {
                    app.input = line.to_string();
                    app.status = format!("✗ not sent ({e:#}). Press Enter to try again.");
                }
            }
        }
    }
}

/// `/unsend`: delete our last message to `name` on both sides.
async fn unsend(node: &mut Node, mux: &mut Network, name: &str) -> String {
    let id = match node.last_sent(name) {
        Ok(Some(id)) => id,
        Ok(None) => return "You have no messages here to unsend.".into(),
        Err(e) => return format!("✗ {e:#}"),
    };
    match node.delete_for_everyone(mux, name, id).await {
        Ok(()) => format!(
            "Your last message is deleted, here and for {}.",
            clean(name)
        ),
        Err(e) => format!("✗ not deleted: {e:#}"),
    }
}

async fn invite(node: &mut Node, mux: &mut Network, app: &mut App, name: &str) {
    app.status = format!("making an invite for {}…", clean(name));
    match node.create_invite(mux, name).await {
        Ok(code) => {
            uncopy(app);
            let copied = copy_to_clipboard(&code);
            if copied {
                app.copied = Some((code.clone(), Instant::now() + CLIPBOARD_FOR));
            }
            let how = if copied {
                "✓ Copied to your clipboard for 3 minutes. Paste it to"
            } else {
                "Select and copy the code below, then send it to"
            };
            app.notice = Some(format!(
                "Invite for {name}\n\n\
                 {how} {name} any way you like: WhatsApp, Signal, email, a text...\n\
                 It works once. When {name} enters it, you're connected.\n\n\
                 {code}\n\n\
                 (press any key to go back)",
                name = clean(name),
            ));
            app.status = format!("waiting for {} to join…", clean(name));
        }
        Err(e) => app.status = format!("✗ could not make an invite: {e:#}"),
    }
}

async fn add(
    node: &mut Node,
    mux: &mut Network,
    scheduler: &mut Option<Scheduler>,
    app: &mut App,
    code: &str,
    name: &str,
) {
    app.status = format!("connecting to {}…", clean(name));
    match node.accept_invite(mux, code, name).await {
        Ok(()) => {
            app.status = format!(
                "✓ {} added. Say hi! They'll see it as soon as they're online.",
                clean(name)
            );
            if let Some(s) = scheduler.as_mut() {
                s.add(name.to_string());
            }
            select(node, app, name);
        }
        Err(e) => app.status = format!("✗ could not use that code: {e:#}"),
    }
}

/// Take our invite code off the clipboard, unless something else has been
/// copied since (that's the user's, and stays).
fn uncopy(app: &mut App) {
    if let Some((code, _)) = app.copied.take() {
        if clipboard_text().is_some_and(|text| text.trim() == code) {
            clear_clipboard();
        }
    }
}

/// On a Mac: copy for this Mac only (no Universal Clipboard to your other
/// Apple devices) and marked concealed, so clipboard managers that follow
/// the nspasteboard.org convention don't save it. Reads `text` from stdin.
#[cfg(target_os = "macos")]
const MAC_LOCAL_COPY: &str = "ObjC.import('AppKit');
var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
var pb = $.NSPasteboard.generalPasteboard;
pb.prepareForNewContentsWithOptions($.NSPasteboardContentsCurrentHostOnly);
(pb.setStringForType(text, $.NSPasteboardTypeString)
  && pb.setStringForType($(''), 'org.nspasteboard.ConcealedType')) ? 'ok' : 'failed';";

/// Run `tool` with `input` on stdin; its stdout if it succeeded.
#[cfg(not(windows))]
fn run_tool(tool: &[&str], input: &str) -> Option<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new(tool[0])
        .args(&tool[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(input.as_bytes())
        .ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Put `text` on the system clipboard, if there is a clipboard tool.
#[cfg(not(windows))]
fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(target_os = "macos")]
    if run_tool(
        &["osascript", "-l", "JavaScript", "-e", MAC_LOCAL_COPY],
        text,
    )
    .is_some_and(|out| out.trim() == "ok")
    {
        return true;
    }
    let tools: &[&[&str]] = &[
        &["pbcopy"],
        &["wl-copy"],
        &["xclip", "-selection", "clipboard"],
        &["xsel", "--clipboard", "--input"],
    ];
    tools.iter().any(|tool| run_tool(tool, text).is_some())
}

/// What's on the clipboard now, if it can be read.
#[cfg(not(windows))]
fn clipboard_text() -> Option<String> {
    let tools: &[&[&str]] = &[
        &["pbpaste"],
        &["wl-paste", "--no-newline"],
        &["xclip", "-selection", "clipboard", "-o"],
        &["xsel", "--clipboard", "--output"],
    ];
    tools.iter().find_map(|tool| run_tool(tool, ""))
}

#[cfg(not(windows))]
fn clear_clipboard() {
    copy_to_clipboard("");
}

/// Run `f` with the Windows clipboard open; `None` if it stayed busy.
#[cfg(windows)]
fn with_clipboard<T>(f: impl FnOnce() -> T) -> Option<T> {
    use windows_sys::Win32::System::DataExchange::{CloseClipboard, OpenClipboard};

    // SAFETY: opened once, always closed again.
    unsafe {
        // Another program may be holding the clipboard for a moment.
        let mut tries = 0;
        while OpenClipboard(std::ptr::null_mut()) == 0 {
            tries += 1;
            if tries == 10 {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = f();
        CloseClipboard();
        Some(out)
    }
}

/// What's on the clipboard now, if it is text.
#[cfg(windows)]
fn clipboard_text() -> Option<String> {
    use windows_sys::Win32::System::DataExchange::GetClipboardData;
    use windows_sys::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    with_clipboard(|| {
        // SAFETY: the clipboard is open; the handle is locked while read
        // and the read stays within its size.
        unsafe {
            let mem = GetClipboardData(CF_UNICODETEXT as u32);
            if mem.is_null() {
                return None;
            }
            let src = GlobalLock(mem).cast::<u16>();
            if src.is_null() {
                return None;
            }
            let units = std::slice::from_raw_parts(src, GlobalSize(mem) / 2);
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            let text = String::from_utf16_lossy(&units[..end]);
            GlobalUnlock(mem);
            Some(text)
        }
    })
    .flatten()
}

#[cfg(windows)]
fn clear_clipboard() {
    use windows_sys::Win32::System::DataExchange::EmptyClipboard;
    // SAFETY: the clipboard is open.
    with_clipboard(|| unsafe { EmptyClipboard() });
}

/// Put `text` on the Windows clipboard, kept out of Clipboard History and
/// cloud clipboard sync: an invite code is a one-time key to becoming the
/// contact, so it must not be uploaded or linger after it's been pasted.
#[cfg(windows)]
fn copy_to_clipboard(text: &str) -> bool {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows_sys::Win32::System::Ole::CF_UNICODETEXT;

    /// Hand `bytes` to the open clipboard under `format`.
    unsafe fn put(format: u32, bytes: &[u8]) -> bool {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len());
        if mem.is_null() {
            return false;
        }
        let dst = GlobalLock(mem);
        if dst.is_null() {
            GlobalFree(mem);
            return false;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.cast(), bytes.len());
        GlobalUnlock(mem);
        // On success the clipboard owns `mem`.
        if SetClipboardData(format, mem).is_null() {
            GlobalFree(mem);
            return false;
        }
        true
    }

    fn format(name: &str) -> u32 {
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        // SAFETY: NUL-terminated UTF-16.
        unsafe { RegisterClipboardFormatW(wide.as_ptr()) }
    }

    let utf16: Vec<u8> = text
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    // Microsoft's documented opt-outs: a DWORD 0 under each of these
    // formats keeps the text out of history and cloud sync, and the
    // last one asks clipboard monitors to skip it.
    let opt_outs = [
        ("CanIncludeInClipboardHistory", &0u32.to_le_bytes()[..]),
        ("CanUploadToCloudClipboard", &0u32.to_le_bytes()[..]),
        ("ExcludeClipboardContentFromMonitorProcessing", &[0u8][..]),
    ];

    // SAFETY: the clipboard is opened once and always closed again; every
    // pointer passed is valid for the call.
    unsafe {
        // Another program may be holding the clipboard for a moment.
        let mut tries = 0;
        while OpenClipboard(std::ptr::null_mut()) == 0 {
            tries += 1;
            if tries == 10 {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let ok = EmptyClipboard() != 0
            && opt_outs.iter().all(|(name, data)| {
                let f = format(name);
                f != 0 && put(f, data)
            })
            && put(CF_UNICODETEXT as u32, &utf16);
        if !ok {
            // Never leave the code on the clipboard without its opt-outs.
            EmptyClipboard();
        }
        CloseClipboard();
        ok
    }
}

fn select(node: &Node, app: &mut App, name: &str) {
    if let Some(i) = node.contacts().iter().position(|c| c.name == name) {
        app.selected = i;
    }
}

fn selected_name(node: &Node, app: &App) -> Option<String> {
    node.contacts().get(app.selected).map(|c| c.name.clone())
}

fn move_selection(node: &Node, app: &mut App, step: isize) {
    let n = node.contacts().len() as isize;
    if n > 0 {
        app.selected = (app.selected as isize + step).rem_euclid(n) as usize;
    }
}

fn draw(f: &mut Frame, node: &Node, app: &App, scheduler: Option<&Scheduler>, awake: bool) {
    let [main, input_area, status_area] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .areas(f.area());
    let [contacts_area, chat_area] =
        Layout::horizontal([Constraint::Length(26), Constraint::Min(20)]).areas(main);

    // Contacts, then invites nobody has used yet.
    let mut items: Vec<ListItem> = node
        .contacts()
        .iter()
        .map(|c| {
            let mut spans = vec![Span::raw(clean(&c.name))];
            if c.unread > 0 {
                spans.push(Span::styled(
                    format!(" ({})", c.unread),
                    Style::new().bold(),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    items.extend(
        node.invites()
            .iter()
            .map(|i| ListItem::new(format!("{} (waiting…)", clean(&i.name))).dim()),
    );
    let mut list_state = ListState::default();
    if !node.contacts().is_empty() {
        list_state.select(Some(app.selected));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title(" contacts "))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        contacts_area,
        &mut list_state,
    );

    let selected = node.contacts().get(app.selected);
    let title = selected.map_or(" privmsg ".to_string(), |c| match c.disappear_after {
        None => format!(" {} ", clean(&c.name)),
        Some(_) => format!(
            " {} · messages disappear after {} ",
            clean(&c.name),
            describe_timer(c.disappear_after)
        ),
    });
    let block = Block::bordered().title(title);
    let body = if let Some(notice) = &app.notice {
        Paragraph::new(notice.as_str())
    } else if let Some(contact) = selected {
        let inner = block.inner(chat_area);
        let cleared = contact.cleared_by_them.map(|at| {
            format!(
                "{} — {} cleared the chat —",
                &utc(at)[11..],
                clean(&contact.name)
            )
        });
        let lines: Vec<String> = cleared
            .into_iter()
            .chain(contact.history.iter().map(|e| {
                let who = if e.outgoing { "me" } else { &contact.name };
                format!("{} {}: {}", &utc(e.at)[11..], clean(who), clean(&e.text))
            }))
            .collect();
        if lines.is_empty() {
            Paragraph::new(format!(
                "No messages with {} yet. Say hi!",
                clean(&contact.name)
            ))
        } else {
            Paragraph::new(last_that_fit(&lines, inner).join("\n"))
        }
    } else {
        Paragraph::new(
            "Welcome to privmsg. No one here yet.\n\n\
             \x20 Ctrl-N   Invite a friend\n\
             \x20 Ctrl-O   I got an invite code\n\n\
             An invite is a one-time code. Send it to your friend any way you\n\
             like (WhatsApp, Signal, email, a text...). When they enter it in\n\
             their privmsg, you're connected and can start chatting.",
        )
    };
    f.render_widget(body.block(block).wrap(Wrap { trim: false }), chat_area);

    let to = app.prompt(selected.map(|c| c.name.as_str()));
    // Long input (an invite code) scrolls: show the end, where the cursor is.
    let width = input_area.width.saturating_sub(3) as usize;
    let typed = app.input.chars().count();
    let shown: String = app
        .input
        .chars()
        .skip(typed.saturating_sub(width))
        .collect();
    f.render_widget(
        Paragraph::new(shown).block(Block::bordered().title(format!(" {to} "))),
        input_area,
    );
    f.set_cursor_position(Position::new(
        input_area.x + 1 + typed.min(width) as u16,
        input_area.y + 1,
    ));

    let mut status = clean(&app.status);
    if scheduler.is_some() {
        status = format!("[decoys on, {} queued] {status}", node.queued());
    }
    let settings = node.settings();
    let tor = if settings.tor { "Tor on" } else { "Tor off" };
    let resting = if settings.auto_sleep.is_some() && !awake {
        " · resting"
    } else {
        ""
    };
    let network = format!(" {tor} · data: {}{resting} ", settings.data_mode.name());
    let [status_area, network_area] = Layout::horizontal([
        Constraint::Min(10),
        Constraint::Length(network.len() as u16),
    ])
    .areas(status_area);
    f.render_widget(Paragraph::new(status).dim(), status_area);
    f.render_widget(Paragraph::new(network).dim().reversed(), network_area);
}

/// The newest lines that fit in `area` once wrapped, oldest first.
fn last_that_fit(lines: &[String], area: Rect) -> Vec<&str> {
    let width = area.width.max(1) as usize;
    let mut rows = 0;
    let mut start = lines.len();
    while start > 0 {
        let needed = lines[start - 1].chars().count().div_ceil(width).max(1);
        if rows + needed > area.height as usize {
            break;
        }
        rows += needed;
        start -= 1;
    }
    lines[start..].iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses the real clipboard, so it's opt-in: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn invite_code_leaves_the_clipboard_but_other_text_stays() {
        let mut app = App::default();
        let code = "privmsg1:clipboard-test".to_string();

        assert!(copy_to_clipboard(&code));
        assert_eq!(clipboard_text().unwrap().trim(), code);
        app.copied = Some((code.clone(), Instant::now()));
        uncopy(&mut app);
        assert_eq!(clipboard_text().unwrap_or_default().trim(), "");

        assert!(copy_to_clipboard(&code));
        app.copied = Some((code, Instant::now()));
        assert!(copy_to_clipboard("something the user copied"));
        uncopy(&mut app);
        assert_eq!(
            clipboard_text().unwrap().trim(),
            "something the user copied"
        );
        assert!(app.copied.is_none());
    }

    fn press(app: &mut App, keys: &str) {
        for c in keys.chars() {
            app.key(KeyCode::Char(c), false);
        }
    }

    #[test]
    fn ctrl_n_asks_for_a_name_then_submits_an_invite() {
        let mut app = App::default();
        assert_eq!(app.key(KeyCode::Char('n'), true), Action::None);
        assert_eq!(app.mode, Mode::InviteName);
        assert_eq!(app.key(KeyCode::Enter, false), Action::None, "needs a name");
        press(&mut app, "alice");
        assert_eq!(
            app.key(KeyCode::Enter, false),
            Action::Submit(Mode::InviteName, "alice".into())
        );
        assert_eq!(app.mode, Mode::Chat);
    }

    #[test]
    fn ctrl_o_takes_a_pasted_code_then_a_name() {
        let mut app = App::default();
        app.key(KeyCode::Char('o'), true);
        app.paste("privmsg1:abc\ndef");
        assert_eq!(app.key(KeyCode::Enter, false), Action::None);
        let code = "privmsg1:abc def".to_string();
        assert_eq!(app.mode, Mode::CodeName { code: code.clone() });
        press(&mut app, "bob");
        assert_eq!(
            app.key(KeyCode::Enter, false),
            Action::Submit(Mode::CodeName { code }, "bob".into())
        );
    }

    #[test]
    fn ctrl_d_steps_the_timer_only_while_chatting() {
        let mut app = App::default();
        assert_eq!(app.key(KeyCode::Char('d'), true), Action::Timer);
        app.key(KeyCode::Char('n'), true);
        assert_eq!(app.key(KeyCode::Char('d'), true), Action::None);
        assert_eq!(app.input, "", "not typed either");
    }

    #[test]
    fn esc_cancels_a_prompt_and_quits_from_chat() {
        let mut app = App::default();
        app.key(KeyCode::Char('n'), true);
        press(&mut app, "ali");
        assert_eq!(app.key(KeyCode::Esc, false), Action::None);
        assert_eq!((app.mode.clone(), app.input.as_str()), (Mode::Chat, ""));
        assert_eq!(app.key(KeyCode::Esc, false), Action::Quit);
        assert_eq!(app.key(KeyCode::Char('c'), true), Action::Quit);
    }

    #[test]
    fn typing_over_a_notice_closes_it_without_losing_keys() {
        let mut app = App {
            notice: Some("invite".into()),
            ..App::default()
        };
        assert_eq!(app.key(KeyCode::Esc, false), Action::None, "only closes it");
        assert!(app.notice.is_none());

        app.notice = Some("invite".into());
        press(&mut app, "hi");
        assert!(app.notice.is_none());
        assert_eq!(app.input, "hi", "the first letter is kept");
    }

    #[test]
    fn only_the_newest_lines_that_fit_are_shown() {
        let lines: Vec<String> = ["old", "middle line that wraps", "new"]
            .map(String::from)
            .to_vec();
        let area = Rect::new(0, 0, 10, 4);
        assert_eq!(
            last_that_fit(&lines, area),
            vec!["middle line that wraps", "new"]
        );
        assert_eq!(last_that_fit(&lines, Rect::new(0, 0, 10, 1)), vec!["new"]);
        assert!(last_that_fit(&[], area).is_empty());
    }
}
