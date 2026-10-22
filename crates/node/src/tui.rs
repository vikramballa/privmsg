//! The app people see when they type `privmsg`: contacts on the left with
//! unread counts, the selected conversation on the right, an input line at
//! the bottom. Everything that reaches the screen from the network goes
//! through [`clean`] first.
//!
//! Making contact is guided: Ctrl-N asks for a name and copies a fresh
//! invite to the clipboard; Ctrl-O takes a pasted invite code and asks what
//! to call its sender. (`/invite <name>` and `/add <name> <code>` still work.)

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as TermEvent, EventStream, KeyCode,
    KeyEventKind, KeyModifiers,
};
use futures::StreamExt;
use privmsg_node::app::{Event, Node};
use privmsg_node::decoy::Scheduler;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::time::Instant;

use crate::{clean, connect, far_future, flush_queued, tick, utc, Network, MAINTENANCE_EVERY};

const HELP: &str =
    "Ctrl-N invite a friend · Ctrl-O enter an invite code · ↑↓ switch chat · Esc quit";

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
}

/// What a key press asks for, decided without touching the network so it
/// can be tested on its own.
#[derive(Debug, PartialEq)]
enum Action {
    None,
    Quit,
    Move(isize),
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
    node.maintain(&mut mux).await?;
    let mut scheduler = node.settings().decoy_interval.map(|secs| {
        Scheduler::new(
            Duration::from_secs(secs.into()),
            node.contacts().iter().map(|c| c.name.clone()),
        )
    });

    let mut terminal = ratatui::init();
    // Start from a blank screen even where the terminal keeps old text.
    terminal.clear()?;
    // So a pasted invite code arrives as one piece, not as keystrokes.
    crossterm::execute!(std::io::stdout(), EnableBracketedPaste).ok();
    let result = event_loop(&mut terminal, &mut node, &mut mux, &mut scheduler).await;
    crossterm::execute!(std::io::stdout(), DisableBracketedPaste).ok();
    ratatui::restore();

    if let Some(s) = scheduler.as_mut() {
        flush_queued(&mut node, &mut mux, s).await;
    }
    mux.close().await;
    result
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    node: &mut Node,
    mux: &mut Network,
    scheduler: &mut Option<Scheduler>,
) -> Result<()> {
    let mut app = App {
        status: HELP.into(),
        ..App::default()
    };
    let mut keys = EventStream::new();
    let mut maintenance =
        tokio::time::interval_at(Instant::now() + MAINTENANCE_EVERY, MAINTENANCE_EVERY);
    loop {
        if let Some(name) = selected_name(node, &app) {
            node.mark_read(&name)?;
        }
        terminal.draw(|f| draw(f, node, &app, scheduler.as_ref()))?;

        let next_tick = scheduler.as_ref().and_then(Scheduler::next_due);
        let tick_at = next_tick.as_ref().map_or_else(far_future, |(_, at)| *at);
        tokio::select! {
            msg = mux.recv() => {
                let (slot, msg) = msg?;
                match node.handle_incoming(mux, &slot, &msg.payload).await {
                    Ok(events) => {
                        for event in events {
                            if let Event::Joined { contact } = event {
                                app.status = format!("✓ {} joined. Say hi!", clean(&contact));
                                if app.mode == Mode::Chat {
                                    // The invite on screen has done its job.
                                    app.notice = None;
                                    select(node, &mut app, &contact);
                                }
                                if let Some(s) = scheduler.as_mut() {
                                    s.add(contact);
                                }
                            }
                        }
                    }
                    Err(e) => app.status = format!("ignored an incoming message: {e:#}"),
                }
            }
            key = keys.next() => match key {
                Some(Ok(TermEvent::Key(k))) if k.kind == KeyEventKind::Press => {
                    // Windows reports AltGr (how many keyboards type @, € or
                    // {) as Ctrl+Alt; that is typing, not a shortcut.
                    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL)
                        && !k.modifiers.contains(KeyModifiers::ALT);
                    match app.key(k.code, ctrl) {
                        Action::None => {}
                        Action::Quit => return Ok(()),
                        Action::Move(step) => move_selection(node, &mut app, step),
                        Action::Submit(mode, line) => {
                            submit(node, mux, scheduler, &mut app, mode, &line).await
                        }
                    }
                }
                Some(Ok(TermEvent::Paste(text))) => app.paste(&text),
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
        }
    }
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
            match scheduler.as_mut() {
                Some(s) => {
                    s.queue(&name, line.to_string());
                    app.status = "queued; it leaves with the next decoy".into();
                }
                None => match node.send_text(mux, &name, line).await {
                    Ok(()) => app.status = format!("✓ sent to {}", clean(&name)),
                    Err(e) => {
                        app.input = line.to_string();
                        app.status = format!("✗ not sent ({e:#}). Press Enter to try again.");
                    }
                },
            }
        }
    }
}

async fn invite(node: &mut Node, mux: &mut Network, app: &mut App, name: &str) {
    app.status = format!("making an invite for {}…", clean(name));
    match node.create_invite(mux, name).await {
        Ok(code) => {
            let copied = copy_to_clipboard(&code);
            let how = if copied {
                "✓ Copied to your clipboard. Paste it to"
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

/// Put `text` on the system clipboard, if there is a clipboard tool.
#[cfg(not(windows))]
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let tools: &[&[&str]] = &[
        &["pbcopy"],
        &["wl-copy"],
        &["xclip", "-selection", "clipboard"],
        &["xsel", "--clipboard", "--input"],
    ];
    tools.iter().any(|tool| {
        Command::new(tool[0])
            .args(&tool[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child
                    .stdin
                    .take()
                    .expect("piped")
                    .write_all(text.as_bytes())?;
                child.wait()
            })
            .is_ok_and(|status| status.success())
    })
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

fn draw(f: &mut Frame, node: &Node, app: &App, scheduler: Option<&Scheduler>) {
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
    let title = selected.map_or(" privmsg ".to_string(), |c| format!(" {} ", clean(&c.name)));
    let block = Block::bordered().title(title);
    let body = if let Some(notice) = &app.notice {
        Paragraph::new(notice.as_str())
    } else if let Some(contact) = selected {
        let inner = block.inner(chat_area);
        let lines: Vec<String> = contact
            .history
            .iter()
            .map(|e| {
                let who = if e.outgoing { "me" } else { &contact.name };
                format!("{} {}: {}", &utc(e.at)[11..], clean(who), clean(&e.text))
            })
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
    if let Some(s) = scheduler {
        status = format!("[decoys on, {} queued] {status}", s.queued());
    }
    f.render_widget(Paragraph::new(status).dim(), status_area);
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
