//! What the app shows, copied out of the messenger after every change, so
//! reading it never waits for the network.

use std::collections::HashMap;

use privmsg_node::app::{describe_timer, Node};
use privmsg_node::store::{Contact, Settings};
use privmsg_node::wire::MessageId;

use crate::{ConnectionStatus, ContactInfo, DataModeChoice, MessageInfo, SettingsInfo};

#[derive(Default)]
pub(crate) struct View {
    pub status: ConnectionStatus,
    pub contacts: Vec<ContactInfo>,
    pub messages: HashMap<String, Vec<MessageInfo>>,
    pub invites: Vec<String>,
    pub settings: SettingsInfo,
    pub queued: u32,
}

impl View {
    /// Copy the current state out of `node`. Whether anything changed.
    pub fn refresh(&mut self, node: &Node) -> bool {
        let mut contacts: Vec<ContactInfo> = node.contacts().iter().map(contact).collect();
        // Most recent conversation first; new ones (no messages) on top.
        contacts.sort_by_key(|c| std::cmp::Reverse(c.last_at.unwrap_or(u64::MAX)));
        let messages: HashMap<String, Vec<MessageInfo>> = node
            .contacts()
            .iter()
            .map(|c| (c.name.clone(), c.history.iter().map(message).collect()))
            .collect();
        let invites: Vec<String> = node.invites().iter().map(|i| i.name.clone()).collect();
        let settings = settings(node.settings());
        let queued = node.queued() as u32;

        let changed = contacts != self.contacts
            || messages != self.messages
            || invites != self.invites
            || settings != self.settings
            || queued != self.queued;
        if changed {
            *self = View {
                status: std::mem::take(&mut self.status),
                contacts,
                messages,
                invites,
                settings,
                queued,
            };
        }
        changed
    }
}

fn contact(c: &Contact) -> ContactInfo {
    let last = c.history.last();
    ContactInfo {
        name: c.name.clone(),
        display_name: privmsg_node::clean(&c.name),
        unread: c.unread,
        last_text: last.map(|e| text(&e.text)),
        last_outgoing: last.is_some_and(|e| e.outgoing),
        last_at: last.map(|e| e.at),
        disappear_after: c.disappear_after,
        disappear_label: describe_timer(c.disappear_after),
        cleared_by_them: c.cleared_by_them.is_some(),
    }
}

fn message(e: &privmsg_node::store::HistoryEntry) -> MessageInfo {
    MessageInfo {
        id: e.id.iter().map(|b| format!("{b:02x}")).collect(),
        outgoing: e.outgoing,
        text: text(&e.text),
        at: e.at,
        can_delete_for_everyone: e.outgoing && e.shared,
    }
}

/// A [`MessageInfo::id`] back as the messenger's.
pub(crate) fn parse_id(id: &str) -> anyhow::Result<MessageId> {
    let gone = || anyhow::anyhow!("That message is already gone.");
    let mut out = MessageId::default();
    if id.len() != 2 * out.len() || !id.is_ascii() {
        return Err(gone());
    }
    for (byte, i) in out.iter_mut().zip((0..id.len()).step_by(2)) {
        *byte = u8::from_str_radix(&id[i..i + 2], 16).map_err(|_| gone())?;
    }
    Ok(out)
}

/// Message text made safe to show: like the desktop's cleaning (no control
/// characters, no direction overrides), but line breaks stay.
pub(crate) fn text(raw: &str) -> String {
    raw.split('\n')
        .map(privmsg_node::clean)
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn settings(s: &Settings) -> SettingsInfo {
    SettingsInfo {
        data_mode: s.data_mode.into(),
        tor: s.tor,
        decoys: s.decoy_interval.is_some(),
        auto_sleep_minutes: s.auto_sleep,
    }
}

impl Default for SettingsInfo {
    fn default() -> Self {
        settings(&Settings::default())
    }
}

impl Default for DataModeChoice {
    fn default() -> Self {
        privmsg_transport::DataMode::default().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ids_round_trip() {
        let id: MessageId = std::array::from_fn(|i| i as u8 * 17);
        let shown: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_id(&shown).unwrap(), id);
        assert!(parse_id("").is_err());
        assert!(parse_id(&shown[2..]).is_err());
        assert!(parse_id(&shown.replace('0', "g")).is_err());
    }

    #[test]
    fn message_text_keeps_lines_but_not_tricks() {
        assert_eq!(text("one\ntwo"), "one\ntwo");
        assert_eq!(text("a\u{202E}b\r"), "a\u{FFFD}b\u{FFFD}");
        assert_eq!(text("\x1b[2J"), "\u{FFFD}[2J");
    }
}
