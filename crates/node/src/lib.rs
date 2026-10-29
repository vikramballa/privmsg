//! The privmsg node as a library: messenger logic (`app`), encrypted profile
//! (`store`), wire formats (`wire`) and keeping secrets out of swap and
//! crash dumps (`secure`). The `privmsg` binary is a command
//! line over it; the fuzz targets drive it directly.

pub mod app;
pub mod decoy;
pub mod secure;
pub mod store;
pub mod wire;

/// Strip control characters so a contact can't send terminal escape
/// sequences that rewrite the screen, and bidirectional overrides that make
/// text display in a different order than it was written.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| {
            let bidi = matches!(
                c,
                '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            );
            if c.is_control() || bidi {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}
