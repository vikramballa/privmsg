//! UniFFI's binding generator, built against the exact uniffi version the
//! library uses: `cargo run -p privmsg-mobile --features bindgen --bin uniffi-bindgen -- generate …`.

fn main() {
    uniffi::uniffi_bindgen_main()
}
