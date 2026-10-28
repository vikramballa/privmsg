//! With the `embedded-tor` feature, link in the C tor library from
//! Tor.framework's `tor-nolzma.xcframework` (fetched by
//! `scripts/fetch-tor-ios.sh`), picking the slice for the target. Without the
//! feature this does nothing.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PRIVMSG_TOR_XCFRAMEWORK");
    if env::var_os("CARGO_FEATURE_EMBEDDED_TOR").is_none() {
        return;
    }
    let Some(xcframework) = env::var_os("PRIVMSG_TOR_XCFRAMEWORK").map(PathBuf::from) else {
        panic!(
            "the embedded-tor feature needs PRIVMSG_TOR_XCFRAMEWORK set to the path of \
             tor-nolzma.xcframework (run scripts/fetch-tor-ios.sh)"
        );
    };
    let target = env::var("TARGET").expect("cargo sets TARGET");
    let slice = match env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("ios") if target.ends_with("-sim") || target.starts_with("x86_64") => {
            "ios-arm64_x86_64-simulator"
        }
        Ok("ios") => "ios-arm64",
        Ok("macos") => "macos-arm64_x86_64",
        _ => panic!("embedded Tor is only available for iOS and macOS, not {target}"),
    };
    let library = xcframework
        .join(slice)
        .join("tor-nolzma.framework/Versions/A/tor-nolzma");
    println!("cargo:rerun-if-changed={}", library.display());
    if !library.is_file() {
        panic!("{} not found", library.display());
    }
    // The archive has no `lib…a` name; give the linker one it can find.
    // The simulator and macOS slices hold two architectures, which Rust
    // can't bundle: keep only the target's.
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let archive = out.join("libtor_embedded.a");
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => panic!("embedded Tor has no build for {target}"),
    };
    let fat = Command::new("lipo")
        .arg("-info")
        .arg(&library)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).starts_with("Architectures in the fat file"))
        .expect("run lipo (part of Xcode)");
    if fat {
        let status = Command::new("lipo")
            .arg(&library)
            .args(["-thin", arch, "-output"])
            .arg(&archive)
            .status()
            .expect("run lipo");
        assert!(
            status.success(),
            "lipo could not take {arch} out of the tor library"
        );
    } else {
        std::fs::copy(&library, &archive).expect("copy the tor library");
    }
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=tor_embedded");
    // Tor's compression.
    println!("cargo:rustc-link-lib=z");
}
