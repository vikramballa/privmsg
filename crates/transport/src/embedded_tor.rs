//! Tor linked in as a library, for phones, where privmsg can't start a
//! program of its own. Same C tor and the same settings as the desktop's
//! child process ([`tor::arguments`](crate::tor)); it runs on a thread of
//! its own and is driven through its control port.
//!
//! The library comes from Tor.framework's prebuilt `tor-nolzma.xcframework`
//! (`scripts/fetch-tor-ios.sh`); `build.rs` links it in. Tor runs at most
//! once per process: its C code can't be restarted after it stops.

use std::ffi::{c_char, c_int, c_void, CString};
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::tor::{arguments, Keep};
use crate::Tor;

extern "C" {
    fn tor_main_configuration_new() -> *mut c_void;
    fn tor_main_configuration_set_command_line(
        cfg: *mut c_void,
        argc: c_int,
        argv: *mut *mut c_char,
    ) -> c_int;
    fn tor_main_configuration_setup_control_socket(cfg: *mut c_void) -> c_int;
    fn tor_run_main(cfg: *const c_void) -> c_int;
}

/// Set once Tor has been started in this process.
static STARTED: AtomicBool = AtomicBool::new(false);

/// How often bootstrap progress is asked for.
const POLL_EVERY: Duration = Duration::from_millis(500);

/// The configuration pointer, moved to Tor's thread. Tor reads it there and
/// nothing else touches it.
struct Config(*mut c_void);
unsafe impl Send for Config {}

impl Tor {
    /// Start the linked-in Tor with its state in `data_dir` and wait until
    /// it has a circuit, reporting bootstrap percentages to `progress`.
    /// There is no time limit: on a phone the network comes and goes, and
    /// Tor keeps trying by itself.
    pub async fn start_embedded(data_dir: &Path, mut progress: impl FnMut(u8)) -> Result<Self> {
        if STARTED.swap(true, Ordering::SeqCst) {
            bail!("Tor has already been started in this app; restart the app");
        }
        crate::create_private_dir(data_dir)
            .with_context(|| format!("create {}", data_dir.display()))?;

        let mut args = vec![std::ffi::OsString::from("tor")];
        args.extend(arguments(data_dir));
        args.extend(["Log".into(), "notice stderr".into()]);
        // Tor keeps pointers to these until it exits, which is never before
        // the process does; leak them.
        let argv: Vec<*mut c_char> = args
            .iter()
            .map(|a| CString::new(a.as_bytes()).map(CString::into_raw))
            .collect::<Result<_, _>>()
            .context("Tor setting contains a NUL byte")?;
        let argv: &'static mut [*mut c_char] = Vec::leak(argv);

        // SAFETY: the configuration API is called in the order tor_api.h
        // documents, on one thread, before tor_run_main.
        let (config, control) = unsafe {
            let cfg = tor_main_configuration_new();
            if cfg.is_null() {
                bail!("Tor could not allocate its configuration");
            }
            if tor_main_configuration_set_command_line(cfg, argv.len() as c_int, argv.as_mut_ptr())
                != 0
            {
                bail!("Tor refused its settings");
            }
            // An owning control connection: Tor stops when it closes.
            let fd = tor_main_configuration_setup_control_socket(cfg);
            if fd < 0 {
                bail!("Tor could not open its control connection");
            }
            (Config(cfg), std::os::unix::net::UnixStream::from_raw_fd(fd))
        };
        control.set_nonblocking(true)?;
        let control = UnixStream::from_std(control)?;

        std::thread::Builder::new()
            .name("tor".into())
            .stack_size(8 << 20)
            .spawn(move || {
                let config = config;
                // SAFETY: the configuration is complete and outlives the
                // call (it is never freed).
                let status = unsafe { tor_run_main(config.0) };
                tracing::warn!(target: "tor", "Tor stopped (status {status})");
            })
            .context("start Tor's thread")?;

        let mut control = Control::new(control);
        let mut last = None;
        loop {
            let reply = control.getinfo("status/bootstrap-phase").await?;
            let percent = bootstrap_progress(&reply)
                .ok_or_else(|| anyhow!("Tor gave an unexpected bootstrap status: {reply}"))?;
            if last != Some(percent) {
                progress(percent);
                last = Some(percent);
            }
            if percent == 100 {
                break;
            }
            tokio::time::sleep(POLL_EVERY).await;
        }
        let listeners = control.getinfo("net/listeners/socks").await?;
        let socks = socks_listener(&listeners)
            .ok_or_else(|| anyhow!("Tor did not report its SOCKS port: {listeners}"))?;
        Ok(Self {
            socks,
            _keep: Keep::Control(control.into_inner()),
        })
    }
}

/// A line-based client for Tor's control protocol, enough for GETINFO.
struct Control {
    stream: BufReader<UnixStream>,
}

impl Control {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream: BufReader::new(stream),
        }
    }

    fn into_inner(self) -> UnixStream {
        self.stream.into_inner()
    }

    /// The value of one GETINFO key (`250-key=value` or a `250+key=` block).
    async fn getinfo(&mut self, key: &str) -> Result<String> {
        self.stream
            .get_mut()
            .write_all(format!("GETINFO {key}\r\n").as_bytes())
            .await
            .context("Tor's control connection closed")?;
        let mut value = String::new();
        loop {
            let mut line = String::new();
            if self.stream.read_line(&mut line).await? == 0 {
                bail!("Tor stopped");
            }
            let line = line.trim_end();
            if line.starts_with("650") {
                // An event we did not ask for; not part of the reply.
                continue;
            }
            match line.get(..4) {
                Some("250 ") => return Ok(value),
                Some("250-") | Some("250+") => {
                    if let Some((_, v)) = line[4..].split_once('=') {
                        value = v.to_string();
                    }
                }
                _ if line.starts_with('5') || line.starts_with('4') => {
                    bail!("Tor refused GETINFO {key}: {line}")
                }
                // A line of a `250+` data block, or its closing `.`.
                _ => {}
            }
        }
    }
}

/// `NOTICE BOOTSTRAP PROGRESS=45 TAG=requesting_descriptors SUMMARY="..."`
fn bootstrap_progress(status: &str) -> Option<u8> {
    let (_, rest) = status.split_once("PROGRESS=")?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// `"127.0.0.1:41234"`; the first one if Tor lists several.
fn socks_listener(listeners: &str) -> Option<SocketAddr> {
    listeners
        .split_whitespace()
        .map(|l| l.trim_matches('"'))
        .find_map(|l| l.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_bootstrap_status() {
        let status = r#"NOTICE BOOTSTRAP PROGRESS=45 TAG=requesting_descriptors SUMMARY="Asking for relay descriptors""#;
        assert_eq!(bootstrap_progress(status), Some(45));
        assert_eq!(
            bootstrap_progress(r#"NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done""#),
            Some(100)
        );
        assert_eq!(bootstrap_progress("NOTICE"), None);
    }

    #[test]
    fn reads_the_socks_listener() {
        assert_eq!(
            socks_listener(r#""127.0.0.1:41234""#),
            Some("127.0.0.1:41234".parse().unwrap())
        );
        assert_eq!(socks_listener(""), None);
    }

    /// Starts the real, linked-in Tor and waits for a circuit. Needs the
    /// internet: `cargo test -p privmsg-transport --features embedded-tor
    /// -- --ignored embedded_tor_bootstraps`.
    #[tokio::test]
    #[ignore]
    async fn embedded_tor_bootstraps() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("privmsg-tor-{}", std::process::id()));
        let tor = Tor::start_embedded(&dir, |p| eprintln!("Tor: {p}%")).await?;
        assert!(tor.socks.ip().is_loopback());
        assert!(
            Tor::start_embedded(&dir, |_| {}).await.is_err(),
            "only once"
        );
        drop(tor);
        // Give Tor a moment to exit before its folder goes.
        tokio::time::sleep(Duration::from_secs(1)).await;
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
