//! Tor in front of Nym, so the entry gateway never learns our IP.
//!
//! Without it, the Nym gateway each address registers with sees the user's
//! IP: not what they say or to whom, but that this IP runs privmsg. With it,
//! the path is `us → Tor (3 hops) → gateway → mixnet`, the gateway sees a
//! Tor exit, and the local network sees only Tor.
//!
//! Tor runs as a child process (the official `tor` binary, shipped in a
//! `tor/` folder next to privmsg, or found on `PATH`) rather than as a
//! library: Arti, the Rust Tor, links a SQLite that clashes with the one
//! Nym's storage links. Every Nym connection goes through its SOCKS port:
//!
//! - gateway websockets, via `set_socks5_proxy` in our patched
//!   `nym-gateway-client` (vendor/README.md);
//! - Nym API requests (topology, gateway list), via a config record in
//!   Nym's HTTP client registry, with the `*_PROXY` variables as a backstop
//!   for any client built outside it.
//!
//! Host names go to Tor unresolved (`socks5h`), so DNS doesn't leak either.
//! If Tor can't start, we stop rather than connect without it.
//!
//! Phones can't start other programs, so the iPhone app links the same C
//! tor in as a library instead and runs it on a thread of its own
//! ([`Tor::start_embedded`], behind the `embedded-tor` feature).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use nym_gateway_client::Socks5Proxy;
use nym_http_api_client::registry::ConfigRecord;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};

/// How long Tor gets to connect. A first start downloads the directory;
/// later ones reuse it from `data_dir` and take seconds.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(180);

/// The proxy URL for Nym's HTTP clients, once Tor is up.
static HTTP_PROXY: OnceLock<String> = OnceLock::new();

nym_http_api_client::inventory::submit! {
    ConfigRecord {
        // After Nym's own records, so nothing replaces the proxy.
        priority: 1000,
        apply: |builder| match HTTP_PROXY.get().map(|url| reqwest::Proxy::all(url.as_str())) {
            Some(Ok(proxy)) => builder.proxy(proxy),
            // Unreachable for our own URL; never fall back to a direct
            // connection — an unusable proxy fails every request instead.
            Some(Err(_)) => builder.proxy(
                reqwest::Proxy::all("socks5h://0.0.0.0:9").expect("static proxy URL"),
            ),
            None => builder,
        },
    }
}

/// A running Tor. Dropping it stops Tor.
pub struct Tor {
    pub(crate) socks: SocketAddr,
    pub(crate) _keep: Keep,
}

/// What keeps Tor running: the child process, or (embedded) the control
/// connection that owns it.
pub(crate) enum Keep {
    Child(#[allow(dead_code)] Child),
    #[cfg(feature = "embedded-tor")]
    Control(#[allow(dead_code)] tokio::net::UnixStream),
}

impl Tor {
    /// Start Tor with its state in `data_dir` and wait until it has a
    /// circuit, reporting bootstrap percentages to `progress`.
    pub async fn start(data_dir: &Path, mut progress: impl FnMut(u8)) -> Result<Self> {
        let binary = find_binary().ok_or_else(|| {
            anyhow!(
                "Tor was not found. It comes in the `tor` folder of the privmsg download; \
                 keep that folder next to privmsg. Or install Tor (`brew install tor`, \
                 `sudo apt install tor`), or run `privmsg tor off` to connect without \
                 hiding your IP address."
            )
        })?;
        crate::create_private_dir(data_dir)
            .with_context(|| format!("create {}", data_dir.display()))?;

        let mut command = Command::new(&binary);
        command
            .args(arguments(data_dir))
            .args(["Log", "notice stdout"])
            // Tor exits by itself if privmsg dies without stopping it.
            .args(["__OwningControllerProcess", &std::process::id().to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        // The Linux bundle keeps its OpenSSL and libevent beside tor but
        // doesn't tell the loader to look there.
        #[cfg(target_os = "linux")]
        if let Some(dir) = binary.parent() {
            let mut paths = vec![dir.to_path_buf()];
            if let Some(old) = std::env::var_os("LD_LIBRARY_PATH") {
                paths.extend(std::env::split_paths(&old));
            }
            command.env("LD_LIBRARY_PATH", std::env::join_paths(paths)?);
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start Tor ({})", binary.display()))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut lines = BufReader::new(stdout).lines();

        let socks =
            match tokio::time::timeout(BOOTSTRAP_TIMEOUT, bootstrap(&mut lines, &mut progress))
                .await
            {
                Ok(Ok(socks)) => socks,
                Ok(Err(e)) => {
                    let exit = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                    return Err(match exit {
                        Ok(Ok(status)) => e.context(format!("Tor exited ({status})")),
                        _ => e,
                    });
                }
                Err(_) => {
                    bail!("Tor could not connect within 3 minutes. Is the internet working?")
                }
            };
        // Keep draining Tor's log so its pipe never fills.
        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::debug!(target: "tor", "{line}");
            }
        });
        Ok(Self {
            socks,
            _keep: Keep::Child(child),
        })
    }

    /// Send every Nym connection this process makes through this Tor.
    /// Call before any Nym client starts; once per process.
    pub fn route_nym(&self) -> Result<()> {
        let proxy = Socks5Proxy {
            address: self.socks,
            username: "privmsg".into(),
            password: "gateway".into(),
        };
        if !nym_gateway_client::set_socks5_proxy(proxy) {
            bail!("Nym is already routed through a Tor");
        }
        let url = format!("socks5h://privmsg:api@{}", self.socks);
        // Backstop for HTTP clients built outside Nym's registry. Set before
        // any of them exist, while nothing else reads the environment.
        for var in ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY"] {
            std::env::set_var(var, &url);
            std::env::set_var(var.to_lowercase(), &url);
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
        HTTP_PROXY
            .set(url)
            .map_err(|_| anyhow!("Nym is already routed through a Tor"))
    }
}

/// The settings privmsg runs Tor with, as command-line arguments.
pub(crate) fn arguments(data_dir: &Path) -> Vec<std::ffi::OsString> {
    // Our settings only: ignore any system-wide torrc.
    let none = data_dir.join("no-torrc");
    let mut args: Vec<std::ffi::OsString> = vec![
        "-f".into(),
        none.clone().into(),
        "--defaults-torrc".into(),
        none.into(),
        "--ignore-missing-torrc".into(),
        "DataDirectory".into(),
        data_dir.into(),
    ];
    // Each gateway connection (numbered SOCKS user, see the vendored
    // gateway client) and the API get their own circuits.
    for arg in [
        "SocksPort",
        "127.0.0.1:auto IsolateDestAddr IsolateSOCKSAuth",
        "ClientOnly",
        "1",
        "AvoidDiskWrites",
        "1",
    ] {
        args.push(arg.into());
    }
    args
}

/// Read Tor's log until it is fully bootstrapped; the SOCKS port it chose.
async fn bootstrap(
    lines: &mut Lines<BufReader<ChildStdout>>,
    progress: &mut impl FnMut(u8),
) -> Result<SocketAddr> {
    let mut socks = None;
    let mut last_problem = String::new();
    while let Some(line) = lines.next_line().await? {
        tracing::debug!(target: "tor", "{line}");
        if let Some(addr) = socks_port(&line) {
            socks = Some(addr);
        } else if let Some(percent) = bootstrap_percent(&line) {
            progress(percent);
            if percent == 100 {
                return socks.ok_or_else(|| anyhow!("Tor did not report its SOCKS port"));
            }
        } else if line.contains("[err]") || line.contains("[warn]") {
            last_problem = line;
        }
    }
    bail!("Tor stopped while starting. {last_problem}")
}

/// `... Opened Socks listener connection (ready) on 127.0.0.1:41234`
fn socks_port(line: &str) -> Option<SocketAddr> {
    let (_, addr) = line.split_once("Opened Socks listener connection (ready) on ")?;
    addr.trim().parse().ok()
}

/// `... [notice] Bootstrapped 45% (requesting_descriptors): ...`
fn bootstrap_percent(line: &str) -> Option<u8> {
    let (_, rest) = line.split_once("Bootstrapped ")?;
    rest.split_once('%')?.0.parse().ok()
}

/// `PRIVMSG_TOR`, else `tor/tor` next to the privmsg executable, else `tor`
/// on `PATH`.
fn find_binary() -> Option<PathBuf> {
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };
    if let Some(path) = std::env::var_os("PRIVMSG_TOR") {
        return Some(PathBuf::from(path));
    }
    let bundled = std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("tor").join(name)));
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(name));
    bundled.into_iter().chain(on_path).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_socks_port() {
        let line = "Oct 23 10:00:00.000 [notice] Opened Socks listener connection (ready) on 127.0.0.1:41234";
        assert_eq!(socks_port(line), Some("127.0.0.1:41234".parse().unwrap()));
        assert_eq!(
            socks_port("[notice] Opening Socks listener on 127.0.0.1:0"),
            None
        );
    }

    #[test]
    fn reads_bootstrap_progress() {
        let line = "Oct 23 10:00:01.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors";
        assert_eq!(bootstrap_percent(line), Some(45));
        assert_eq!(
            bootstrap_percent("[notice] Bootstrapped 100% (done): Done"),
            Some(100)
        );
        assert_eq!(
            bootstrap_percent("[notice] Tor 0.4.8 opening log file."),
            None
        );
    }
}
