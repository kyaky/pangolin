//! Native route / address / link management for the pangolin tun
//! device — a Rust replacement for the `pangolin-vpnc-script.sh` shim.
//!
//! # Scope
//!
//! Linux-only for now. Under the hood we shell out to `ip(8)` via
//! [`std::process::Command`]. A future version can swap that for
//! rtnetlink without touching the public API — the [`CommandRunner`]
//! trait exists specifically to keep the call sites testable against
//! a mock while we're still in the shell-out phase.
//!
//! # What it does
//!
//! Given a [`TunConfig`] that describes:
//!
//! * the tun interface name libopenconnect picked (e.g. `"tun0"`),
//! * the server-assigned IPv4 address (from `openconnect_get_ip_info`),
//! * the MTU (optional),
//! * and a list of split-tunnel routes (already parsed into
//!   `ip route`-compatible `cidr` strings),
//!
//! [`apply`] performs the equivalent of:
//!
//! ```text
//! ip link set dev tunN up
//! ip link set dev tunN mtu <mtu>          # only if MTU is set
//! ip addr  add <addr>/32 dev tunN
//! ip route add <route>   dev tunN         # for each route
//! ```
//!
//! Every successfully-installed route is recorded in an
//! [`AppliedState`] that can be passed back to [`revert`] for clean
//! teardown. `revert` is best-effort: it logs individual failures
//! rather than stopping, because partial-success state is more useful
//! than a hard error during cleanup.
//!
//! # What it deliberately does NOT do
//!
//! * DNS configuration — lives in `gp-dns` (future).
//! * Default-route replacement — we only install per-target routes.
//!   Full-tunnel mode is handled by pointing `pgn connect` at a real
//!   vpnc-script the usual way.
//! * Reading libopenconnect's `split_includes` — we take routes from
//!   the caller, because `pgn`'s `--only` semantics (hostname
//!   resolution, CIDR passthrough) are decided in Rust before the
//!   tunnel comes up.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Output};

use thiserror::Error;

/// Description of how a tun interface should be configured.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (`ip link`'s `<dev>` argument). `tun0` etc.
    pub ifname: String,
    /// IPv4 address to assign to the interface (usually the
    /// `INTERNAL_IP4_ADDRESS` from libopenconnect's ip info).
    pub ipv4: Option<Ipv4Addr>,
    /// MTU. Omitted means "leave whatever the kernel picked."
    pub mtu: Option<u16>,
    /// Routes to install, in a form `ip route` accepts. Each entry
    /// should be a CIDR or bare IP (`10.0.0.0/8`, `1.2.3.4/32`).
    /// Validation is the caller's responsibility — `gp-route` does
    /// not sanity-check the strings, it just forwards them.
    pub routes: Vec<String>,
}

/// State produced by a successful (or partially-successful) [`apply`]
/// call. Hand this back to [`revert`] to undo.
#[derive(Debug, Clone, Default)]
pub struct AppliedState {
    pub ifname: String,
    pub installed_routes: Vec<String>,
    pub installed_addr: Option<Ipv4Addr>,
}

/// Errors produced by the `gp-route` API.
#[derive(Debug, Error)]
pub enum RouteError {
    #[error("ip command failed: {op}: {stderr}")]
    IpCommand {
        op: &'static str,
        stderr: String,
    },

    #[error("spawning `ip`: {0}")]
    Spawn(#[from] io::Error),

    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// Abstraction over "run a command and inspect its output."
///
/// Production code uses [`SystemCommandRunner`]. Tests inject a mock
/// that records the argv it was asked to run and replies with a
/// scripted [`Output`].
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error>;
}

/// Default implementation: just [`Command::new`] + `output()`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
        Command::new(program).args(args).output()
    }
}

/// Apply a [`TunConfig`] to the live system. Returns an
/// [`AppliedState`] describing exactly what was installed so the
/// caller can [`revert`] it later.
///
/// The function stops on the first error *during setup* (link up,
/// MTU, address) — those are fatal for the session. Route installation
/// failures are collected and reported as a single error at the end
/// so the caller knows whether every requested route landed.
pub fn apply(config: &TunConfig) -> Result<AppliedState, RouteError> {
    apply_with(&SystemCommandRunner, config)
}

/// Like [`apply`] but uses the given [`CommandRunner`]. Exists for
/// unit tests; production callers should use [`apply`].
pub fn apply_with<R: CommandRunner>(
    runner: &R,
    config: &TunConfig,
) -> Result<AppliedState, RouteError> {
    if config.ifname.is_empty() {
        return Err(RouteError::InvalidConfig(
            "tun interface name is empty".into(),
        ));
    }

    let mut state = AppliedState {
        ifname: config.ifname.clone(),
        ..AppliedState::default()
    };

    // 1. Bring the link up.
    run_ip(
        runner,
        "link up",
        &["link", "set", "dev", &config.ifname, "up"],
    )?;

    // 2. Set MTU if requested.
    if let Some(mtu) = config.mtu {
        let mtu_str = mtu.to_string();
        run_ip(
            runner,
            "set mtu",
            &["link", "set", "dev", &config.ifname, "mtu", &mtu_str],
        )?;
    }

    // 3. Assign the server-provided IPv4 address, if any.
    if let Some(addr) = config.ipv4 {
        let addr_cidr = format!("{addr}/32");
        run_ip(
            runner,
            "addr add",
            &["addr", "add", &addr_cidr, "dev", &config.ifname],
        )?;
        state.installed_addr = Some(addr);
    }

    // 4. Install routes. Collect failures into one error rather than
    //    stopping, so partial success is visible in AppliedState.
    let mut failed: Vec<String> = Vec::new();
    for route in &config.routes {
        if let Err(e) = run_ip(
            runner,
            "route add",
            &["route", "add", route, "dev", &config.ifname],
        ) {
            tracing::warn!("route add {route} on {}: {e}", config.ifname);
            failed.push(route.clone());
        } else {
            state.installed_routes.push(route.clone());
        }
    }

    if !failed.is_empty() {
        return Err(RouteError::IpCommand {
            op: "route add (one or more)",
            stderr: format!(
                "failed to install {} route(s): {}",
                failed.len(),
                failed.join(", ")
            ),
        });
    }

    Ok(state)
}

/// Reverse an [`AppliedState`]. Best-effort: per-route failures are
/// logged (and included in the returned vector) but do not short-
/// circuit the cleanup.
pub fn revert(state: &AppliedState) -> Vec<String> {
    revert_with(&SystemCommandRunner, state)
}

/// Like [`revert`] but uses the given [`CommandRunner`].
pub fn revert_with<R: CommandRunner>(runner: &R, state: &AppliedState) -> Vec<String> {
    let mut errors = Vec::new();

    // Routes come down first so there's no window where an
    // address-less interface still has routes pointing at it.
    for route in &state.installed_routes {
        if let Err(e) = run_ip(
            runner,
            "route del",
            &["route", "del", route, "dev", &state.ifname],
        ) {
            errors.push(format!("route del {route}: {e}"));
        }
    }

    // Then the address.
    if let Some(addr) = state.installed_addr {
        let addr_cidr = format!("{addr}/32");
        if let Err(e) = run_ip(
            runner,
            "addr del",
            &["addr", "del", &addr_cidr, "dev", &state.ifname],
        ) {
            errors.push(format!("addr del {addr_cidr}: {e}"));
        }
    }

    // Leave the link itself alone — libopenconnect owns its lifetime
    // and will tear it down when the session ends.
    errors
}

/// Check whether an [`IpAddr`] is v4 and narrow to [`Ipv4Addr`].
pub fn as_ipv4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(_) => None,
    }
}

fn run_ip<R: CommandRunner>(
    runner: &R,
    op: &'static str,
    args: &[&str],
) -> Result<(), RouteError> {
    tracing::debug!("gp-route: ip {}", args.join(" "));
    let out = runner.run("ip", args)?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(RouteError::IpCommand { op, stderr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    /// Test runner that records every call and lets each test pre-
    /// load a scripted response.
    struct FakeRunner {
        calls: RefCell<Vec<Vec<String>>>,
        outcomes: RefCell<Vec<Result<Output, io::Error>>>,
    }

    impl FakeRunner {
        fn ok() -> Output {
            Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn err(stderr: &str) -> Output {
            Output {
                status: ExitStatus::from_raw(1 << 8), // raw exit status 1
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        fn new(outcomes: Vec<Result<Output, io::Error>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcomes: RefCell::new(outcomes),
            }
        }

        fn all_ok(n: usize) -> Self {
            let outcomes = (0..n).map(|_| Ok(Self::ok())).collect();
            Self::new(outcomes)
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
            let mut full = vec![program.to_string()];
            full.extend(args.iter().map(|s| s.to_string()));
            self.calls.borrow_mut().push(full);
            let mut outcomes = self.outcomes.borrow_mut();
            if outcomes.is_empty() {
                panic!("FakeRunner: no more outcomes queued (unexpected call)");
            }
            outcomes.remove(0)
        }
    }

    fn cfg(routes: Vec<&str>) -> TunConfig {
        TunConfig {
            ifname: "tun7".into(),
            ipv4: Some(Ipv4Addr::new(10, 1, 2, 3)),
            mtu: Some(1422),
            routes: routes.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn apply_issues_expected_commands_in_order() {
        let runner = FakeRunner::all_ok(5);
        let state = apply_with(&runner, &cfg(vec!["10.0.0.0/8", "172.16.0.0/12"])).unwrap();

        assert_eq!(state.ifname, "tun7");
        assert_eq!(state.installed_addr, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(state.installed_routes, vec!["10.0.0.0/8", "172.16.0.0/12"]);

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0], vec!["ip", "link", "set", "dev", "tun7", "up"]);
        assert_eq!(
            calls[1],
            vec!["ip", "link", "set", "dev", "tun7", "mtu", "1422"]
        );
        assert_eq!(
            calls[2],
            vec!["ip", "addr", "add", "10.1.2.3/32", "dev", "tun7"]
        );
        assert_eq!(
            calls[3],
            vec!["ip", "route", "add", "10.0.0.0/8", "dev", "tun7"]
        );
        assert_eq!(
            calls[4],
            vec!["ip", "route", "add", "172.16.0.0/12", "dev", "tun7"]
        );
    }

    #[test]
    fn apply_skips_mtu_and_addr_when_not_set() {
        let config = TunConfig {
            ifname: "tun0".into(),
            ipv4: None,
            mtu: None,
            routes: vec!["10.0.0.0/8".into()],
        };
        let runner = FakeRunner::all_ok(2);
        apply_with(&runner, &config).unwrap();
        let calls = runner.calls.borrow();
        // Only: link up, route add.
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1..4], ["link", "set", "dev"]);
        assert_eq!(calls[1][1..3], ["route", "add"]);
    }

    #[test]
    fn apply_fails_fast_on_link_up() {
        let runner = FakeRunner::new(vec![Ok(FakeRunner::err("boom"))]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(matches!(err, RouteError::IpCommand { op: "link up", .. }));
        assert_eq!(runner.calls.borrow().len(), 1);
    }

    #[test]
    fn apply_collects_route_failures_into_single_error() {
        // link up, mtu, addr, route1 (ok), route2 (fail), route3 (ok)
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),
            Ok(FakeRunner::ok()),
            Ok(FakeRunner::ok()),
            Ok(FakeRunner::ok()),
            Ok(FakeRunner::err("route2 broken")),
            Ok(FakeRunner::ok()),
        ]);
        let err = apply_with(
            &runner,
            &cfg(vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
        )
        .unwrap_err();
        match err {
            RouteError::IpCommand { op, stderr } => {
                assert_eq!(op, "route add (one or more)");
                assert!(stderr.contains("172.16.0.0/12"), "got: {stderr}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn revert_removes_routes_and_address() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            installed_addr: Some(Ipv4Addr::new(172, 17, 0, 2)),
        };
        let runner = FakeRunner::all_ok(3);
        let errors = revert_with(&runner, &state);
        assert!(errors.is_empty(), "{errors:?}");
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 3);
        // Routes come down first.
        assert_eq!(
            calls[0],
            vec!["ip", "route", "del", "10.0.0.0/8", "dev", "tun0"]
        );
        assert_eq!(
            calls[1],
            vec!["ip", "route", "del", "192.168.1.0/24", "dev", "tun0"]
        );
        // Then the address.
        assert_eq!(
            calls[2],
            vec!["ip", "addr", "del", "172.17.0.2/32", "dev", "tun0"]
        );
    }

    #[test]
    fn revert_is_best_effort_on_per_item_failure() {
        let state = AppliedState {
            ifname: "tun0".into(),
            installed_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            installed_addr: None,
        };
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::err("first gone")),
            Ok(FakeRunner::ok()),
        ]);
        let errors = revert_with(&runner, &state);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("10.0.0.0/8"), "{errors:?}");
    }

    #[test]
    fn empty_ifname_is_rejected() {
        let config = TunConfig {
            ifname: String::new(),
            ipv4: None,
            mtu: None,
            routes: vec![],
        };
        let runner = FakeRunner::all_ok(0);
        let err = apply_with(&runner, &config).unwrap_err();
        assert!(matches!(err, RouteError::InvalidConfig(_)));
    }
}
