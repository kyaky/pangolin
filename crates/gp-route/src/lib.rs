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
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default per-`ip(8)` timeout. Route/addr/link operations should
/// finish in milliseconds on a healthy kernel; 10 seconds is ample
/// headroom and short enough that a wedged child can't starve the
/// about-to-start openconnect main loop.
pub const DEFAULT_IP_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

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
    IpCommand { op: &'static str, stderr: String },

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

/// Default implementation: spawn the child, poll with `try_wait`
/// until completion or [`DEFAULT_IP_COMMAND_TIMEOUT`], then collect
/// stdout/stderr.
///
/// The extra machinery exists to bound how long we'll wait on a
/// wedged `ip(8)` process. The bare `Command::output()` we used
/// before had no timeout, which meant a stuck child during `apply`
/// could starve libopenconnect's about-to-start main loop.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<Output, io::Error> {
        run_with_timeout(program, args, DEFAULT_IP_COMMAND_TIMEOUT)
    }
}

/// Run `program args` and wait up to `timeout`. On timeout the
/// child is SIGKILL'd and reaped before an `io::ErrorKind::TimedOut`
/// error is returned. Stdout/stderr are captured regardless of
/// success so the caller can log them.
fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => {
                // wait_with_output drains the pipes and reaps the
                // zombie. try_wait already observed exit, so this
                // returns immediately.
                return child.wait_with_output().map(|o| Output {
                    status,
                    stdout: o.stdout,
                    stderr: o.stderr,
                });
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "`{program} {}` did not exit within {:?}",
                            args.join(" "),
                            timeout
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Apply a [`TunConfig`] to the live system. Returns a fully-
/// populated [`AppliedState`] on success. On ANY failure during
/// setup — link up, MTU, address, or route installation — the
/// function auto-rolls-back everything it installed so far (best-
/// effort), logs per-step failures via `tracing`, and returns the
/// triggering error. Callers therefore see an all-or-nothing
/// transition: either every route is up, or none of them are.
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

    // Helper: roll back whatever `state` currently reports, then
    // return the triggering error. Keeps the control flow linear.
    let rollback_and_fail = |runner: &R, state: &AppliedState, err: RouteError| -> RouteError {
        if !state.installed_routes.is_empty() || state.installed_addr.is_some() {
            for rev_err in revert_with(runner, state) {
                tracing::warn!("gp-route apply-rollback: {rev_err}");
            }
        }
        err
    };

    // 1. Bring the link up. Nothing in `state` to roll back yet, so
    //    a failure here just propagates.
    run_ip(
        runner,
        "link up",
        &["link", "set", "dev", &config.ifname, "up"],
    )?;

    // 2. Set MTU if requested. Still nothing rollback-worthy in
    //    `state` — gp-route doesn't own the link itself.
    if let Some(mtu) = config.mtu {
        let mtu_str = mtu.to_string();
        run_ip(
            runner,
            "set mtu",
            &["link", "set", "dev", &config.ifname, "mtu", &mtu_str],
        )?;
    }

    // 3. Assign the server-provided IPv4 address, if any. Record it
    //    in `state` AFTER it lands so a failure in the next step
    //    triggers address cleanup, but a failure HERE is still a
    //    bare `?` because there's nothing to clean up.
    if let Some(addr) = config.ipv4 {
        let addr_cidr = format!("{addr}/32");
        run_ip(
            runner,
            "addr add",
            &["addr", "add", &addr_cidr, "dev", &config.ifname],
        )?;
        state.installed_addr = Some(addr);
    }

    // 4. Install routes one at a time. On the first failure, roll
    //    back everything — including any routes already installed
    //    in this loop — so the caller sees all-or-nothing state.
    for route in &config.routes {
        if let Err(e) = run_ip(
            runner,
            "route add",
            &["route", "add", route, "dev", &config.ifname],
        ) {
            tracing::warn!(
                "gp-route: route add {route} on {} failed ({e}); rolling back",
                config.ifname
            );
            return Err(rollback_and_fail(runner, &state, e));
        }
        state.installed_routes.push(route.clone());
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

fn run_ip<R: CommandRunner>(runner: &R, op: &'static str, args: &[&str]) -> Result<(), RouteError> {
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
    fn apply_auto_rolls_back_on_route_failure() {
        // Setup:     link up, mtu, addr, route1 (ok), route2 (fail).
        // Rollback:  route del route1, addr del.
        // We expect 7 calls total, and the returned error must
        // refer to the failing route add (not a rollback step).
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),              // link up
            Ok(FakeRunner::ok()),              // mtu
            Ok(FakeRunner::ok()),              // addr add
            Ok(FakeRunner::ok()),              // route add 10.0.0.0/8
            Ok(FakeRunner::err("route2 bad")), // route add 172.16.0.0/12 FAILS
            Ok(FakeRunner::ok()),              // route del 10.0.0.0/8 (rollback)
            Ok(FakeRunner::ok()),              // addr del (rollback)
        ]);
        let err = apply_with(
            &runner,
            &cfg(vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
        )
        .unwrap_err();
        match err {
            RouteError::IpCommand { op, stderr } => {
                assert_eq!(op, "route add");
                assert!(stderr.contains("route2 bad"), "got: {stderr}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 7, "call sequence: {:#?}", calls);
        assert_eq!(
            calls[5],
            vec!["ip", "route", "del", "10.0.0.0/8", "dev", "tun7"],
            "first rollback step must be `route del` for the successful route"
        );
        assert_eq!(
            calls[6],
            vec!["ip", "addr", "del", "10.1.2.3/32", "dev", "tun7"],
            "second rollback step must be `addr del`"
        );
    }

    #[test]
    fn apply_rolls_back_address_on_first_route_failure() {
        // Address was just added; first route fails. Rollback must
        // remove the address (no routes to remove yet).
        let runner = FakeRunner::new(vec![
            Ok(FakeRunner::ok()),        // link up
            Ok(FakeRunner::ok()),        // mtu
            Ok(FakeRunner::ok()),        // addr add
            Ok(FakeRunner::err("nope")), // route add FAILS
            Ok(FakeRunner::ok()),        // addr del (rollback)
        ]);
        let err = apply_with(&runner, &cfg(vec!["10.0.0.0/8"])).unwrap_err();
        assert!(matches!(
            err,
            RouteError::IpCommand {
                op: "route add",
                ..
            }
        ));
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 5);
        assert_eq!(
            calls[4],
            vec!["ip", "addr", "del", "10.1.2.3/32", "dev", "tun7"]
        );
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
