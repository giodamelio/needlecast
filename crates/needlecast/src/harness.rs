//! Test scaffolding, compiled only with `--features testing`.
//!
//! `needlecast server` and `needlecast client` deliberately fuse three things: the identity, the
//! tunnel, and the datapath. That is right for the product and wrong for a regression suite, which
//! needs to change one variable at a time. These commands drive one half in isolation:
//!
//! - `bridge` is the client's decision path with an explicit target and no control plane, which
//!   keeps the eight `cgroup_sock_addr` programs testable on a single machine.
//! - `datapath` is the server's tc programs on an interface the harness created, which is the only
//!   coverage of the `ARPHRD_ETHER` L3 offset — the shipped binary only ever attaches to `needle`,
//!   which is `ARPHRD_NONE`.
//!
//! Nothing here is reachable from a binary built without the feature, so none of it can quietly
//! become load bearing for the real thing.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::client::Bridge;
use crate::server::Datapath;
use crate::shutdown::Shutdown;

#[derive(Subcommand)]
pub enum Command {
    /// The client's decision path alone: attach, enable against a fixed target, and hold.
    Bridge {
        /// Where a connection with no local listener is sent.
        #[arg(long)]
        target_v4: Ipv4Addr,
        /// The IPv6 counterpart. The shipped client has none — the tunnel is v4-only — so this is
        /// the only way to exercise the complete `connect6` / `getpeername6` path.
        #[arg(long)]
        target_v6: Option<Ipv6Addr>,
        #[arg(long, default_value_t = 8000)]
        port_lo: u16,
        #[arg(long, default_value_t = 8999)]
        port_hi: u16,
        /// Drop the netns cookie guard. The negative control for the isolation suite: without it
        /// every other assertion there would still pass with the guard deleted.
        #[arg(long)]
        no_netns_guard: bool,
        /// Require a port to be present in DESKTOP_PORTS before rewriting.
        #[arg(long)]
        use_listener_map: bool,
        #[arg(long, default_value_t = 2)]
        syncnt: u8,
        /// Also load the isolated `bpf_setsockopt(TCP_SYNCNT)` probe program.
        #[arg(long)]
        syncnt_probe: bool,
    },
    /// The server's datapath alone: attach to an interface someone else created and hold.
    Datapath {
        /// The transport interface. An ethernet link exercises the L3 offset the product never
        /// sees.
        #[arg(long)]
        iface: String,
        /// This machine's address on that link.
        #[arg(long)]
        transport_v4: Ipv4Addr,
        /// The peer's address on that link.
        #[arg(long)]
        transport_peer_v4: Ipv4Addr,
        #[arg(long, default_value_t = 8000)]
        port_lo: u16,
        #[arg(long, default_value_t = 8999)]
        port_hi: u16,
        /// Also serve the control plane on the transport address.
        #[arg(long)]
        control_port: Option<u16>,
    },
}

pub fn run(cmd: Command) -> Result<()> {
    let shutdown = Shutdown::install()?;
    match cmd {
        Command::Bridge {
            target_v4,
            target_v6,
            port_lo,
            port_hi,
            no_netns_guard,
            use_listener_map,
            syncnt,
            syncnt_probe,
        } => {
            if port_lo > port_hi {
                bail!("--port-lo must not exceed --port-hi");
            }
            let bridge = Bridge::attach_with(crate::client::Attach {
                target_v4,
                target_v6,
                syncnt,
                port_lo,
                port_hi,
                netns_guard: !no_netns_guard,
                // No control plane here, so nothing else would ever enable it.
                enabled: true,
                syncnt_probe,
            })?;
            if !use_listener_map {
                crate::bpf::set_use_listener_map(0)?;
            }
            hold(&shutdown);
            drop(bridge);
            Ok(())
        }
        Command::Datapath {
            iface,
            transport_v4,
            transport_peer_v4,
            port_lo,
            port_hi,
            control_port,
        } => {
            if port_lo > port_hi {
                bail!("--port-lo must not exceed --port-hi");
            }
            let datapath =
                Datapath::attach(&iface, transport_v4, transport_peer_v4, port_lo, port_hi)?;
            match control_port {
                Some(port) => {
                    crate::control::serve(transport_v4, port, port_lo, port_hi, &shutdown)?
                }
                None => hold(&shutdown),
            }
            drop(datapath);
            Ok(())
        }
    }
}

/// The links live in the value the caller holds; dropping it, or dying, detaches everything.
fn hold(shutdown: &Shutdown) {
    while !shutdown.requested() {
        shutdown.sleep(std::time::Duration::from_secs(1));
    }
}
