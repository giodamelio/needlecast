//! Test scaffolding, compiled only with `--features testing`.
//!
//! `server` and `client` fuse the identity, the tunnel and the datapath — right for the product,
//! wrong for a suite that needs to change one variable at a time. These drive one half alone.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::client::Bridge;
use crate::server::Datapath;
use crate::shutdown::Shutdown;

#[derive(Subcommand)]
pub enum Command {
    /// The client's decision path alone, against a fixed target and no control plane.
    Bridge {
        #[arg(long)]
        target_v4: Ipv4Addr,
        /// The shipped client has none, so this is the only way to exercise `connect6`.
        #[arg(long)]
        target_v6: Option<Ipv6Addr>,
        #[arg(long, default_value_t = 8000)]
        port_lo: u16,
        #[arg(long, default_value_t = 8999)]
        port_hi: u16,
        /// The isolation suite's negative control: without it every other assertion there would
        /// still pass with the guard deleted.
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
    /// The server's datapath alone, on an interface someone else created. An ethernet link is the
    /// only coverage of the `ARPHRD_ETHER` L3 offset, which the product never sees.
    Datapath {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        transport_v4: Ipv4Addr,
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

pub async fn run(cmd: Command) -> Result<()> {
    let mut shutdown = Shutdown::install()?;
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
                // Nothing else would ever enable it: there is no control plane here.
                enabled: true,
                syncnt_probe,
            })?;
            if !use_listener_map {
                crate::bpf::set_use_listener_map(0)?;
            }
            hold(&mut shutdown).await;
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
                    crate::control::serve(transport_v4, port, port_lo, port_hi, &mut shutdown)
                        .await?
                }
                None => hold(&mut shutdown).await,
            }
            drop(datapath);
            Ok(())
        }
    }
}

/// Stay attached until told to stop: the suite drives the machine, not this process.
async fn hold(shutdown: &mut Shutdown) {
    shutdown.requested().await;
}
