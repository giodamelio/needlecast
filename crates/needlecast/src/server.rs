//! The machine whose loopback ports are being reached.
//!
//! Stateless with respect to the client, so one that vanishes needs no cleanup: the tc programs
//! stay attached and simply never match.

use std::net::Ipv4Addr;

use anyhow::{anyhow, bail, Context, Result};
use aya::programs::tc::{SchedClassifierLink, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use needlecast_common::SleeveConfig;

use crate::bpf;
use crate::control;
use crate::identity::{Identity, Role};
use crate::shutdown::Shutdown;
use crate::transport::{self, Tunnel};

/// Not configurable: the point is that what a server is told is byte-identical to a genuinely
/// local connection.
const LOCAL_V4: Ipv4Addr = Ipv4Addr::LOCALHOST;

pub struct Args {
    pub secret: std::path::PathBuf,
    pub peer: String,
    pub port_lo: u16,
    pub port_hi: u16,
    pub listen_port: u16,
    pub control_port: u16,
}

pub async fn run(a: Args) -> Result<()> {
    if a.port_lo > a.port_hi {
        bail!("--port-lo must not exceed --port-hi");
    }
    let identity = Identity::load(&a.secret, Role::Server)?;
    let mut shutdown = Shutdown::install()?;

    let endpoint = format!("{}:{}", a.peer, a.listen_port);
    let tunnel = Tunnel::up(&identity, &endpoint, a.listen_port).await?;

    let datapath = Datapath::attach(
        transport::IFACE,
        tunnel.own_addr(),
        tunnel.peer_addr(),
        a.port_lo,
        a.port_hi,
    )?;

    log::info!(
        "serving loopback ports {}-{} to {} on {}",
        a.port_lo,
        a.port_hi,
        tunnel.peer_addr(),
        transport::IFACE
    );
    control::serve(
        tunnel.own_addr(),
        a.control_port,
        a.port_lo,
        a.port_hi,
        &mut shutdown,
    )
    .await?;

    drop(datapath);
    tunnel.down()
}

/// Split out so its shape is testable without a kernel: a byte-order slip here would be invisible
/// until traffic failed to match.
fn sleeve_config(
    transport_v4: Ipv4Addr,
    transport_peer_v4: Ipv4Addr,
    port_lo: u16,
    port_hi: u16,
    l3_offset: u16,
) -> SleeveConfig {
    SleeveConfig {
        transport_v4: bpf::v4_be(transport_v4),
        transport_peer_v4: bpf::v4_be(transport_peer_v4),
        local_v4: bpf::v4_be(LOCAL_V4),
        transport_v6: [0; 4],
        transport_peer_v6: [0; 4],
        local_v6: [0; 4],
        port_lo,
        port_hi,
        l3_offset,
        enabled: 1,
        _pad: 0,
    }
}

/// Dropping it, or dying, detaches every program and reverts the machine.
pub struct Datapath {
    _ebpf: aya::Ebpf,
    _links: Vec<SchedClassifierLink>,
    _cgroup: std::fs::File,
}

impl Datapath {
    pub fn attach(
        iface: &str,
        transport_v4: Ipv4Addr,
        transport_peer_v4: Ipv4Addr,
        port_lo: u16,
        port_hi: u16,
    ) -> Result<Self> {
        bpf::reset_pin_dir(bpf::SERVER_PIN_DIR)?;
        bpf::clear_ready(bpf::SERVER_READY_FILE);

        let l3_offset = bpf::l3_offset_for(iface)?;
        let mut ebpf = bpf::load_object(bpf::SERVER_PIN_DIR)?;

        // clsact must exist before either direction can attach; it may already be there.
        let _ = aya::programs::tc::qdisc_add_clsact(iface);

        let mut links = Vec::new();
        bpf::attach_tc(
            &mut ebpf,
            "tc_ingress",
            iface,
            TcAttachType::Ingress,
            &mut links,
        )?;
        bpf::attach_tc(
            &mut ebpf,
            "tc_egress",
            iface,
            TcAttachType::Egress,
            &mut links,
        )?;

        // The one program outside the transport interface. It changes nothing on the machine —
        // only what a server is told about its peer.
        let cgroup = std::fs::File::open(bpf::CGROUP_ROOT)
            .with_context(|| format!("opening {}", bpf::CGROUP_ROOT))?;
        let program: &mut CgroupSockAddr = ebpf
            .program_mut("sleeve_getpeername4")
            .ok_or_else(|| anyhow!("sleeve_getpeername4 not found"))?
            .try_into()?;
        program.load().context("loading sleeve_getpeername4")?;
        program
            .attach(&cgroup, CgroupAttachMode::Single)
            .context("attaching sleeve_getpeername4")?;

        let config = sleeve_config(transport_v4, transport_peer_v4, port_lo, port_hi, l3_offset);
        let mut cfg_map: aya::maps::Array<_, SleeveConfig> = ebpf
            .map_mut("SLEEVE_CONFIG")
            .ok_or_else(|| anyhow!("SLEEVE_CONFIG map missing"))?
            .try_into()?;
        cfg_map.set(0, config, 0)?;

        bpf::write_ready(
            bpf::SERVER_READY_FILE,
            &format!(
                "iface={iface}\nl3_offset={l3_offset}\ntransport={transport_v4}\n\
                 peer={transport_peer_v4}\nports={port_lo}-{port_hi}\n\
                 attached=tc_ingress,tc_egress,sleeve_getpeername4\n"
            ),
        )?;
        log::info!("datapath attached to {iface}, L3 offset {l3_offset}");
        println!("ready");

        Ok(Datapath {
            _ebpf: ebpf,
            _links: links,
            _cgroup: cgroup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use needlecast_common::net;

    fn cfg(l3_offset: u16) -> SleeveConfig {
        sleeve_config(
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 18, 0, 2),
            8000,
            8999,
            l3_offset,
        )
    }

    /// A host-order slip would never match, and the datapath would silently pass everything.
    #[test]
    fn addresses_are_stored_in_network_byte_order() {
        let c = cfg(0);
        assert_eq!(u32::from_be(c.transport_v4), 0xC612_0001);
        assert_eq!(u32::from_be(c.transport_peer_v4), 0xC612_0002);
        assert_eq!(c.local_v4, net::LOOPBACK_V4);
    }

    #[test]
    fn delivery_is_always_plain_loopback() {
        assert_eq!(LOCAL_V4, Ipv4Addr::LOCALHOST);
        assert!(net::is_loopback_v4(cfg(0).local_v4));
    }

    /// 14 on an Ethernet-framed link, 0 on an L3-only one; one program serves both.
    #[test]
    fn the_l3_offset_is_carried_rather_than_guessed() {
        assert_eq!(cfg(0).l3_offset, 0);
        assert_eq!(cfg(14).l3_offset, 14);
    }

    #[test]
    fn the_managed_range_is_carried_verbatim() {
        let c = cfg(0);
        assert!(net::port_in_range(8000, c.port_lo, c.port_hi));
        assert!(net::port_in_range(8999, c.port_lo, c.port_hi));
        assert!(!net::port_in_range(7999, c.port_lo, c.port_hi));
        assert!(!net::port_in_range(9000, c.port_lo, c.port_hi));
    }

    /// Otherwise the datapath would rewrite the control plane's own packets.
    #[test]
    fn the_control_port_is_outside_the_range_it_serves() {
        let c = cfg(0);
        assert!(!net::port_in_range(
            needlecast_common::proto::DEFAULT_CONTROL_PORT,
            c.port_lo,
            c.port_hi
        ));
    }

    /// Unlike the client, it holds no state about the peer, so there is nothing to wait for.
    #[test]
    fn the_datapath_is_enabled_from_the_start() {
        assert_eq!(cfg(0).enabled, 1);
    }
}
