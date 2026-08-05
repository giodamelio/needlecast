//! Loading, attaching, and reaching the pinned maps.
//!
//! Both halves of needlecast load the same object and keep their programs alive by holding the
//! `bpf_link`s. Dropping them — or dying — detaches everything, which is what makes a crashed
//! daemon revert the machine to stock rather than leave it half-configured.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::tc::{SchedClassifierLink, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier};
use aya::{Ebpf, EbpfLoader};
use needlecast_common::{Config, CONFIG_KEY};

/// Plain `include_bytes!` yields alignment 1, but the `object` crate parses the ELF header
/// zero-copy and needs it aligned. Whether that happens to work depends on where the linker put
/// the array, so it fails intermittently across rebuilds.
pub const OBJECT: &[u8] = aya::include_bytes_aligned!(env!("NEEDLECAST_EBPF_OBJ"));

/// What `include_bytes_aligned!` guarantees.
pub const OBJECT_ALIGN: usize = 32;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const RUN_DIR: &str = "/run/needlecast";

/// The laptop half: `cgroup_sock_addr` programs and the maps they decide from.
pub const CLIENT_PIN_DIR: &str = "/sys/fs/bpf/needlecast/client";
pub const CLIENT_READY_FILE: &str = "/run/needlecast/client.ready";

/// The desktop half: the tc datapath and its own config.
pub const SERVER_PIN_DIR: &str = "/sys/fs/bpf/needlecast/server";
pub const SERVER_READY_FILE: &str = "/run/needlecast/server.ready";

/// What the server attaches. Named here so `status` can ask whether they are still loaded, which
/// is the only honest liveness signal: they disappear with the process holding their links.
pub const SERVER_PROGRAMS: &[&str] = &["tc_ingress", "tc_egress", "sleeve_getpeername4"];

/// Attached to the cgroup on the client, in this order.
pub const CLIENT_PROGRAMS: &[&str] = &[
    "connect4",
    "connect6",
    "getpeername4",
    "getpeername6",
    "sendmsg4",
    "sendmsg6",
    "recvmsg4",
    "recvmsg6",
];

/// Alignment of the embedded object is guaranteed by `include_bytes_aligned!`, but the failure it
/// prevents is intermittent and its error message points nowhere useful, so check it explicitly
/// rather than letting a regression come back as a confusing ELF parse error on one build in three.
pub fn assert_object_aligned() -> Result<()> {
    let offset = OBJECT.as_ptr() as usize % OBJECT_ALIGN;
    if offset != 0 {
        bail!(
            "embedded object is misaligned by {offset} bytes (address {:p}); \
             it must be included with aya::include_bytes_aligned!",
            OBJECT.as_ptr()
        );
    }
    Ok(())
}

/// `EbpfError`'s inner `object::read::Error` is not exposed as a `source`, so the Display chain
/// stops at "error parsing ELF data". Debug is the only way to see what actually went wrong.
pub fn load_object(pin_dir: &str) -> Result<Ebpf> {
    assert_object_aligned()?;
    EbpfLoader::new()
        .map_pin_path(pin_dir)
        .load(OBJECT)
        .map_err(|e| anyhow!("loading BPF object: {e:?}"))
}

/// Stale pins from a previous run would silently carry old counters and config forward.
pub fn reset_pin_dir(dir: &str) -> Result<()> {
    if Path::new(dir).exists() {
        std::fs::remove_dir_all(dir)
            .with_context(|| format!("clearing stale pin directory {dir}"))?;
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating pin directory {dir}"))?;
    Ok(())
}

/// Written only after every attach and config write succeeded, so tests and `status` can wait on
/// real readiness instead of on the map pins, which appear during load and survive a crash.
pub fn write_ready(path: &str, contents: &str) -> Result<()> {
    std::fs::create_dir_all(RUN_DIR).with_context(|| format!("creating {RUN_DIR}"))?;
    std::fs::write(path, contents).with_context(|| format!("writing {path}"))
}

pub fn clear_ready(path: &str) {
    let _ = std::fs::remove_file(path);
}

pub fn attach_cgroup(ebpf: &mut Ebpf, name: &str, cgroup: &std::fs::File) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("program {name} not found in object"))?
        .try_into()?;
    program.load()?;
    // `AllowMultiple` maps to BPF_F_ALLOW_MULTI, which `bpf_link_create` rejects with EINVAL.
    // `Single` maps to flags 0 and, despite the name, does not restrict us to one program.
    program.attach(cgroup, CgroupAttachMode::Single)?;
    Ok(())
}

pub fn attach_tc(
    ebpf: &mut Ebpf,
    name: &str,
    iface: &str,
    direction: TcAttachType,
    links: &mut Vec<SchedClassifierLink>,
) -> Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("program {name} not found"))?
        .try_into()?;
    program.load().with_context(|| format!("loading {name}"))?;
    let id = program
        .attach(iface, direction)
        .with_context(|| format!("attaching {name} to {iface}"))?;
    links.push(program.take_link(id)?);
    Ok(())
}

/// 1 is `ARPHRD_ETHER`, so the IP header sits after a 14-byte link header. A WireGuard interface
/// reports `ARPHRD_NONE` and has no link header at all. Reading it beats guessing, and it is the
/// single value that lets one program serve both device classes.
pub fn l3_offset_for(iface: &str) -> Result<u16> {
    let path = format!("/sys/class/net/{iface}/type");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let arphrd: u32 = raw.trim().parse().context("parsing interface type")?;
    const ARPHRD_ETHER: u32 = 1;
    const ARPHRD_LOOPBACK: u32 = 772;
    Ok(match arphrd {
        ARPHRD_ETHER | ARPHRD_LOOPBACK => 14,
        _ => 0,
    })
}

/// `SO_NETNS_COOKIE` on any socket returns the cookie of the namespace it was created in, which is
/// what `bpf_get_netns_cookie` reports from inside the program.
pub fn netns_cookie() -> Result<u64> {
    const SO_NETNS_COOKIE: libc::c_int = 71;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            bail!("socket: {}", std::io::Error::last_os_error());
        }
        let mut cookie: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        let rc = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_NETNS_COOKIE,
            &mut cookie as *mut u64 as *mut libc::c_void,
            &mut len,
        );
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if rc != 0 {
            bail!("getsockopt(SO_NETNS_COOKIE): {err}");
        }
        Ok(cookie)
    }
}

pub fn v4_be(addr: Ipv4Addr) -> u32 {
    u32::from(addr).to_be()
}

/// Four network-byte-order words, matching `bpf_sock_addr::user_ip6`.
pub fn v6_words(addr: std::net::Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    let mut w = [0u32; 4];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]).to_be();
    }
    w
}

pub fn open_pinned(dir: &str, name: &str, wrap: fn(MapData) -> Map) -> Result<Map> {
    let path = Path::new(dir).join(name);
    let data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map {}", path.display()))?;
    Ok(wrap(data))
}

pub fn read_config() -> Result<Config> {
    let m = open_pinned(CLIENT_PIN_DIR, "CONFIG", Map::Array)?;
    let map: Array<_, Config> = (&m).try_into()?;
    Ok(map.get(&CONFIG_KEY, 0)?)
}

pub fn set_enabled(value: u8) -> Result<()> {
    update_config(|c| c.enabled = value)
}

#[cfg(feature = "testing")]
pub fn set_use_listener_map(value: u8) -> Result<()> {
    update_config(|c| c.use_listener_map = value)
}

pub fn set_port_range(port_lo: u16, port_hi: u16) -> Result<()> {
    update_config(|c| {
        c.port_lo = port_lo;
        c.port_hi = port_hi;
    })
}

fn update_config(f: impl FnOnce(&mut Config)) -> Result<()> {
    let mut m = open_pinned(CLIENT_PIN_DIR, "CONFIG", Map::Array)?;
    let mut map: Array<_, Config> = (&mut m).try_into()?;
    let mut c = map.get(&CONFIG_KEY, 0)?;
    f(&mut c);
    map.set(CONFIG_KEY, c, 0)?;
    Ok(())
}

/// Replaces the whole set rather than applying a delta, so a dropped update cannot leave the two
/// sides disagreeing indefinitely.
pub fn replace_listeners(ports: &[u16]) -> Result<()> {
    let mut m = open_pinned(CLIENT_PIN_DIR, "DESKTOP_PORTS", Map::HashMap)?;
    let mut map: HashMap<_, u16, u8> = (&mut m).try_into()?;
    let existing: Vec<u16> = map.keys().filter_map(|k| k.ok()).collect();
    for k in existing {
        if !ports.contains(&k) {
            let _ = map.remove(&k);
        }
    }
    for p in ports {
        map.insert(p, 1, 0)?;
    }
    Ok(())
}

pub fn clear_listeners() -> Result<()> {
    replace_listeners(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_conversion_is_network_byte_order() {
        assert_eq!(
            v4_be(Ipv4Addr::new(127, 0, 0, 1)),
            u32::from_be_bytes([127, 0, 0, 1]).to_be()
        );
        assert_eq!(v4_be(Ipv4Addr::new(198, 18, 0, 2)).to_le_bytes()[0], 198);
    }

    #[test]
    fn v6_conversion_splits_into_four_network_order_words() {
        let addr: std::net::Ipv6Addr = "fd00:7::2".parse().unwrap();
        let w = v6_words(addr);
        assert_eq!(u32::from_be(w[0]), 0xfd000007);
        assert_eq!(u32::from_be(w[1]), 0);
        assert_eq!(u32::from_be(w[2]), 0);
        assert_eq!(u32::from_be(w[3]), 2);
    }

    /// The value `connect6` compares against for "no v6 target configured".
    #[test]
    fn the_unspecified_address_is_all_zero_words() {
        assert_eq!(v6_words(std::net::Ipv6Addr::UNSPECIFIED), [0; 4]);
        assert_ne!(v6_words(std::net::Ipv6Addr::LOCALHOST), [0; 4]);
    }

    #[test]
    fn the_two_pin_directories_are_distinct() {
        assert_ne!(CLIENT_PIN_DIR, SERVER_PIN_DIR);
        assert_ne!(CLIENT_READY_FILE, SERVER_READY_FILE);
    }

    /// Every program the client attaches must exist in the object, or `attach` fails at runtime
    /// with a name nobody can grep for.
    #[test]
    fn every_client_program_is_present_in_the_embedded_object() {
        let obj = aya_obj::Object::parse(OBJECT).expect("the embedded object parses");
        for name in CLIENT_PROGRAMS {
            assert!(
                obj.programs.contains_key(*name),
                "{name} is missing from the object"
            );
        }
    }

    #[test]
    fn every_server_program_is_present_in_the_embedded_object() {
        let obj = aya_obj::Object::parse(OBJECT).expect("the embedded object parses");
        for name in SERVER_PROGRAMS {
            assert!(
                obj.programs.contains_key(*name),
                "{name} is missing from the object"
            );
        }
    }

    #[test]
    fn every_map_the_daemons_open_is_present_in_the_embedded_object() {
        let obj = aya_obj::Object::parse(OBJECT).expect("the embedded object parses");
        for name in [
            "CONFIG",
            "COUNTERS",
            "DESKTOP_PORTS",
            "SLEEVE_CONFIG",
            "TC_COUNTERS",
        ] {
            assert!(obj.maps.contains_key(name), "{name} is missing");
        }
    }

    /// The failure this guards against is intermittent and its error message points nowhere useful,
    /// so it is asserted rather than assumed on every build.
    #[test]
    fn the_embedded_object_is_aligned() {
        assert_object_aligned().expect("aligned");
    }
}
