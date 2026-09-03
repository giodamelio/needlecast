//! Loading, attaching, and reaching the pinned maps.
//!
//! Both halves keep their programs alive by holding the `bpf_link`s, so a crashed daemon reverts
//! the machine to stock rather than leaving it half-configured.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::tc::{SchedClassifierLink, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier};
use aya::{Ebpf, EbpfLoader};
use needlecast_common::{Config, CONFIG_KEY};

/// `include_bytes!` yields alignment 1, but `object` parses the ELF header zero-copy and needs it
/// aligned — so it fails depending on where the linker happened to put the array.
pub const OBJECT: &[u8] = aya::include_bytes_aligned!(env!("NEEDLECAST_EBPF_OBJ"));

pub const OBJECT_ALIGN: usize = 32;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
pub const RUN_DIR: &str = "/run/needlecast";
const PIN_ROOT: &str = "/sys/fs/bpf/needlecast";

/// Which end of the tunnel this process is, and everything that differs between the two. The paths
/// are derived rather than written twice, so a half can never half-exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    Client,
    Server,
}

impl Half {
    pub const fn as_str(self) -> &'static str {
        match self {
            Half::Client => "client",
            Half::Server => "server",
        }
    }

    pub fn pin_dir(self) -> String {
        format!("{PIN_ROOT}/{}", self.as_str())
    }

    pub fn ready_file(self) -> String {
        format!("{RUN_DIR}/{}.ready", self.as_str())
    }

    /// Named so `status` can ask whether they are still loaded — the only honest liveness signal.
    pub const fn programs(self) -> &'static [&'static str] {
        match self {
            Half::Client => &[
                "connect4",
                "connect6",
                "getpeername4",
                "getpeername6",
                "sendmsg4",
                "sendmsg6",
                "recvmsg4",
                "recvmsg6",
            ],
            Half::Server => &["tc_ingress", "tc_egress", "sleeve_getpeername4"],
        }
    }

    pub fn has_pins(self) -> bool {
        Path::new(&self.pin_dir()).exists()
    }

    /// Stale pins would silently carry old counters and config forward.
    pub fn reset_pins(self) -> Result<()> {
        let dir = self.pin_dir();
        if Path::new(&dir).exists() {
            std::fs::remove_dir_all(&dir)
                .with_context(|| format!("clearing stale pin directory {dir}"))?;
        }
        std::fs::create_dir_all(&dir).with_context(|| format!("creating pin directory {dir}"))
    }

    pub fn open_map(self, name: &str, wrap: fn(MapData) -> Map) -> Result<Map> {
        let path = Path::new(&self.pin_dir()).join(name);
        let data = MapData::from_pin(&path)
            .with_context(|| format!("opening pinned map {}", path.display()))?;
        Ok(wrap(data))
    }

    /// Written only once every attach succeeded, so waiting on it means waiting on real readiness —
    /// unlike the map pins, which appear during load and survive a crash.
    pub fn write_ready(self, contents: &str) -> Result<()> {
        std::fs::create_dir_all(RUN_DIR).with_context(|| format!("creating {RUN_DIR}"))?;
        let path = self.ready_file();
        std::fs::write(&path, contents).with_context(|| format!("writing {path}"))
    }

    pub fn clear_ready(self) {
        let _ = std::fs::remove_file(self.ready_file());
    }
}

/// Checked explicitly because the failure it prevents is intermittent and its error message points
/// nowhere useful.
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

/// `EbpfError`'s inner `object::read::Error` is not a `source`, so Display stops at "error parsing
/// ELF data" and `{:?}` is the only way to see the cause.
pub fn load_object(pin_dir: &str) -> Result<Ebpf> {
    assert_object_aligned()?;
    EbpfLoader::new()
        .map_pin_path(pin_dir)
        .load(OBJECT)
        .map_err(|e| anyhow!("loading BPF object: {e:?}"))
}

pub fn attach_cgroup(ebpf: &mut Ebpf, name: &str, cgroup: &std::fs::File) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("program {name} not found in object"))?
        .try_into()?;
    program.load()?;
    // `AllowMultiple` maps to BPF_F_ALLOW_MULTI, which `bpf_link_create` rejects with EINVAL.
    // `Single` is flags 0 and, despite the name, does not restrict us to one program.
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

/// `ARPHRD_ETHER` puts the IP header 14 bytes in; a WireGuard interface is `ARPHRD_NONE` and has
/// no link header at all. This one value is what lets a single program serve both device classes.
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

const TRACEFS: &str = "/sys/kernel/tracing/events/sock/inet_sock_set_state/format";

/// The offsets the listener feed reads, taken from the tracepoint's own `format` file.
///
/// Hardcoding them would work today on every kernel tested. It is still the wrong trade: the layout
/// is not ABI, and getting it wrong makes the feed go quiet rather than fail, which is the hardest
/// kind of bug to notice.
pub fn tracepoint_offsets() -> Result<needlecast_common::FeedConfig> {
    let text = std::fs::read_to_string(TRACEFS)
        .with_context(|| format!("reading {TRACEFS}; is tracefs mounted?"))?;
    Ok(needlecast_common::FeedConfig {
        oldstate_off: field_offset(&text, "oldstate")?,
        newstate_off: field_offset(&text, "newstate")?,
        sport_off: field_offset(&text, "sport")?,
        port_lo: 0,
        port_hi: 0,
    })
}

/// Lines look like `\tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;`.
fn field_offset(format: &str, name: &str) -> Result<u32> {
    for line in format.lines() {
        let Some((decl, rest)) = line.split_once(";") else {
            continue;
        };
        // Match the whole identifier, or `sport` would also match `dport`'s neighbour in a future
        // layout, and `state` would match both of the ones wanted here.
        if !decl
            .rsplit([' ', '\t', '*'])
            .next()
            .is_some_and(|last| last == name)
        {
            continue;
        }
        let Some(off) = rest.split("offset:").nth(1) else {
            continue;
        };
        let digits: String = off.chars().take_while(|c| c.is_ascii_digit()).collect();
        return digits
            .parse()
            .with_context(|| format!("parsing the offset of {name} from {line:?}"));
    }
    bail!("{TRACEFS} has no field named {name}")
}

/// Where the v6 datapath redirects an inbound packet. Read rather than assumed to be 1: that is
/// true on every kernel in practice, but a wrong ifindex would deliver traffic to another device.
pub fn loopback_ifindex() -> Result<u32> {
    let path = "/sys/class/net/lo/ifindex";
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    raw.trim().parse().context("parsing lo's ifindex")
}

/// Returns the same value `bpf_get_netns_cookie` reports from inside a program, which is what
/// makes the container guard implementable.
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

/// Matching `bpf_sock_addr::user_ip6`.
pub fn v6_words(addr: std::net::Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    let mut w = [0u32; 4];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]).to_be();
    }
    w
}

pub fn read_config() -> Result<Config> {
    let m = Half::Client.open_map("CONFIG", Map::Array)?;
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
    let mut m = Half::Client.open_map("CONFIG", Map::Array)?;
    let mut map: Array<_, Config> = (&mut m).try_into()?;
    let mut c = map.get(&CONFIG_KEY, 0)?;
    f(&mut c);
    map.set(CONFIG_KEY, c, 0)?;
    Ok(())
}

/// Whole set rather than a delta, so a dropped update cannot leave the two sides disagreeing.
pub fn replace_listeners(ports: &[u16]) -> Result<()> {
    let mut m = Half::Client.open_map("DESKTOP_PORTS", Map::HashMap)?;
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

    /// What `connect6` compares against for "no v6 target configured".
    #[test]
    fn the_unspecified_address_is_all_zero_words() {
        assert_eq!(v6_words(std::net::Ipv6Addr::UNSPECIFIED), [0; 4]);
        assert_ne!(v6_words(std::net::Ipv6Addr::LOCALHOST), [0; 4]);
    }

    /// The two halves never run on the same machine, but they do share a build, and a shared path
    /// would have one clobbering the other's pins on a machine running both for a test.
    #[test]
    fn the_two_halves_share_no_paths() {
        assert_ne!(Half::Client.pin_dir(), Half::Server.pin_dir());
        assert_ne!(Half::Client.ready_file(), Half::Server.ready_file());
        assert!(Half::Client.pin_dir().starts_with(PIN_ROOT));
        assert!(Half::Server.ready_file().starts_with(RUN_DIR));
    }

    #[test]
    fn every_program_each_half_attaches_is_present_in_the_embedded_object() {
        let obj = aya_obj::Object::parse(OBJECT).expect("the embedded object parses");
        for half in [Half::Client, Half::Server] {
            for name in half.programs() {
                assert!(
                    obj.programs.contains_key(*name),
                    "{name} is missing from the object"
                );
            }
        }
    }

    /// A program listed under both halves would be attached twice on a machine running both.
    #[test]
    fn the_halves_attach_disjoint_programs() {
        for name in Half::Client.programs() {
            assert!(!Half::Server.programs().contains(name), "{name}");
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

    #[test]
    fn the_embedded_object_is_aligned() {
        assert_object_aligned().expect("aligned");
    }

    /// A real `format` file, so the parser is tested against the shape it will actually meet.
    const SET_STATE_FORMAT: &str = "\
name: inet_sock_set_state
ID: 1234
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;
\tfield:int oldstate;\toffset:16;\tsize:4;\tsigned:1;
\tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;
\tfield:__u16 sport;\toffset:24;\tsize:2;\tsigned:0;
\tfield:__u16 dport;\toffset:26;\tsize:2;\tsigned:0;
\tfield:__u16 family;\toffset:28;\tsize:2;\tsigned:0;
\tfield:__u8 saddr[4];\toffset:32;\tsize:4;\tsigned:0;
";

    #[test]
    fn tracepoint_field_offsets_are_read_from_the_format() {
        assert_eq!(field_offset(SET_STATE_FORMAT, "oldstate").unwrap(), 16);
        assert_eq!(field_offset(SET_STATE_FORMAT, "newstate").unwrap(), 20);
        assert_eq!(field_offset(SET_STATE_FORMAT, "sport").unwrap(), 24);
        assert_eq!(field_offset(SET_STATE_FORMAT, "dport").unwrap(), 26);
    }

    /// `sport` and `dport` differ by one character, and `state` is a suffix of both the fields
    /// that matter. A substring match would silently pick whichever came first.
    #[test]
    fn a_field_name_matches_whole_or_not_at_all() {
        assert!(field_offset(SET_STATE_FORMAT, "state").is_err());
        assert!(field_offset(SET_STATE_FORMAT, "port").is_err());
        assert!(field_offset(SET_STATE_FORMAT, "addr").is_err());
        assert!(field_offset(SET_STATE_FORMAT, "nonesuch").is_err());
    }

    /// A pointer field's name abuts its `*`, so the split has to treat that as whitespace.
    #[test]
    fn a_pointer_field_is_still_found_by_name() {
        assert_eq!(field_offset(SET_STATE_FORMAT, "skaddr").unwrap(), 8);
    }

    #[test]
    fn a_missing_format_names_the_field_rather_than_panicking() {
        let err = field_offset("", "newstate").expect_err("no fields");
        assert!(err.to_string().contains("newstate"), "{err}");
    }
}
