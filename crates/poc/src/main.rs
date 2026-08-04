mod control;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap, Map, MapData};
use aya::programs::tc::{SchedClassifierLink, TcAttachType};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier};
use aya::{Ebpf, EbpfLoader};
use clap::{Parser, Subcommand};
use needlecast_common::proto::DEFAULT_CONTROL_PORT;
use needlecast_common::{
    counter_slot, ev, mode, prog, tc, tc_counter_slot, tcev, Config, SleeveConfig, CONFIG_KEY,
    COUNTER_SLOTS, EV_NAMES, PROG_NAMES, TCEV_NAMES, TC_PROG_NAMES,
};

/// Plain `include_bytes!` yields alignment 1, but the `object` crate parses the ELF header
/// zero-copy and needs it aligned. Whether that happens to work depends on where the linker put
/// the array, so it fails intermittently across rebuilds.
const OBJECT: &[u8] = aya::include_bytes_aligned!(env!("NEEDLECAST_EBPF_OBJ"));

/// What `include_bytes_aligned!` guarantees.
const OBJECT_ALIGN: usize = 32;

const PIN_DIR: &str = "/sys/fs/bpf/needlecast";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const READY_FILE: &str = "/run/needlecast-poc.ready";
const SLEEVE_PIN_DIR: &str = "/sys/fs/bpf/needlecast-sleeve";
const SLEEVE_READY_FILE: &str = "/run/needlecast-sleeve.ready";

const PROGRAMS: &[&str] = &[
    "connect4",
    "connect6",
    "getpeername4",
    "getpeername6",
    "sendmsg4",
    "sendmsg6",
    "recvmsg4",
    "recvmsg6",
];

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum SleeveMode {
    RungA,
    RungB,
}

impl SleeveMode {
    fn as_u8(self) -> u8 {
        match self {
            SleeveMode::RungA => mode::RUNG_A,
            SleeveMode::RungB => mode::RUNG_B,
        }
    }
}

#[derive(Parser)]
#[command(about = "needlecast proof of concept")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load, attach, configure, and hold the links until killed.
    Run {
        #[arg(long, default_value = "10.7.0.2")]
        target_v4: Ipv4Addr,
        #[arg(long, default_value = "fd00:7::2")]
        target_v6: Ipv6Addr,
        #[arg(long, default_value_t = 8000)]
        port_lo: u16,
        #[arg(long, default_value_t = 8999)]
        port_hi: u16,
        /// Skip the netns cookie guard, so the programs act in every namespace.
        #[arg(long)]
        no_netns_guard: bool,
        /// Require a port to be present in DESKTOP_PORTS before rewriting.
        #[arg(long)]
        use_listener_map: bool,
        /// Also load the isolated bpf_setsockopt(TCP_SYNCNT) probe program.
        #[arg(long)]
        syncnt_probe: bool,
        /// Desktop control address. Given, the enabled flag follows the control connection and the
        /// listener set is mirrored into BPF. Absent, the flag is set once at startup and left.
        #[arg(long)]
        control: Option<Ipv4Addr>,
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
        /// TCP_SYNCNT for rewritten sockets. Caps the hang when the desktop vanishes between
        /// heartbeats. Zero leaves the system default.
        #[arg(long, default_value_t = 2)]
        syncnt: u8,
    },
    /// Try loading and attaching only the setsockopt probe. Exits non-zero if the verifier
    /// rejected it.
    ProbeSyncnt,
    /// Print every non-zero counter as `program.event=count`.
    Counters,
    /// Print the loaded configuration.
    ShowConfig,
    /// Flip the enabled flag without restarting the loader.
    SetEnabled { value: u8 },
    /// Populate DESKTOP_PORTS.
    Advertise { ports: Vec<u16> },
    /// Remove entries from DESKTOP_PORTS.
    Withdraw { ports: Vec<u16> },
    /// Desktop side: attach the tc datapath to a transport interface and hold it until killed.
    Sleeve {
        /// Transport interface: an ethernet link in the Phase 3 harness, `wg0` in production.
        #[arg(long)]
        iface: String,
        /// This machine's address on that link.
        #[arg(long)]
        transport_v4: Ipv4Addr,
        /// The laptop's address on that link.
        #[arg(long)]
        transport_peer_v4: Ipv4Addr,
        /// Where inbound packets are delivered.
        #[arg(long, default_value = "127.0.0.1")]
        local_v4: Ipv4Addr,
        #[arg(long, default_value_t = 8000)]
        port_lo: u16,
        #[arg(long, default_value_t = 8999)]
        port_hi: u16,
        /// Serve the control plane on the transport address at this port.
        #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
        control_port: u16,
        /// Do not serve the control plane at all.
        #[arg(long)]
        no_control: bool,
        /// rung-a: the server sees the laptop's tunnel address as its peer.
        /// rung-b: the server is told 127.0.0.1, so it cannot distinguish the connection from a
        /// local one.
        #[arg(long, default_value = "rung-b")]
        mode: SleeveMode,
    },
    /// Print every non-zero tc counter as `program.event=count`.
    TcCounters,
    /// Print the ports this machine is serving, as the control plane would publish them.
    Listeners,
    /// Report the current network namespace cookie.
    NetnsCookie,
    /// Parse an object without touching the kernel. Defaults to the embedded one. Unprivileged.
    VerifyObject { path: Option<PathBuf> },
    /// Prove the embedded object is aligned, and that misalignment is what breaks the parser.
    /// Unprivileged. Exits non-zero if either half of that does not hold.
    AlignmentCheck,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            target_v4,
            target_v6,
            port_lo,
            port_hi,
            no_netns_guard,
            use_listener_map,
            syncnt_probe,
            control,
            control_port,
            syncnt,
        } => run(RunArgs {
            target_v4,
            target_v6,
            port_lo,
            port_hi,
            no_netns_guard,
            use_listener_map,
            syncnt_probe,
            control,
            control_port,
            syncnt,
        }),
        Command::ProbeSyncnt => probe_syncnt(),
        Command::Counters => counters(),
        Command::ShowConfig => show_config(),
        Command::SetEnabled { value } => set_enabled(value),
        Command::Advertise { ports } => advertise(&ports, true),
        Command::Withdraw { ports } => advertise(&ports, false),
        Command::VerifyObject { path } => {
            let bytes = match &path {
                Some(p) => std::fs::read(p)?,
                None => OBJECT.to_vec(),
            };
            println!("bytes={}", bytes.len());
            let obj = aya_obj::Object::parse(&bytes).context("parsing object")?;
            let mut names: Vec<_> = obj.programs.keys().cloned().collect();
            names.sort();
            for n in names {
                println!("program {n}");
            }
            let mut maps: Vec<_> = obj.maps.keys().cloned().collect();
            maps.sort();
            for m in maps {
                println!("map {m}");
            }
            Ok(())
        }
        Command::Sleeve {
            iface,
            transport_v4,
            transport_peer_v4,
            local_v4,
            port_lo,
            port_hi,
            control_port,
            no_control,
            mode,
        } => sleeve(SleeveArgs {
            iface,
            transport_v4,
            transport_peer_v4,
            local_v4,
            port_lo,
            port_hi,
            control_port,
            no_control,
            mode,
        }),
        Command::TcCounters => tc_counters(),
        Command::Listeners => {
            for p in control::local_listeners()? {
                println!("{p}");
            }
            Ok(())
        }
        Command::AlignmentCheck => alignment_check(),
        Command::NetnsCookie => {
            println!("{}", netns_cookie()?);
            Ok(())
        }
    }
}

/// `SO_NETNS_COOKIE` on any socket returns the cookie of the namespace it was created in, which is
/// what `bpf_get_netns_cookie` reports from inside the program.
fn netns_cookie() -> Result<u64> {
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

fn open_pinned(name: &str, wrap: fn(MapData) -> Map) -> Result<Map> {
    open_pinned_in(PIN_DIR, name, wrap)
}

fn open_pinned_in(dir: &str, name: &str, wrap: fn(MapData) -> Map) -> Result<Map> {
    let path = Path::new(dir).join(name);
    let data = MapData::from_pin(&path)
        .with_context(|| format!("opening pinned map {}", path.display()))?;
    Ok(wrap(data))
}

struct RunArgs {
    target_v4: Ipv4Addr,
    target_v6: Ipv6Addr,
    port_lo: u16,
    port_hi: u16,
    no_netns_guard: bool,
    use_listener_map: bool,
    syncnt_probe: bool,
    control: Option<Ipv4Addr>,
    control_port: u16,
    syncnt: u8,
}

fn run(a: RunArgs) -> Result<()> {
    let RunArgs {
        target_v4,
        target_v6,
        port_lo,
        port_hi,
        no_netns_guard,
        use_listener_map,
        syncnt_probe,
        control,
        control_port,
        syncnt,
    } = a;
    if port_lo > port_hi {
        bail!("--port-lo must not exceed --port-hi");
    }
    // Stale pins from a previous run would silently carry old counters and config forward.
    if Path::new(PIN_DIR).exists() {
        std::fs::remove_dir_all(PIN_DIR).context("clearing stale pin directory")?;
    }
    std::fs::create_dir_all(PIN_DIR).context("creating pin directory")?;
    let _ = std::fs::remove_file(READY_FILE);

    let mut ebpf = load_object()?;

    let cgroup =
        std::fs::File::open(CGROUP_ROOT).with_context(|| format!("opening {CGROUP_ROOT}"))?;

    let mut attached = Vec::new();
    for name in PROGRAMS {
        attach(&mut ebpf, name, &cgroup).with_context(|| format!("attaching {name}"))?;
        attached.push(*name);
    }
    if syncnt_probe {
        match attach(&mut ebpf, "connect4_syncnt_probe", &cgroup) {
            Ok(()) => attached.push("connect4_syncnt_probe"),
            Err(e) => log::warn!("connect4_syncnt_probe rejected: {e:#}"),
        }
    }

    let cookie = if no_netns_guard { 0 } else { netns_cookie()? };
    let config = Config {
        netns_cookie: cookie,
        target_v4: u32::from(target_v4).to_be(),
        target_v6: v6_words(target_v6),
        port_lo,
        port_hi,
        // With a control plane, nothing is enabled until it says the desktop is there.
        enabled: u8::from(control.is_none()),
        use_listener_map: u8::from(use_listener_map || control.is_some()),
        syncnt,
        _pad: 0,
    };

    let mut cfg_map: Array<_, Config> = ebpf
        .map_mut("CONFIG")
        .ok_or_else(|| anyhow!("CONFIG map missing"))?
        .try_into()?;
    cfg_map.set(CONFIG_KEY, config, 0)?;

    log::info!(
        "attached {} programs, netns cookie {cookie}, ports {port_lo}-{port_hi}, target {target_v4} / {target_v6}",
        attached.len()
    );
    // Written only after every attach and the config write succeeded, so tests can wait on real
    // readiness instead of on the map pins, which appear during load.
    std::fs::write(READY_FILE, format!("{}\n", attached.join(" ")))?;
    println!("ready");

    match control {
        Some(addr) => control_loop(SocketAddr::from((addr, control_port))),
        // The links live in `ebpf`; dropping it, or dying, detaches everything.
        None => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
    }
}

/// The ordering here is the only subtle part of the control plane: on any error the enabled flag is
/// cleared *before* anything else, so there is never a window where the programs rewrite toward a
/// desktop that is known to be gone.
fn control_loop(addr: SocketAddr) -> ! {
    let mut backoff = std::time::Duration::from_millis(200);
    loop {
        match session(addr) {
            Ok(()) => log::info!("control connection closed cleanly"),
            Err(e) => log::info!("control connection failed: {e:#}"),
        }
        if let Err(e) = set_enabled(0).and_then(|()| clear_listeners()) {
            log::error!("failed to disable after losing the control connection: {e:#}");
        }
        std::thread::sleep(backoff);
        backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
    }
}

fn session(addr: SocketAddr) -> Result<()> {
    use needlecast_common::proto::{wire, Msg};

    let s = control::dial(addr)?;
    log::info!(
        "control connection up, desktop serves {}-{}",
        s.port_lo,
        s.port_hi
    );
    let mut stream = s.stream;
    let mut reader = stream.try_clone()?;

    // Deliberately not enabled yet: wait for the first listener snapshot, so the very first
    // connection after coming up is decided on real information rather than an empty map.
    let mut ready = false;
    let mut last_ping = std::time::Instant::now();
    let mut last_heard = std::time::Instant::now();
    loop {
        match wire::read(&mut reader) {
            Ok(msg) => {
                last_heard = std::time::Instant::now();
                match msg {
                    Msg::Listeners { ports } => {
                        replace_listeners(&ports)?;
                        if !ready {
                            set_enabled(1)?;
                            ready = true;
                        }
                        log::info!("desktop serves {} ports in range", ports.len());
                    }
                    Msg::Goodbye => anyhow::bail!("desktop said goodbye"),
                    _ => {}
                }
            }
            Err(e) if control::is_idle(&e) => {}
            Err(e) => return Err(e.into()),
        }

        // On its own timer, not gated on having received something — otherwise two idle peers
        // deadlock and every connection dies at the liveness timeout.
        if last_ping.elapsed() >= control::PING_INTERVAL {
            wire::write(&mut stream, &Msg::Ping)?;
            last_ping = std::time::Instant::now();
        }
        if last_heard.elapsed() >= control::LIVENESS_TIMEOUT {
            anyhow::bail!("no reply within {:?}", control::LIVENESS_TIMEOUT);
        }
    }
}

fn replace_listeners(ports: &[u16]) -> Result<()> {
    let mut m = open_pinned("DESKTOP_PORTS", Map::HashMap)?;
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

fn clear_listeners() -> Result<()> {
    let mut m = open_pinned("DESKTOP_PORTS", Map::HashMap)?;
    let mut map: HashMap<_, u16, u8> = (&mut m).try_into()?;
    let existing: Vec<u16> = map.keys().filter_map(|k| k.ok()).collect();
    for k in existing {
        let _ = map.remove(&k);
    }
    Ok(())
}

/// Alignment of the embedded object is guaranteed by `include_bytes_aligned!`, but the failure it
/// prevents is intermittent and its error message points nowhere useful, so check it explicitly
/// rather than letting a regression come back as a confusing ELF parse error on one build in three.
fn assert_object_aligned() -> Result<()> {
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

/// Demonstrates both halves of the claim: the embedded object parses, and the same bytes at a
/// deliberately odd address do not. Without the second half, "we fixed it with alignment" is a
/// story rather than a finding.
fn alignment_check() -> Result<()> {
    let addr = OBJECT.as_ptr() as usize;
    println!("address={addr:#x}");
    println!("align_{OBJECT_ALIGN}_offset={}", addr % OBJECT_ALIGN);
    println!("align_8_offset={}", addr % 8);

    assert_object_aligned()?;
    aya_obj::Object::parse(OBJECT).context("aligned parse should succeed")?;
    println!("aligned_parse=ok");

    // A Vec's buffer is at least 8-aligned, so slicing one byte in is reliably odd.
    let mut shifted = vec![0u8; OBJECT.len() + 1];
    shifted[1..].copy_from_slice(OBJECT);
    let misaligned = &shifted[1..];
    println!(
        "misaligned_align_8_offset={}",
        misaligned.as_ptr() as usize % 8
    );
    match aya_obj::Object::parse(misaligned) {
        Ok(_) => {
            println!("misaligned_parse=ok");
            bail!(
                "a misaligned slice parsed fine, so alignment is not what caused the \
                 intermittent failure — the real cause is still unidentified"
            );
        }
        Err(e) => {
            println!("misaligned_parse=failed");
            println!("misaligned_error={e:?}");
        }
    }
    Ok(())
}

/// `EbpfError`'s inner `object::read::Error` is not exposed as a `source`, so the Display chain
/// stops at "error parsing ELF data". Debug is the only way to see what actually went wrong.
fn load_object() -> Result<Ebpf> {
    assert_object_aligned()?;
    EbpfLoader::new()
        .map_pin_path(PIN_DIR)
        .load(OBJECT)
        .map_err(|e| anyhow!("loading BPF object: {e:?}"))
}

fn attach(ebpf: &mut Ebpf, name: &str, cgroup: &std::fs::File) -> Result<()> {
    let program: &mut CgroupSockAddr = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("program {name} not found in object"))?
        .try_into()?;
    program.load()?;
    program.attach(cgroup, CgroupAttachMode::Single)?;
    Ok(())
}

/// Loading this program on its own is the whole test: if the verifier rejects `bpf_setsockopt` in
/// `cgroup_sock_addr` it fails here, rather than taking the other eight programs down with it.
fn probe_syncnt() -> Result<()> {
    // Its own pin directory so the probe can run before, during, or after the loader.
    let dir = format!("{PIN_DIR}-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).context("creating probe pin directory")?;
    assert_object_aligned()?;
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(&dir)
        .load(OBJECT)
        .map_err(|e| anyhow!("loading BPF object: {e:?}"))?;
    let program: &mut CgroupSockAddr = ebpf
        .program_mut("connect4_syncnt_probe")
        .ok_or_else(|| anyhow!("probe program missing"))?
        .try_into()?;
    if let Err(e) = program.load() {
        println!("verifier: rejected");
        println!("{e:#}");
        std::process::exit(1);
    }
    println!("verifier: accepted");
    let cgroup = std::fs::File::open(CGROUP_ROOT)?;
    match program.attach(&cgroup, CgroupAttachMode::Single) {
        Ok(_) => println!("attach: ok"),
        Err(e) => {
            println!("attach: failed");
            println!("{e:#}");
            std::process::exit(2);
        }
    }
    Ok(())
}

/// 1 is `ARPHRD_ETHER`, so the IP header sits after a 14-byte link header. A WireGuard interface
/// reports `ARPHRD_NONE` and has no link header at all. Reading it beats guessing, and it is the
/// single value that lets one program serve both Rung A and the WireGuard datapath.
fn l3_offset_for(iface: &str) -> Result<u16> {
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

struct SleeveArgs {
    iface: String,
    transport_v4: Ipv4Addr,
    transport_peer_v4: Ipv4Addr,
    local_v4: Ipv4Addr,
    port_lo: u16,
    port_hi: u16,
    control_port: u16,
    no_control: bool,
    mode: SleeveMode,
}

fn attach_tc(
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

fn sleeve(a: SleeveArgs) -> Result<()> {
    if Path::new(SLEEVE_PIN_DIR).exists() {
        std::fs::remove_dir_all(SLEEVE_PIN_DIR).context("clearing stale sleeve pin directory")?;
    }
    std::fs::create_dir_all(SLEEVE_PIN_DIR).context("creating sleeve pin directory")?;
    let _ = std::fs::remove_file(SLEEVE_READY_FILE);

    let l3_offset = l3_offset_for(&a.iface)?;
    assert_object_aligned()?;
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(SLEEVE_PIN_DIR)
        .load(OBJECT)
        .map_err(|e| anyhow!("loading BPF object: {e:?}"))?;

    // clsact must exist before either direction can attach; it may already be there.
    let _ = aya::programs::tc::qdisc_add_clsact(&a.iface);

    let mut links: Vec<SchedClassifierLink> = Vec::new();
    let mut attached = vec!["tc_ingress", "tc_egress"];
    attach_tc(
        &mut ebpf,
        "tc_ingress",
        &a.iface,
        TcAttachType::Ingress,
        &mut links,
    )?;
    attach_tc(
        &mut ebpf,
        "tc_egress",
        &a.iface,
        TcAttachType::Egress,
        &mut links,
    )?;

    // Nothing outside needlecast's own interface: no route, nothing attached to lo.
    let mut cgroup_holder = None;
    if matches!(a.mode, SleeveMode::RungB) {
        let cgroup =
            std::fs::File::open(CGROUP_ROOT).with_context(|| format!("opening {CGROUP_ROOT}"))?;
        let program: &mut CgroupSockAddr = ebpf
            .program_mut("sleeve_getpeername4")
            .ok_or_else(|| anyhow!("sleeve_getpeername4 not found"))?
            .try_into()?;
        program.load().context("loading sleeve_getpeername4")?;
        program
            .attach(&cgroup, CgroupAttachMode::Single)
            .context("attaching sleeve_getpeername4")?;
        attached.push("sleeve_getpeername4");
        cgroup_holder = Some(cgroup);
    }
    let _cgroup_holder = cgroup_holder;

    let config = SleeveConfig {
        transport_v4: u32::from(a.transport_v4).to_be(),
        transport_peer_v4: u32::from(a.transport_peer_v4).to_be(),
        local_v4: u32::from(a.local_v4).to_be(),
        transport_v6: [0; 4],
        local_v6: [0; 4],
        port_lo: a.port_lo,
        port_hi: a.port_hi,
        l3_offset,
        mode: a.mode.as_u8(),
        enabled: 1,
    };
    let mut cfg_map: aya::maps::Array<_, SleeveConfig> = ebpf
        .map_mut("SLEEVE_CONFIG")
        .ok_or_else(|| anyhow!("SLEEVE_CONFIG map missing"))?
        .try_into()?;
    cfg_map.set(0, config, 0)?;

    std::fs::write(
        SLEEVE_READY_FILE,
        format!(
            "iface={} l3_offset={l3_offset} mode={:?} attached={}\n",
            a.iface,
            a.mode,
            attached.join(",")
        ),
    )?;
    log::info!("sleeve attached: {attached:?}, mode {:?}", a.mode);
    println!("ready");

    if a.no_control {
        // Links are held here; dropping them, or dying, detaches every direction.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
    control::serve(a.transport_v4, a.control_port, a.port_lo, a.port_hi)?;
    Ok(())
}

fn tc_counters() -> Result<()> {
    let m = open_pinned_in(SLEEVE_PIN_DIR, "TC_COUNTERS", Map::Array)?;
    let map: Array<_, u64> = (&m).try_into()?;
    for p in 0..tc::COUNT {
        for e in 0..tcev::COUNT {
            let v = map.get(&tc_counter_slot(p, e), 0).unwrap_or(0);
            if v != 0 {
                println!(
                    "{}.{}={}",
                    TC_PROG_NAMES[p as usize], TCEV_NAMES[e as usize], v
                );
            }
        }
    }
    Ok(())
}

fn counters() -> Result<()> {
    let m = open_pinned("COUNTERS", Map::Array)?;
    let map: Array<_, u64> = (&m).try_into()?;
    for p in 0..prog::COUNT {
        for e in 0..ev::COUNT {
            let v = map.get(&counter_slot(p, e), 0).unwrap_or(0);
            if v != 0 {
                println!("{}.{}={}", PROG_NAMES[p as usize], EV_NAMES[e as usize], v);
            }
        }
    }
    Ok(())
}

fn show_config() -> Result<()> {
    let m = open_pinned("CONFIG", Map::Array)?;
    let map: Array<_, Config> = (&m).try_into()?;
    let c = map.get(&CONFIG_KEY, 0)?;
    println!("enabled={}", c.enabled);
    println!("netns_cookie={}", c.netns_cookie);
    println!("port_lo={}", c.port_lo);
    println!("port_hi={}", c.port_hi);
    println!("use_listener_map={}", c.use_listener_map);
    println!("target_v4={}", Ipv4Addr::from(u32::from_be(c.target_v4)));
    Ok(())
}

fn set_enabled(value: u8) -> Result<()> {
    let mut m = open_pinned("CONFIG", Map::Array)?;
    let mut map: Array<_, Config> = (&mut m).try_into()?;
    let mut c = map.get(&CONFIG_KEY, 0)?;
    c.enabled = value;
    map.set(CONFIG_KEY, c, 0)?;
    Ok(())
}

fn advertise(ports: &[u16], present: bool) -> Result<()> {
    let mut m = open_pinned("DESKTOP_PORTS", Map::HashMap)?;
    let mut map: HashMap<_, u16, u8> = (&mut m).try_into()?;
    for p in ports {
        if present {
            map.insert(p, 1, 0)?;
        } else {
            map.remove(p)?;
        }
    }
    Ok(())
}

fn v6_words(addr: Ipv6Addr) -> [u32; 4] {
    let o = addr.octets();
    let mut w = [0u32; 4];
    for (i, word) in w.iter_mut().enumerate() {
        *word = u32::from_be_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]).to_be();
    }
    w
}

const _: () = assert!(COUNTER_SLOTS == prog::COUNT * ev::COUNT);
