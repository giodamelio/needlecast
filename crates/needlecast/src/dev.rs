//! Diagnostics. Pinned counter arrays indexed by `(program, event)` let a test assert on which
//! branch a program took, not merely on the observable outcome — which is the difference between
//! "the connection went local because a listener was found" and "because the port was out of
//! range". They have been a better debugging channel than `bpf_printk` throughout.

use std::path::PathBuf;

use anyhow::{Context, Result};
use aya::maps::{Array, Map};
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::EbpfLoader;
use needlecast_common::{all_counters, all_tc_counters};

use crate::bpf;

pub fn counters() -> Result<()> {
    let m = bpf::Half::Client.open_map("COUNTERS", Map::Array)?;
    let map: Array<_, u64> = (&m).try_into()?;
    for (p, e, slot) in all_counters() {
        let v = map.get(&slot, 0).unwrap_or(0);
        if v != 0 {
            println!("{}.{}={}", p.as_str(), e.as_str(), v);
        }
    }
    Ok(())
}

pub fn tc_counters() -> Result<()> {
    let m = bpf::Half::Server.open_map("TC_COUNTERS", Map::Array)?;
    let map: Array<_, u64> = (&m).try_into()?;
    for (p, e, slot) in all_tc_counters() {
        let v = map.get(&slot, 0).unwrap_or(0);
        if v != 0 {
            println!("{}.{}={}", p.as_str(), e.as_str(), v);
        }
    }
    Ok(())
}

pub fn show_config() -> Result<()> {
    let c = bpf::read_config()?;
    println!("enabled={}", c.enabled);
    println!("netns_cookie={}", c.netns_cookie);
    println!("port_lo={}", c.port_lo);
    println!("port_hi={}", c.port_hi);
    println!("use_listener_map={}", c.use_listener_map);
    println!(
        "target_v4={}",
        std::net::Ipv4Addr::from(u32::from_be(c.target_v4))
    );
    Ok(())
}

pub fn set_enabled(value: u8) -> Result<()> {
    bpf::set_enabled(value)
}

pub fn advertise(ports: &[u16], present: bool) -> Result<()> {
    use aya::maps::HashMap;
    let mut m = bpf::Half::Client.open_map("DESKTOP_PORTS", Map::HashMap)?;
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

pub fn listeners() -> Result<()> {
    for p in crate::control::local_listeners()? {
        println!("{p}");
    }
    Ok(())
}

pub fn netns_cookie() -> Result<()> {
    println!("{}", bpf::netns_cookie()?);
    Ok(())
}

pub fn verify_object(path: Option<PathBuf>) -> Result<()> {
    let bytes = match &path {
        Some(p) => std::fs::read(p)?,
        None => bpf::OBJECT.to_vec(),
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

/// Loading this program on its own is the whole test: if the verifier rejects `bpf_setsockopt` in
/// `cgroup_sock_addr` it fails here, rather than taking the other eight programs down with it.
pub fn probe_syncnt() -> Result<()> {
    // Its own pin directory so the probe can run before, during, or after the loader.
    let dir = format!("{}-probe", bpf::Half::Client.pin_dir());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).context("creating probe pin directory")?;
    bpf::assert_object_aligned()?;
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(&dir)
        .load(bpf::OBJECT)
        .map_err(|e| anyhow::anyhow!("loading BPF object: {e:?}"))?;
    let program: &mut CgroupSockAddr = ebpf
        .program_mut("connect4_syncnt_probe")
        .ok_or_else(|| anyhow::anyhow!("probe program missing"))?
        .try_into()?;
    if let Err(e) = program.load() {
        println!("verifier: rejected");
        println!("{e:#}");
        std::process::exit(1);
    }
    println!("verifier: accepted");
    let cgroup = std::fs::File::open(bpf::CGROUP_ROOT)?;
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
