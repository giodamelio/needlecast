//! Packet and address predicates shared by the BPF programs and userspace.
//!
//! Outside the BPF crate because that one only builds for `bpfel-unknown-none` and cannot run a
//! test — and these are the parts most worth testing. The fragment test and the IPv4-mapped
//! detection each have a wrong answer that corrupts only large or only dual-stack traffic.

/// `127.0.0.1` in network byte order.
pub const LOOPBACK_V4: u32 = 0x7f00_0001u32.to_be();

/// `::1` as four network-byte-order words.
pub const LOOPBACK_V6: [u32; 4] = [0, 0, 0, 1u32.to_be()];

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;

/// Offset of the ethertype within an Ethernet header, and the header's own length.
pub const ETH_TYPE_OFF: usize = 12;
pub const ETH_HDR_LEN: usize = 14;

/// Byte offsets within an IPv4 header.
pub const IPV4_FRAG_OFF: usize = 6;
pub const IPV4_PROTO_OFF: usize = 9;
pub const IPV4_CSUM_OFF: usize = 10;
pub const IPV4_SADDR_OFF: usize = 12;
pub const IPV4_DADDR_OFF: usize = 16;
pub const IPV4_MIN_HDR: usize = 20;

/// Byte offsets within the L4 header, from its start.
pub const L4_SPORT_OFF: usize = 0;
pub const L4_DPORT_OFF: usize = 2;
pub const TCP_CSUM_OFF: usize = 16;
pub const UDP_CSUM_OFF: usize = 6;

#[inline(always)]
pub fn is_loopback_v4(addr_be: u32) -> bool {
    u32::from_be(addr_be) >> 24 == 127
}

#[inline(always)]
pub fn is_loopback_v6(w: &[u32; 4]) -> bool {
    w[0] == 0 && w[1] == 0 && w[2] == 0 && u32::from_be(w[3]) == 1
}

/// `Some(v4)` for an IPv4-mapped address such as `::ffff:127.0.0.1` — what a dual-stack socket
/// sees for `localhost`. Answered by the v4 stack, so it needs the v4 lookup and the v4 target.
#[inline(always)]
pub fn mapped_v4(w: &[u32; 4]) -> Option<u32> {
    if w[0] == 0 && w[1] == 0 && u32::from_be(w[2]) == 0xffff {
        Some(w[3])
    } else {
        None
    }
}

/// Inclusive on both ends.
#[inline(always)]
pub fn port_in_range(port: u16, lo: u16, hi: u16) -> bool {
    port >= lo && port <= hi
}

/// tc ingress runs before reassembly, so an oversized datagram arrives as several fragments and
/// only the first carries an L4 header — no port to check, no L4 checksum to fix on the rest.
/// Getting this backwards corrupts large datagrams while small ones keep working perfectly.
#[inline(always)]
pub fn is_first_fragment(frag_off_be: u16) -> bool {
    u16::from_be(frag_off_be) & 0x1fff == 0
}

/// Options make this variable, so the L4 header is not reliably 20 bytes in.
#[inline(always)]
pub fn ihl_bytes(version_ihl: u8) -> usize {
    ((version_ihl & 0x0f) as usize) * 4
}

#[inline(always)]
pub fn ip_version(version_ihl: u8) -> u8 {
    version_ihl >> 4
}

/// Offset within the L4 header, for protocols whose checksum covers a pseudo-header. `None` means
/// an address rewrite needs no L4 fixup.
#[inline(always)]
pub fn l4_csum_offset(proto: u8) -> Option<usize> {
    match proto {
        IPPROTO_TCP => Some(TCP_CSUM_OFF),
        IPPROTO_UDP => Some(UDP_CSUM_OFF),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d]).to_be()
    }

    #[test]
    fn loopback_v4_covers_the_whole_slash_eight() {
        assert!(is_loopback_v4(v4(127, 0, 0, 1)));
        assert!(is_loopback_v4(v4(127, 71, 0, 1)));
        assert!(is_loopback_v4(v4(127, 255, 255, 255)));
        assert!(!is_loopback_v4(v4(126, 255, 255, 255)));
        assert!(!is_loopback_v4(v4(128, 0, 0, 1)));
        assert!(!is_loopback_v4(v4(10, 7, 0, 2)));
        assert!(!is_loopback_v4(v4(198, 18, 0, 1)));
    }

    #[test]
    fn loopback_v4_constant_matches_the_predicate() {
        assert_eq!(LOOPBACK_V4, v4(127, 0, 0, 1));
        assert!(is_loopback_v4(LOOPBACK_V4));
    }

    #[test]
    fn loopback_v6_is_exactly_one() {
        assert!(is_loopback_v6(&LOOPBACK_V6));
        assert!(!is_loopback_v6(&[0, 0, 0, 0]));
        assert!(!is_loopback_v6(&[0, 0, 0, 2u32.to_be()]));
        assert!(!is_loopback_v6(&[
            0xfd000007u32.to_be(),
            0,
            0,
            2u32.to_be()
        ]));
    }

    #[test]
    fn mapped_v4_detects_the_ffff_prefix_and_nothing_else() {
        let mapped = [0, 0, 0xffffu32.to_be(), v4(127, 0, 0, 1)];
        assert_eq!(mapped_v4(&mapped), Some(v4(127, 0, 0, 1)));

        assert_eq!(mapped_v4(&LOOPBACK_V6), None);
        assert_eq!(mapped_v4(&[0, 0, 0, v4(127, 0, 0, 1)]), None);
        assert_eq!(mapped_v4(&[0, 0, 0xfffeu32.to_be(), 1]), None);
    }

    #[test]
    fn a_mapped_loopback_address_reads_as_loopback_through_its_v4_half() {
        let mapped = [0, 0, 0xffffu32.to_be(), v4(127, 0, 0, 1)];
        let inner = mapped_v4(&mapped).expect("mapped");
        assert!(is_loopback_v4(inner));
        // Or both paths would fire.
        assert!(!is_loopback_v6(&mapped));
    }

    #[test]
    fn port_range_is_inclusive_at_both_ends() {
        assert!(port_in_range(8000, 8000, 8999));
        assert!(port_in_range(8999, 8000, 8999));
        assert!(port_in_range(8080, 8000, 8999));
        assert!(!port_in_range(7999, 8000, 8999));
        assert!(!port_in_range(9000, 8000, 8999));
        assert!(port_in_range(8080, 8080, 8080));
        assert!(!port_in_range(8081, 8080, 8080));
    }

    #[test]
    fn first_fragment_test_ignores_the_flag_bits() {
        assert!(is_first_fragment(0u16.to_be()), "unfragmented");
        assert!(is_first_fragment(0x4000u16.to_be()), "Don't Fragment");
        assert!(
            is_first_fragment(0x2000u16.to_be()),
            "More Fragments, offset 0"
        );
        assert!(
            !is_first_fragment(0x2000u16.wrapping_add(185).to_be()),
            "offset 185, More Fragments"
        );
        assert!(!is_first_fragment(555u16.to_be()), "last fragment");
    }

    #[test]
    fn ihl_and_version_split_the_first_byte() {
        assert_eq!(ip_version(0x45), 4);
        assert_eq!(ihl_bytes(0x45), 20);
        assert_eq!(ihl_bytes(0x4f), 60, "15 words of options");
        assert_eq!(ip_version(0x60), 6);
        assert!(
            ihl_bytes(0x44) < IPV4_MIN_HDR,
            "the parser must reject this"
        );
    }

    #[test]
    fn l4_csum_offset_is_none_for_protocols_with_no_pseudo_header_checksum() {
        assert_eq!(l4_csum_offset(IPPROTO_TCP), Some(TCP_CSUM_OFF));
        assert_eq!(l4_csum_offset(IPPROTO_UDP), Some(UDP_CSUM_OFF));
        assert_eq!(l4_csum_offset(1), None, "ICMP");
        assert_eq!(l4_csum_offset(47), None, "GRE");
        assert_eq!(l4_csum_offset(50), None);
    }
}
