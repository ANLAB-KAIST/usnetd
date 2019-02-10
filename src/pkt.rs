use libusnetd::{ClientMessageIp, WantMsg};

use byteorder::{ByteOrder, NetworkEndian};
use hashbrown::HashMap;
use std::str::FromStr;

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet,
};

#[derive(Debug, PartialEq, Clone)]
pub enum PacketInfo {
    Ipv4 {
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    },
    Arp,
    Eapol,
}
impl PacketInfo {
    pub fn is_arp(&self) -> bool {
        match self {
            PacketInfo::Arp => true,
            _ => false,
        }
    }
    pub fn is_eapol(&self) -> bool {
        match self {
            PacketInfo::Eapol => true,
            _ => false,
        }
    }
    pub fn is_dhcp_request(&self) -> bool {
        match self {
            PacketInfo::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
            } => {
                if *protocol == IpProtocol::Udp
                    && src_addr.is_unspecified()
                    && *src_port == Some(68)
                    && *dst_port == Some(67)
                    && dst_addr.as_bytes()[3] == 255
                {
                    true
                } else {
                    false
                }
            }
            PacketInfo::Arp | PacketInfo::Eapol => false,
        }
    }
    pub fn is_dhcp_answer(&self) -> bool {
        match self {
            PacketInfo::Ipv4 {
                src_addr: _,
                dst_addr: _,
                src_port,
                dst_port,
                protocol,
            } => {
                if *protocol == IpProtocol::Udp && *src_port == Some(67) && *dst_port == Some(68) {
                    true
                } else {
                    false
                }
            }
            PacketInfo::Arp | PacketInfo::Eapol => false,
        }
    }
    /// converts a sent-out packet to a match entry for answers (only of the other's specific (port,ip) pair)
    pub fn to_want(&self) -> Want {
        match self {
            PacketInfo::Arp | PacketInfo::Eapol => unreachable!("cannot add ARP/EAPOL"),
            PacketInfo::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
            } => Want {
                dst_addr: *src_addr,
                dst_port: *src_port,
                src_addr: Some(*dst_addr),
                src_port: *dst_port,
                protocol: u8::from(*protocol),
            },
        }
    }
    pub fn to_match_want_with_src(&self, with_src: bool) -> Want {
        match self {
            PacketInfo::Arp | PacketInfo::Eapol => unreachable!("cannot match ARP/EAPOL"),
            PacketInfo::Ipv4 {
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
            } => Want {
                dst_addr: *dst_addr,
                dst_port: *dst_port,
                src_addr: if with_src { Some(*src_addr) } else { None },
                src_port: if with_src { *src_port } else { None },
                protocol: u8::from(*protocol),
            },
        }
    }
    pub fn is_loopback(&self) -> bool {
        match self {
            PacketInfo::Arp | PacketInfo::Eapol => false,
            PacketInfo::Ipv4 {
                src_addr: _,
                dst_addr,
                src_port: _,
                dst_port: _,
                protocol: _,
            } => dst_addr.is_loopback(),
        }
    }
}

fn protocol_has_ports(protocol: IpProtocol) -> bool {
    protocol == IpProtocol::Tcp || protocol == IpProtocol::Udp
  || protocol == IpProtocol::from(0x21) // DCCP
  || protocol == IpProtocol::from(0x84) // SCTP
  || protocol == IpProtocol::from(0x88) // UDPLite
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct FragmentationKey {
    id: u16,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: u8,
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
}

impl FragmentationKey {
    fn new(frame: &EthernetFrame<&[u8]>, packet: &Ipv4Packet<&[u8]>) -> FragmentationKey {
        FragmentationKey {
            id: packet.ident(),
            src_ip: packet.src_addr(),
            dst_ip: packet.dst_addr(),
            protocol: u8::from(packet.protocol()),
            src_mac: frame.src_addr(),
            dst_mac: frame.dst_addr(),
        }
    }
}

pub fn extract_pkt_info(
    frame: &[u8],
    fragmentation_map: &mut HashMap<
        FragmentationKey,
        (PacketInfo, EthernetAddress, EthernetAddress),
    >,
) -> Option<(PacketInfo, EthernetAddress, EthernetAddress)> {
    let eth_frame = EthernetFrame::new_checked(frame).ok()?;
    match eth_frame.ethertype() {
        EthernetProtocol::Arp => {
            Some((PacketInfo::Arp, eth_frame.src_addr(), eth_frame.dst_addr()))
        }
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload()).ok()?;
            if ipv4_packet.frag_offset() > 0 {
                let key = FragmentationKey::new(&eth_frame, &ipv4_packet);
                trace!("looking up fragmentation info for {:?}", key);
                return fragmentation_map.get(&key).cloned();
            }
            let payload = ipv4_packet.payload();
            let (src_port, dst_port) =
                if protocol_has_ports(ipv4_packet.protocol()) && payload.len() > 4 {
                    (
                        Some(NetworkEndian::read_u16(&payload[0..2])),
                        Some(NetworkEndian::read_u16(&payload[2..4])),
                    )
                } else {
                    (None, None)
                };
            let ret = (
                PacketInfo::Ipv4 {
                    src_addr: ipv4_packet.src_addr(),
                    dst_addr: ipv4_packet.dst_addr(),
                    protocol: ipv4_packet.protocol(),
                    src_port: src_port,
                    dst_port: dst_port,
                },
                eth_frame.src_addr(),
                eth_frame.dst_addr(),
            );
            if !ipv4_packet.dont_frag() && ipv4_packet.more_frags() {
                let key = FragmentationKey::new(&eth_frame, &ipv4_packet);
                trace!("remembering fragmentation info for {:?}", key);
                let _ = fragmentation_map.insert(key, ret.clone());
            }
            Some(ret)
        }
        EthernetProtocol::Ipv6 => None,
        EthernetProtocol::Unknown(t) => {
            if t == 0x888e {
                Some((
                    PacketInfo::Eapol,
                    eth_frame.src_addr(),
                    eth_frame.dst_addr(),
                ))
            } else {
                None
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Want {
    pub dst_addr: Ipv4Address,
    pub dst_port: Option<u16>,
    pub src_addr: Option<Ipv4Address>,
    pub src_port: Option<u16>,
    pub protocol: u8,
}

impl Want {
    pub fn new_from_want_msg(want_msg: &WantMsg) -> Option<Want> {
        let WantMsg {
            dst_addr,
            dst_port,
            src_addr,
            src_port,
            protocol,
        } = want_msg;
        let dst_addr_ipv4 = match dst_addr {
            ClientMessageIp::Ipv4(ipstr) => Ipv4Address::from_str(&ipstr).ok(),
            _ => panic!("unimplemented"),
        }?;
        let src_addr_ipv4_opt = if let Some(s) = src_addr {
            match s {
                ClientMessageIp::Ipv4(ipstr) => Ipv4Address::from_str(&ipstr).ok(),
                _ => panic!("unimpl"),
            }
        } else {
            None
        };
        Some(Want {
            dst_addr: dst_addr_ipv4,
            dst_port: *dst_port,
            src_addr: src_addr_ipv4_opt,
            src_port: *src_port,
            protocol: *protocol,
        })
    }
}
