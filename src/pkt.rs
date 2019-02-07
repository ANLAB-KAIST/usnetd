use libusnetd::{ClientMessageIp, WantMsg};

use byteorder::{ByteOrder, NetworkEndian};

use std::str::FromStr;

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Address, Ipv4Packet,
};

#[derive(Debug)]
pub enum PacketInfo {
    Ipv4 {
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    },
    Arp,
}
impl PacketInfo {
    pub fn is_arp(&self) -> bool {
        match self {
            PacketInfo::Arp => true,
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
            PacketInfo::Arp => false,
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
            PacketInfo::Arp => false,
        }
    }
    /// converts a sent-out packet to a match entry for answers (only of the other's specific (port,ip) pair)
    pub fn to_want(&self) -> Want {
        match self {
            PacketInfo::Arp => unreachable!("cannot add Arp"),
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
            PacketInfo::Arp => unreachable!("cannot match Arp"),
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
            PacketInfo::Arp => false,
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

pub fn extract_pkt_info(frame: &[u8]) -> Option<(PacketInfo, EthernetAddress, EthernetAddress)> {
    let eth_frame = EthernetFrame::new_checked(frame).ok()?;
    match eth_frame.ethertype() {
        EthernetProtocol::Arp => {
            Some((PacketInfo::Arp, eth_frame.src_addr(), eth_frame.dst_addr()))
        }
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload()).ok()?;
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
            Some((
                PacketInfo::Ipv4 {
                    src_addr: ipv4_packet.src_addr(),
                    dst_addr: ipv4_packet.dst_addr(),
                    protocol: ipv4_packet.protocol(),
                    src_port: src_port,
                    dst_port: dst_port,
                },
                eth_frame.src_addr(),
                eth_frame.dst_addr(),
            ))
        }
        _ => None,
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
