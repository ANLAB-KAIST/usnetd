use devices::{EndpointDevice, ReceiveTokenImpl};
use pkt::{extract_pkt_info, PacketInfo, Want};
use EndpointOrControl;

use smoltcp::phy::PcapSink;
use smoltcp::phy::RxToken;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, Ipv4Address};
use smoltcp::Error;

use hashbrown::HashMap;

use std::path::PathBuf;

use std::cell::RefCell;
use std::rc::Rc;

/// an endpoint may have a different IP (or many) but usually shares one with the host kernel
#[derive(Debug)]
pub struct Endpoint {
    // could add MAC (more than one) if needed e.g. for host kernel's L2 bridge/VMs/containers?
    pub dev: EndpointDevice,
    pub for_nic: Option<Rc<RefCell<EndpointOrControl>>>,
    pub client_path: Option<PathBuf>,
    pub listening: Vec<(Ipv4Address, u8, Option<u16>)>,
}

impl Endpoint {
    fn forward_helper(
        &mut self,
        rx_nic: impl RxToken,
        innerl2bridge: &mut Vec<EthernetAddress>,
        match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
        own_endpoint_index: usize,
        all_devices: &[Rc<RefCell<EndpointOrControl>>],
        zerocopy: bool,
        pcap_dump: &Option<Box<PcapSink>>,
    ) -> Option<Vec<usize>> {
        if let Ok(ret_val) = rx_nic.consume(Instant::from_millis(0), |read_buffer| {
            match pcap_dump {
                Some(pcap_sink) => {
                    pcap_sink.packet(Instant::now(), read_buffer);
                }
                _ => {}
            }
            let (target, mut ret) = self.find_forward(
                innerl2bridge,
                match_register,
                own_endpoint_index,
                read_buffer,
                all_devices,
            );
            if let Some(target_wrap) = target {
                let target_ref = match target_wrap {
                    Target::Endpoint(end_ref) => end_ref,
                    Target::Nic => self.for_nic.as_ref().unwrap(),
                };
                let mut target_outer = target_ref.borrow_mut();
                let mut target = target_outer.ept_mut();
                let write_res = if zerocopy && self.dev.is_netmap() && target.dev.is_netmap() {
                    target.dev.zc_forward(&mut self.dev)
                } else {
                    target.dev.write(read_buffer)
                };
                if write_res.is_err() {
                    debug!(
                        "Write error {:?} for {} {:?}, {:?}",
                        write_res,
                        own_endpoint_index,
                        target.client_path,
                        target.dev.get_nic()
                    );
                } else {
                    trace!(
                        "Forwarded to {:?}, {:?}",
                        target.client_path,
                        target.dev.get_nic()
                    );
                }
                if let Err(Error::Unaddressable) = write_res {
                    let mut target_index = None;
                    for (idx, ep) in all_devices.iter().enumerate() {
                        if Rc::ptr_eq(ep, target_ref) {
                            target_index = Some(idx);
                            break;
                        }
                    }
                    if let Some(ref mut v) = ret {
                        v.push(target_index.unwrap());
                    } else {
                        ret = Some(vec![target_index.unwrap()]);
                    }
                }
            }
            Ok(ret)
        }) {
            ret_val
        } else {
            None
        }
    }
    pub fn forward(
        &mut self,
        innerl2bridge: &mut Vec<EthernetAddress>,
        match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
        own_endpoint_index: usize,
        all_devices: &[Rc<RefCell<EndpointOrControl>>],
        zerocopy: bool,
        pcap_dump: &Option<Box<PcapSink>>,
    ) -> Option<Vec<usize>> {
        let mut ret: Option<Vec<usize>> = None;
        while let Some(receive_token_impl) = self.dev.get_device_receive() {
            // is rewriting sometimes needed? e.g. to announce a different MAC to the host kernel but send out with the same on the network
            if let Some(p) = match receive_token_impl {
                ReceiveTokenImpl::Netmap((rx_nic, _)) => self.forward_helper(
                    rx_nic,
                    innerl2bridge,
                    match_register,
                    own_endpoint_index,
                    all_devices,
                    zerocopy,
                    pcap_dump,
                ),
                ReceiveTokenImpl::UnixDomainSocket((rx_nic, _)) => self.forward_helper(
                    rx_nic,
                    innerl2bridge,
                    match_register,
                    own_endpoint_index,
                    all_devices,
                    zerocopy,
                    pcap_dump,
                ),
            } {
                if let Some(ref mut v) = ret {
                    v.extend(p);
                } else {
                    ret = Some(p);
                }
            }
        }
        ret
    }
    pub fn find_forward<'a>(
        &mut self,
        innerl2bridge: &'a mut Vec<EthernetAddress>,
        match_register: &'a mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
        own_endpoint_index: usize,
        read_buffer: &[u8],
        all_devices: &'a [Rc<RefCell<EndpointOrControl>>],
    ) -> (Option<Target<'a>>, Option<Vec<usize>>) {
        let incoming_packet = self.dev.get_nic().is_some();
        if let Some((pkt_info, ethsrc, ethdst)) = extract_pkt_info(read_buffer) {
            if !incoming_packet && ethsrc.is_unicast() && !innerl2bridge.contains(&ethsrc) {
                innerl2bridge.push(ethsrc);
            }
            trace!("Looking up pkt: {:?}", pkt_info);
            if pkt_info.is_arp() {
                return (
                    None,
                    mirror_to_all(own_endpoint_index, all_devices, read_buffer),
                ); // got already forwarded
            }
            if pkt_info.is_loopback() {
                debug!("Drop localhost packet {:?}", pkt_info);
                return (None, None);
            }
            if !incoming_packet {
                let want = pkt_info.to_want();
                trace!("Converted to {:?}", want);
                if !self
                    .listening
                    .contains(&(want.dst_addr, want.protocol, want.dst_port))
                {
                    let entry = match_register.entry(want);
                    trace!(
                        "has already an automatic forward rule: {}",
                        match entry {
                            hashbrown::hash_map::Entry::Vacant(_) => false,
                            hashbrown::hash_map::Entry::Occupied(_) => true,
                        }
                    );
                    let _ = entry.or_insert((false, all_devices[own_endpoint_index].clone()));
                } else {
                    trace!("explicit forwarding rule exists");
                }
            }
            if !incoming_packet && !innerl2bridge.contains(&ethdst) {
                (Some(Target::Nic), None) // forward to endpoint's NIC
            } else {
                // bounce back not allowed, NIC as target not allowed
                let target =
                    get_endpoint(match_register, own_endpoint_index, all_devices, &pkt_info);
                if target.is_none() {
                    debug!("Drop recv {:?}", pkt_info);
                } else {
                    trace!("Forwarding {:?}", pkt_info);
                }
                (target.map(|e| Target::Endpoint(e)), None)
            }
        } else {
            trace!("dropped unkown packet");
            (None, None)
        }
    }
}

pub enum Target<'a> {
    Endpoint(&'a Rc<RefCell<EndpointOrControl>>),
    Nic,
}

// performs the matching
fn get_endpoint<'a>(
    match_register: &'a HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
    own_endpoint_index: usize,
    all_devices: &'a [Rc<RefCell<EndpointOrControl>>],
    pkt_info: &PacketInfo,
) -> Option<&'a Rc<RefCell<EndpointOrControl>>> {
    // first look for (src_addr+src_port, dst_port, protocol, dst_addr)
    // then look for (None, dst_port, protocol, dst_addr)
    // but this *None* (↓) is not needed because listener must setup port if applicable:
    // (None/src_addr, *None*, …) [in case dst_port.is_some()]
    let endpoint_opt = if let Some((_, endpoint)) =
        match_register.get(&pkt_info.to_match_want_with_src(true))
    {
        Some(endpoint)
    } else {
        if let Some((_, endpoint)) = match_register.get(&pkt_info.to_match_want_with_src(false)) {
            Some(endpoint)
        } else {
            None
        }
    };
    if let Some(endpoint_ref) = endpoint_opt {
        let endpoint_outer = endpoint_ref.borrow();
        let endpoint = endpoint_outer.ept();
        if endpoint.dev.get_nic().is_some()
            || Rc::ptr_eq(endpoint_ref, &all_devices[own_endpoint_index])
        {
            return None;
        }
    }
    endpoint_opt
}

fn mirror_to_all(
    own_endpoint_index: usize,
    all_devices: &[Rc<RefCell<EndpointOrControl>>],
    read_buffer: &[u8],
) -> Option<Vec<usize>> {
    let mut ret: Option<Vec<usize>> = None;
    for (ind, endpoint) in all_devices
        .iter()
        .enumerate()
        .filter(|(ind, _)| *ind != own_endpoint_index)
    {
        let mut target = endpoint.borrow_mut();
        if target.is_ept() {
            if let Err(Error::Unaddressable) = target.ept_mut().dev.write(read_buffer) {
                if let Some(ref mut v) = ret {
                    v.push(ind);
                } else {
                    ret = Some(vec![ind]);
                }
            }
        }
    }
    ret
}
