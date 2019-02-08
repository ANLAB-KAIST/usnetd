mod devices;
mod endpoint;
mod pkt;

#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate clap;
extern crate dotenv;

use devices::{all_pipes, EndpointDevice};
use endpoint::Endpoint;
use pkt::Want;

extern crate libusnetd;
use libusnetd::{ClientMessage, ClientMessageIp, SOCKET_PATH};

extern crate usnet_devices;
use self::usnet_devices::{nmreq, Netmap, UnixDomainSocket};

extern crate smoltcp;

#[cfg(feature = "pcap")]
use smoltcp::phy::PcapLinkType;
use smoltcp::phy::PcapSink;
use smoltcp::wire::{EthernetAddress, IpProtocol, Ipv4Address};

extern crate hashbrown;
use hashbrown::HashMap;

extern crate byteorder;

extern crate nix;
use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockAddr};
use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
use nix::sys::uio::IoVec;
use nix::unistd::{chown, Gid};

use nix::poll::{poll, EventFlags, PollFd};

use std::cell::RefCell;
use std::env;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use std::os::raw::c_int;

use std::fs;
#[cfg(feature = "pcap")]
use std::io;
use std::io::Read;
use std::path::Path;
use std::str;
use std::str::FromStr;

use std::mem;
use std::os::unix::net::UnixDatagram;
use std::slice;

extern crate serde_json;

#[derive(Debug)]
pub enum EndpointOrControl {
    Control(UnixDatagram),
    Ept(Endpoint),
}

impl EndpointOrControl {
    fn ept(&self) -> &Endpoint {
        match self {
            EndpointOrControl::Ept(e) => e,
            _ => panic!("not an endpoint"),
        }
    }
    fn ept_mut(&mut self) -> &mut Endpoint {
        match self {
            EndpointOrControl::Ept(e) => e,
            _ => panic!("not an endpoint"),
        }
    }
    fn is_ept(&self) -> bool {
        match self {
            EndpointOrControl::Ept(_) => true,
            _ => false,
        }
    }
    fn as_raw_fd(&self) -> RawFd {
        match self {
            EndpointOrControl::Ept(e) => e.dev.as_raw_fd(),
            EndpointOrControl::Control(ud) => ud.as_raw_fd(),
        }
    }
}

struct Endpoints {
    fds: Vec<PollFd>, // managed by Endpoints.add/remove methods
}
impl Endpoints {
    fn new() -> Endpoints {
        Endpoints { fds: vec![] }
    }
    fn poll<'a>(
        &'a mut self,
        devices: &'a [Rc<RefCell<EndpointOrControl>>],
    ) -> impl Iterator<Item = (usize, &Rc<RefCell<EndpointOrControl>>)> + 'a {
        match poll(&mut self.fds[..], -1 as c_int) {
            Ok(_) => self
                .fds
                .iter()
                .zip(devices.iter().enumerate())
                .filter(|(pfd, _)| pfd.revents() == Some(EventFlags::POLLIN))
                .map(|(_, d)| d),
            Err(e) => panic!("poll error: {}", e),
        }
    }
    fn add(
        &mut self,
        devices: &mut Vec<Rc<RefCell<EndpointOrControl>>>,
        endpoint: Rc<RefCell<EndpointOrControl>>,
    ) {
        match *endpoint.borrow() {
            EndpointOrControl::Ept(ref ed) => {
                assert_eq!(!ed.dev.get_nic().is_some(), ed.for_nic.is_some());
            }
            _ => {}
        }
        let raw_fd = endpoint.borrow().as_raw_fd();
        self.fds.push(PollFd::new(raw_fd, EventFlags::POLLIN));
        devices.push(endpoint);
        info!("added endpoint {}", devices.len() - 1);
    }
    fn remove(
        &mut self,
        devices: &mut Vec<Rc<RefCell<EndpointOrControl>>>,
        e: Rc<RefCell<EndpointOrControl>>,
    ) {
        let mut index_opt = None;
        for (ind, rc) in devices.iter().enumerate() {
            if Rc::ptr_eq(rc, &e) {
                index_opt = Some(ind);
                break;
            }
        }
        if let Some(index) = index_opt {
            self.fds.remove(index);
            devices.remove(index);
            info!("cleared endpoint {}", index);
        } else {
            info!("double remove call");
        }
    }
}

fn find_by_client_path(
    devices: &Vec<Rc<RefCell<EndpointOrControl>>>,
    own_endpoint_index: usize,
    client_path: &Path,
) -> Option<Rc<RefCell<EndpointOrControl>>> {
    let mut r = None;
    for (_, endpoint_ref) in devices
        .iter()
        .enumerate()
        .filter(|(ind, _)| *ind != own_endpoint_index)
    {
        let endpoint_outer = endpoint_ref.borrow();
        match *endpoint_outer {
            EndpointOrControl::Ept(ref endpoint) => match endpoint.client_path {
                Some(ref pathbuf) if pathbuf.as_path() == client_path => {
                    r = Some(endpoint_ref.clone());
                    break;
                }
                _ => {}
            },
            _ => {}
        }
    }
    r
}

fn find_nic_by_interface(
    devices: &Vec<Rc<RefCell<EndpointOrControl>>>,
    own_endpoint_index: usize,
    iface: &str,
) -> Option<Rc<RefCell<EndpointOrControl>>> {
    let mut r = None;
    for (_, endpoint_ref) in devices
        .iter()
        .enumerate()
        .filter(|(ind, _)| *ind != own_endpoint_index)
    {
        let endpoint_outer = endpoint_ref.borrow();
        match *endpoint_outer {
            EndpointOrControl::Ept(ref endpoint) => match endpoint.dev.get_nic() {
                Some(ref name) if *name == iface => {
                    r = Some(endpoint_ref.clone());
                    break;
                }
                _ => {}
            },
            _ => {}
        }
    }
    r
}

fn find_host_ring_by_interface(
    devices: &Vec<Rc<RefCell<EndpointOrControl>>>,
    own_endpoint_index: usize,
    iface: &str,
) -> Option<Rc<RefCell<EndpointOrControl>>> {
    let mut r = None;
    for (_, endpoint_ref) in devices
        .iter()
        .enumerate()
        .filter(|(ind, _)| *ind != own_endpoint_index)
    {
        let endpoint_outer = endpoint_ref.borrow();
        match *endpoint_outer {
            EndpointOrControl::Ept(ref endpoint) => match endpoint.dev.get_host_ring() {
                Some(ref name) if *name == iface => {
                    r = Some(endpoint_ref.clone());
                    break;
                }
                _ => {}
            },
            _ => {}
        }
    }
    r
}

fn add_listening_match(
    sticky: bool,
    endpoint: Rc<RefCell<EndpointOrControl>>,
    want: Want,
    match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
) -> bool {
    if match_register.contains_key(&want) {
        return false;
    }
    {
        let mut endpoint_inner = endpoint.borrow_mut();
        endpoint_inner
            .ept_mut()
            .listening
            .push((want.dst_addr, want.protocol, want.dst_port));
        // delete cache
        match &endpoint_inner.ept_mut().for_nic {
            Some(ne) => {
                let mut ni = ne.borrow_mut();
                ni.ept_mut().last_pkt = None;
            }
            None => {
                panic!("listening match should be registered for endpoint, not NIC");
            }
        }
    }
    match_register.insert(want, (sticky, endpoint));
    debug!("Now the match rules are:");
    for k in match_register.keys() {
        debug!("* {:?}", k);
    }
    return true;
}

fn add_debug_match_for_kernel(
    want: Want,
    match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
    devices: &Vec<Rc<RefCell<EndpointOrControl>>>,
    interface: &str,
) {
    let host = find_host_ring_by_interface(devices, usize::max_value(), interface)
        .expect("host ring not found");
    add_listening_match(true, host, want, match_register);
}

fn add_static_pipe(
    want: Want,
    interface: &str,
    endpoints: &mut Endpoints,
    match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
    devices: &mut Vec<Rc<RefCell<EndpointOrControl>>>,
) {
    let anic =
        find_nic_by_interface(&devices, usize::max_value(), interface).expect("NIC not found");
    let pipe_id = {
        let mut nic_inner = anic.borrow_mut();
        nic_inner
            .ept_mut()
            .dev
            .free_pipe_ids()
            .pop()
            .expect("No pipe IDs")
    };
    let pipeidstr = format!("{}", pipe_id);
    let pipename = "netmap:".to_string() + interface + "}" + &pipeidstr;
    let netmap_pipe_endpoint =
        Netmap::new(&pipename, interface, true, None).expect("Could not construct netmap pipe");
    let epref = Rc::new(RefCell::new(EndpointOrControl::Ept(Endpoint {
        dev: EndpointDevice::UserNetmap(netmap_pipe_endpoint, pipe_id),
        for_nic: Some(anic),
        client_path: None,
        listening: vec![],
        next_dhcp_endpoint: None,
        last_pkt: None,
        last_pkt_dst: None,
    })));
    endpoints.add(devices, epref.clone());
    info!("added static pipe: {}, use with {}", pipename, "{");
    add_listening_match(true, epref, want, match_register);
}

fn get_ip_string(interface: &str) -> String {
    use std::process::Command;
    let ioutput = Command::new("ip")
        .args(&["-4", "a", "show", "dev", interface])
        .output()
        .expect("command ip show failed");
    let iout1a = String::from_utf8(ioutput.stdout).unwrap();
    let iout1 = iout1a.split("inet ").collect::<Vec<_>>()[1];
    let ipandsub = iout1.split(' ').collect::<Vec<_>>()[0]
        .split('/')
        .collect::<Vec<_>>();
    let ipv4 = ipandsub[0].to_string();
    let _sub = u8::from_str(ipandsub[1]).expect("net size not found");
    ipv4
}

fn parse_port_list(port_list: &str) -> Vec<(String, u8, Option<u16>, Option<String>)> {
    let mut r = Vec::new();
    for entry in port_list.split(',') {
        let mut parts = entry.split(':');
        let interface = parts.next().expect("expected interface name").to_string();
        let (protocol, maybe_port) = {
            match parts.next() {
                Some(prot) if prot == "ICMP" => (u8::from(IpProtocol::Icmp), None),
                Some(prot) if prot == "TCP" || prot == "UDP" => (
                    u8::from(if prot == "TCP" {
                        IpProtocol::Tcp
                    } else {
                        IpProtocol::Udp
                    }),
                    Some(
                        u16::from_str(parts.next().expect("expected :port"))
                            .expect("could not parse port"),
                    ),
                ),
                Some(prot) => panic!(
                    "protocol {} is currently not recognized in the static configuration",
                    prot
                ),
                None => panic!("no protocol:port tuple given"),
            }
        };
        let maybe_remote = parts.next().map(|s| s.to_string());
        assert_eq!(parts.next(), None);
        r.push((interface, protocol, maybe_port, maybe_remote));
    }
    r
}

enum EntryChange {
    Add(Rc<RefCell<EndpointOrControl>>),
    Remove(Rc<RefCell<EndpointOrControl>>),
    CleanupKernel,
}

fn act_on(
    client_msg: &ClientMessage,
    client_path: &Path,
    sock_addr: &SockAddr,
    service_socket: &mut UnixDatagram,
    all_devices: &Vec<Rc<RefCell<EndpointOrControl>>>,
    endpoint_index: usize,
    match_register: &mut HashMap<Want, (bool, Rc<RefCell<EndpointOrControl>>)>,
    endpoint_changes: &mut Vec<EntryChange>,
    pipe_monitor: &mut Vec<(u64, Rc<RefCell<EndpointOrControl>>)>,
) {
    match client_msg {
        ClientMessage::RequestUDS(ref iface, pid) => {
            if let Some(anic) = find_nic_by_interface(all_devices, endpoint_index, iface) {
                if let Ok((userspace_stack_endpoint, userspace_stack_handover)) =
                    UnixDatagram::pair()
                {
                    let fds = [userspace_stack_handover.as_raw_fd()];
                    let cmsg = ControlMessage::ScmRights(&fds);
                    let iov = [IoVec::from_slice(b"$")];
                    if let Ok(_) = sendmsg(
                        service_socket.as_raw_fd(),
                        &iov,
                        &[cmsg],
                        MsgFlags::empty(),
                        Some(&sock_addr),
                    ) {
                        if let Ok(uds_dev) = UnixDomainSocket::new_from_unix_datagram(
                            userspace_stack_endpoint,
                            iface,
                            None,
                        ) {
                            let endpoint = Endpoint {
                                dev: EndpointDevice::UserUnixDomainSocket(uds_dev),
                                for_nic: Some(anic),
                                client_path: Some(client_path.to_path_buf()),
                                listening: vec![],
                                next_dhcp_endpoint: None,
                                last_pkt: None,
                                last_pkt_dst: None,
                            };
                            let endpoint_rc =
                                Rc::new(RefCell::new(EndpointOrControl::Ept(endpoint)));
                            pipe_monitor.push((*pid, endpoint_rc.clone()));
                            endpoint_changes.push(EntryChange::Add(endpoint_rc));
                        } else {
                            error!("unix domain socket creation falied");
                        }
                    } else {
                        error!("sndmsg falied");
                    }
                } else {
                    error!("no unix datagram pair created");
                }
            } else {
                error!("nic {} not found", iface);
            }
        }
        ClientMessage::RequestNetmapPipe(ref iface, pid) => {
            if let Some(anic) = find_nic_by_interface(all_devices, endpoint_index, iface) {
                if let Some(pipe_id) = {
                    let mut nic_inner = anic.borrow_mut();
                    nic_inner.ept_mut().dev.free_pipe_ids().pop()
                } {
                    let pipeidstr = format!("{}", pipe_id);
                    if let Ok(netmap_pipe_handover) = Netmap::new(
                        &("netmap:".to_string() + iface + "{" + &pipeidstr),
                        iface,
                        true,
                        None,
                    ) {
                        if let Ok(netmap_pipe_endpoint) = Netmap::new(
                            &("netmap:".to_string() + iface + "}" + &pipeidstr),
                            iface,
                            true,
                            None,
                        ) {
                            let fds = [netmap_pipe_handover.as_raw_fd()];
                            let cmsg = ControlMessage::ScmRights(&fds);
                            let req = netmap_pipe_handover.get_nmreq();
                            let req_slice = unsafe {
                                slice::from_raw_parts(
                                    (&req as *const nmreq) as *const u8,
                                    mem::size_of::<nmreq>(),
                                )
                            };

                            let iov = [IoVec::from_slice(req_slice)];
                            if let Ok(_) = sendmsg(
                                service_socket.as_raw_fd(),
                                &iov,
                                &[cmsg],
                                MsgFlags::empty(),
                                Some(&sock_addr),
                            ) {
                                let endpoint = Endpoint {
                                    dev: EndpointDevice::UserNetmap(netmap_pipe_endpoint, pipe_id),
                                    for_nic: Some(anic),
                                    client_path: Some(client_path.to_path_buf()),
                                    listening: vec![],
                                    next_dhcp_endpoint: None,
                                    last_pkt: None,
                                    last_pkt_dst: None,
                                };
                                let endpoint_rc =
                                    Rc::new(RefCell::new(EndpointOrControl::Ept(endpoint)));
                                pipe_monitor.push((*pid, endpoint_rc.clone()));
                                endpoint_changes.push(EntryChange::Add(endpoint_rc));
                            } else {
                                error!("sndmsg failed");
                            }
                        } else {
                            error!("no own netmap pipe created");
                        }
                    } else {
                        error!("no own netmap pipe created");
                    }
                } else {
                    error!("pipe IDs exhausted");
                }
            } else {
                error!("nic {} not found", iface);
            }
        }
        ClientMessage::AddMatch(want_msg) => {
            if let Some(endpoint) = find_by_client_path(all_devices, endpoint_index, client_path) {
                if let Some(want) = Want::new_from_want_msg(&want_msg) {
                    info!("adding rule for {:?} from {:?}", want, client_path);
                    let aw = if add_listening_match(false, endpoint, want, match_register) {
                        "OK"
                    } else {
                        "ER"
                    };
                    if let Ok(r) = service_socket.send_to(aw.as_bytes(), client_path) {
                        assert_eq!(r, aw.len());
                    } else {
                        error!("AddMatch: cannot send to {}", client_path.display());
                    }
                } else {
                    error!("AddMatch: error parsing ip addr from {:?}", want_msg);
                }
            } else {
                error!("AddMatch: endpoint for {} not found", client_path.display());
            }
        }
        ClientMessage::QueryUsedPorts => {
            let mut listening_triple = vec![];
            let mut connection_triple = vec![];
            // not looking in endpoint.listen here, assuming that listeners just don't have a src_ip set, so in some cases the categories can vary
            for k in match_register.keys() {
                let Want {
                    dst_addr,
                    dst_port,
                    src_addr,
                    src_port: _,
                    protocol,
                } = k;
                if let Some(port) = dst_port {
                    let listening_or_connection = if src_addr.is_some() {
                        &mut connection_triple
                    } else {
                        &mut listening_triple
                    };
                    listening_or_connection.push((
                        *protocol,
                        ClientMessageIp::Ipv4(format!("{}", dst_addr)),
                        *port,
                    ));
                }
            }
            let resp = ClientMessage::QueryUsedPortsAnswer {
                listening: listening_triple,
                connected: connection_triple,
            };
            let payl = serde_json::to_string(&resp).unwrap();
            let sent_bytes = service_socket
                .send_to(payl.as_bytes(), client_path)
                .expect("cannot send on service unix domain socket");
            assert_eq!(sent_bytes, payl.len());
        }
        ClientMessage::DeleteClient => {
            if let Some(endpoint) = find_by_client_path(all_devices, endpoint_index, client_path) {
                info!("got delete event from client");
                endpoint_changes.push(EntryChange::Remove(endpoint));
            }
        }
        ClientMessage::RemoveMatch(want_msg) => {
            if let Some(endpoint) = find_by_client_path(all_devices, endpoint_index, client_path) {
                if let Some(want) = Want::new_from_want_msg(&want_msg) {
                    if let Some((_, endp)) = match_register.get(&want) {
                        if !Rc::ptr_eq(endp, &endpoint) {
                            warn!("want rule does not belong to client which requests removal");
                            return;
                        }
                    } else {
                        warn!("could not find rule to remove");
                    }
                    match_register.remove(&want);
                    info!("remove rule {:?} as requested from client", want);
                } else {
                    warn!("could not convert to want msg");
                }
            }
        }
        ClientMessage::QueryUsedPortsAnswer {
            listening: _,
            connected: _,
        } => {
            warn!("received answer message from client, ignoring");
        }
    }
}

#[cfg(feature = "pcap")]
fn pcap_dump() -> Option<Box<PcapSink>> {
    let log_file = env::var("PCAP_LOG").ok()?;
    let pcap_writer: Box<io::Write> =
        Box::new(fs::File::create(log_file).expect("cannot open file"));
    let pcap_sink = Box::new(RefCell::new(pcap_writer)) as Box<PcapSink>;
    pcap_sink.global_header(PcapLinkType::Ethernet);
    Some(pcap_sink)
}

#[cfg(not(feature = "pcap"))]
fn pcap_dump() -> Option<Box<PcapSink>> {
    None
}

fn read_ports_from(proc_net_tcp_or_udp: &str) -> Vec<u16> {
    let mut f = fs::File::open(proc_net_tcp_or_udp).expect("cannot open /proc/net/tcp|udp");
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)
        .expect("cannot read from /proc/net/tcp|udp");
    buffer
        .lines()
        .skip(1)
        .map(|s| {
            u16::from_str_radix(
                s.split(':')
                    .nth(2)
                    .expect("misparsed")
                    .split(' ')
                    .nth(0)
                    .expect("misparsed"),
                16,
            )
            .expect("cannot parse hex port")
        })
        .collect::<Vec<_>>()
}

fn cleanup_kernel() {
    let timer_path = SOCKET_PATH.to_string() + "timer";
    let _ = fs::remove_file(&timer_path);
    let timer = UnixDatagram::bind(&timer_path).expect("Cannot bind timer socket");
    loop {
        thread::sleep(Duration::from_secs(60));
        timer
            .send_to("cleanup_kernel".as_bytes(), SOCKET_PATH)
            .expect("cannot send to service unix domain socket");
    }
}

fn main() {
    let matches = clap::App::new("usnetd")
     .about("Memory-safe L4 Switch for Userspace Network Stacks")
     .version(crate_version!())
     .args_from_usage("[CONFFILE]           'Optional configuration file where fallback env variables are loaded from'")
     .after_help(("Required and optional environment variables (<>: required, []: optional, |: alternative):
<INTERFACES>: Names of NIC interfaces which should be claimed, separated by commas
[ALLOW_GID]: Sets the user group ID which can access the control socket at ".to_string() + SOCKET_PATH + "
[DEBUG_PORTS]: Opens ports for the kernel network stack, specified as list of
               <INTERFACE>:<<TCP:PORTNUMBER>|<UDP:PORTNUMBER>|<ICMP>>[:<REMOTEIP>] separated
               by commas, e.g., eth0:TCP:22 (currently takes only the first IP of the kernel)
[STATIC_PIPES]: Creates static netmap pipes specified as list of
                <INTERFACE>:<<TCP:PORTNUMBER>|<UDP:PORTNUMBER>|<ICMP>>[:<REMOTEIP>] separated
                by commas, starting with a pipe ID of 4094 and counting downwards,
                i.e., netmap:eth0{4094 (currently, only one port per pipe can be specified in
                this format and the same IP is used as the IP of the kernel)
[ADD_MACS]:     Adds local MACs for to the bridge for endpoints that do not send out packets
                so that their MAC could be learned. Takes a list separated by commas.
[NO_HOST_RINGS]: Disables forwarding for host kernel packets if set to 'true'
[NO_ZERO_COPY]: Turns off netmap zero-copy forwarding if set to 'true'
[PCAP_LOG]: If built with the 'pcap' feature, specifies dump file location
[RUST_LOG]: Can be one of 'error', 'warn', 'info', 'debug', 'trace' ('trace' only for debug builds)
").as_ref())
     .get_matches();
    match matches.value_of("CONFFILE") {
        Some(filename) => {
            dotenv::from_path(Path::new(filename)).expect("could not open configuration file");
            info!("read config from {}", filename)
        }
        _ => {}
    }
    env_logger::init();

    let interfaces = env::var("INTERFACES").expect("INTERFACES env var not specified");

    let zerocopy = env::var("NO_ZERO_COPY") != Ok("true".to_string());
    info!("using zero copy: {}", zerocopy);
    let host_rings = env::var("NO_HOST_RINGS") != Ok("true".to_string());
    info!("forwarding kernel packets: {}", host_rings);

    let gid = env::var("ALLOW_GID")
        .ok()
        .map(|s| Gid::from_raw(u32::from_str(&s).expect("ALLOW_GID not an unsigned integer")));

    let pcap_dump = pcap_dump();

    let mut match_register = HashMap::default();
    let mut innerl2bridge = vec![];
    match env::var("ADD_MACS") {
        Ok(macs) => {
            for mac in macs.split(',') {
                let m = mac
                    .split(':')
                    .map(|s| u8::from_str_radix(s, 16).unwrap())
                    .collect::<Vec<_>>();
                innerl2bridge.push(EthernetAddress([m[0], m[1], m[2], m[3], m[4], m[5]]));
            }
            info!("prepopulated bridge MACs: {:?}", innerl2bridge);
        }
        _ => {}
    }
    let mut pipe_monitor = vec![];
    let mut all_devices = vec![]; // only managed by Endpoints.add() etc
    let mut endpoints = Endpoints::new();

    let _ = fs::remove_file(SOCKET_PATH);
    let ud = UnixDatagram::bind(SOCKET_PATH).expect("Cannot bind service socket");
    chown(SOCKET_PATH, None, gid).expect("chown to set group failed");
    fchmodat(
        None,
        SOCKET_PATH,
        Mode::S_IRUSR
            | Mode::S_IWUSR
            | Mode::S_IXUSR
            | Mode::S_IRGRP
            | Mode::S_IWGRP
            | Mode::S_IXGRP,
        FchmodatFlags::FollowSymlink,
    )
    .expect("chmod 770 failed");
    ud.set_nonblocking(true).unwrap();
    let control = Rc::new(RefCell::new(EndpointOrControl::Control(ud)));
    endpoints.add(&mut all_devices, control);
    for interface in interfaces.split(',') {
        let nic = Rc::new(RefCell::new(EndpointOrControl::Ept(Endpoint {
            for_nic: None,
            client_path: None,
            dev: EndpointDevice::NicNetmap(
                Netmap::new(&("netmap:".to_string() + interface), interface, true, None).unwrap(),
                interface.to_string(),
                all_pipes(),
            ),
            listening: vec![],
            next_dhcp_endpoint: None,
            last_pkt: None,
            last_pkt_dst: None,
        })));
        endpoints.add(&mut all_devices, nic.clone());
        if host_rings {
            let host = Rc::new(RefCell::new(EndpointOrControl::Ept(Endpoint {
                for_nic: Some(nic),
                client_path: None,
                dev: EndpointDevice::HostRing(
                    Netmap::new(
                        &("netmap:".to_string() + interface + "^"),
                        interface,
                        true,
                        None,
                    )
                    .unwrap(),
                    interface.to_string(),
                ),
                listening: vec![],
                next_dhcp_endpoint: None,
                last_pkt: None,
                last_pkt_dst: None,
            })));
            endpoints.add(&mut all_devices, host);
        }
    }

    if let Ok(port_list) = env::var("DEBUG_PORTS") {
        for (interface, protocol, maybe_port, maybe_remote) in parse_port_list(&port_list) {
            let interface_ip = get_ip_string(&interface);
            let want_ssh = Want {
                dst_addr: Ipv4Address::from_str(&interface_ip).unwrap(),
                protocol: protocol,
                dst_port: maybe_port,
                src_addr: maybe_remote.map(|s| Ipv4Address::from_str(&s).unwrap()),
                src_port: None,
            };
            add_debug_match_for_kernel(want_ssh, &mut match_register, &mut all_devices, &interface);
        }
    }
    if let Ok(port_list) = env::var("STATIC_PIPES") {
        for (interface, protocol, maybe_port, maybe_remote) in parse_port_list(&port_list) {
            let interface_ip = get_ip_string(&interface);
            let want_static = Want {
                dst_addr: Ipv4Address::from_str(&interface_ip).unwrap(),
                dst_port: maybe_port,
                src_addr: maybe_remote.map(|s| Ipv4Address::from_str(&s).unwrap()),
                src_port: None,
                protocol: protocol,
            };
            add_static_pipe(
                want_static,
                &interface,
                &mut endpoints,
                &mut match_register,
                &mut all_devices,
            );
        }
    }
    // finished processing static configuration

    let _cleanup_thread = thread::spawn(cleanup_kernel);

    let mut client_buf = vec![0; 4000];
    let mut endpoint_changes = vec![];

    loop {
        for (endpoint_index, endpointorcontrol_ref) in endpoints.poll(&all_devices) {
            // select on all FDs
            let mut endpointorcontrol = endpointorcontrol_ref.borrow_mut();
            match *endpointorcontrol {
                EndpointOrControl::Control(ref mut service_socket) => {
                    if let Ok((len, client_addr)) =
                        service_socket.recv_from(client_buf.as_mut_slice())
                    {
                        if let Some(client_path) = client_addr.as_pathname() {
                            if let Ok(sock_addr) = SockAddr::new_unix(client_path) {
                                if let Ok(client_msg_str) = str::from_utf8(&client_buf[0..len]) {
                                    if let Ok(client_msg) = serde_json::from_str(&client_msg_str) {
                                        act_on(
                                            &client_msg,
                                            client_path,
                                            &sock_addr,
                                            service_socket,
                                            &all_devices,
                                            endpoint_index,
                                            &mut match_register,
                                            &mut endpoint_changes,
                                            &mut pipe_monitor,
                                        );
                                    } else {
                                        if client_msg_str == "cleanup_kernel" {
                                            endpoint_changes.push(EntryChange::CleanupKernel);
                                        } else {
                                            error!("no json: {}", client_msg_str);
                                        }
                                    }
                                } else {
                                    error!("broken string");
                                }
                            } else {
                                error!("no socket addr possible");
                            }
                        } else {
                            error!("no client path");
                        }
                    }
                }
                EndpointOrControl::Ept(ref mut endpoint) => {
                    if let Some(mut v) = endpoint.forward(
                        &mut innerl2bridge,
                        &mut match_register,
                        endpoint_index,
                        &all_devices,
                        zerocopy,
                        &pcap_dump,
                    ) {
                        v.sort_unstable();
                        v.dedup();
                        for rem_ind in v {
                            endpoint_changes
                                .push(EntryChange::Remove(all_devices[rem_ind].clone()));
                        }
                    }
                }
            }
        }
        if !endpoint_changes.is_empty() {
            for (pid, e_rc) in pipe_monitor.iter() {
                let process_probe = format!("/proc/{}/cmdline", pid);
                if let Err(_) = fs::File::open(&process_probe) {
                    endpoint_changes.push(EntryChange::Remove(e_rc.clone()));
                }
            }
        }
        while let Some(change) = endpoint_changes.pop() {
            match change {
                EntryChange::Add(endpoint_rc) => {
                    endpoints.add(&mut all_devices, endpoint_rc);
                }
                EntryChange::Remove(e) => {
                    {
                        match_register.retain(|_, (_, rc)| !Rc::ptr_eq(rc, &e));
                        pipe_monitor.retain(|(_, rc)| !Rc::ptr_eq(rc, &e));
                    }
                    endpoints.remove(&mut all_devices, e);
                }
                EntryChange::CleanupKernel => {
                    let open_tcp_ports = read_ports_from("/proc/net/tcp");
                    let open_udp_ports = read_ports_from("/proc/net/udp");
                    debug!("Before cleanup the match rules are:");
                    for k in match_register.keys() {
                        debug!("* {:?}", k);
                    }
                    for endpoint_ref in all_devices.iter() {
                        let kernel_ring = match *endpoint_ref.borrow() {
                            EndpointOrControl::Ept(ref endpoint) => {
                                endpoint.dev.get_host_ring().is_some()
                            }
                            _ => false,
                        };
                        if kernel_ring {
                            match_register.retain(|wantrule, (sticky, rc)| {
                                !(Rc::ptr_eq(rc, &endpoint_ref) && !*sticky && {
                                    match wantrule.dst_port {
                                        Some(dst_port) => {
                                            if wantrule.protocol == u8::from(IpProtocol::Tcp) {
                                                !open_tcp_ports.contains(&dst_port)
                                            } else if wantrule.protocol == u8::from(IpProtocol::Udp)
                                            {
                                                !open_udp_ports.contains(&dst_port)
                                            } else {
                                                true
                                            } // i.e., matches for protocols which have no ports in /proc/net/protocolname are cleared regularly
                                        }
                                        None => true, // i.e., matches for protocols without ports are cleared regularly
                                    }
                                })
                            });
                        }
                    }
                    debug!("After cleanup the match rules are:");
                    for k in match_register.keys() {
                        debug!("* {:?}", k);
                    }
                }
            }
        }
    }
}
