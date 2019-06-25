# usnetd: Memory-safe L4 Switch for Userspace Network Stacks

This is a prototype implementation of the switch design in the master thesis [“Memory-safe Network Services Through A Userspace Networking Switch”](https://pothos.github.io/papers/msc_thesis_memory-safe_network_services_userspace_switch.pdf), for a short version see the defense [presentation](https://pothos.github.io/papers/msc_thesis_memory-safe_network_services_userspace_switch_slides.pdf).

The switch runs as system service that shares a NIC for multiple userspace network stacks and the Linux kernel network stack.
It allows to use the same IP address for the kernel as for userspace network stacks.
To keep the security benefit of memory-safe network stacks it is written in Rust and also firewalls the host kernel network stack while supporting outgoing connections for system updates or other applications.
Network services can dynamically attach to the switch through handover of IPC pipes. They can register the IP address and port they want to receive (different IPs/MACs than the kernel uses are allowed).
See the [usnet_sockets](https://github.com/ANLAB-KAIST/usnet_sockets) Rust library for a easy-to-use memory-safe network stack that integrates well with the loopback interface of the kernel and makes use of usnetd to share the same IP.

The thesis evaluation was done with the tools in the folder `eval/` and shows that 10G line-rate packet matching with small packets is not yet possible due to lacking multi-core scalability but for larger packets a 10G TCP transfer is possible.

The current implementation covers the netmap and macvtap variant for NIC access.
Netmap needs a the netmap kernel module to be loaded at runtime and the netmap headers to be available at compile time.
It is recommended not only for performance reasons but also for a smooth experience for connection changes (specially WiFi).
With netmap support the userspace networking stacks can use netmap pipes as IPC channel for packets.

Macvtap NIC access with the passthru mode is used as fallback if netmap support was not enabled at compile time.
For the host kernel to keep network access a virtual TAP interface is used with appropriate routing table entries (deletes old ones, recreates them when it terminates).
Therefore, usnetd should be started after the interface got configured with DHCP or a static IP.

Unsafe code is used for netmap packet transfer and file descriptor handover. Read Chapter 3 of the thesis for a reasoning about the threat model and L2 code as the trusted code base.
Note: Support for DHCP, WiFi authentification, IP fragmentation, and macvtap access was added after the thesis was written.

Compile it as follows (optionally with the `--features pcap` flag to enable copying of all packets to a PCAP dump file):

    cargo build --release
    # or if netmap is available
    cargo build --release --features netmap

To use usnetd with netmap, first compile netmap and load the kernel module and the patched drivers, e.g., for ixgbe as follows.

    rmmod ixgbe
    insmod netmap/netmap.ko
    insmod netmap/ixgbe/ixgbe.ko
    # Then disable offloads and also Ethernet flow control. If you plan to use multiple MACs, then turn the card in promiscuous mode.
    ethtool -K enp1s0f0 tx off rx off gso off tso off gro off # maybe also "lro off"
    ethtool --pause enp1s0f0 tx off rx off
    ip link set enp1s0f0 promisc on
    dmesg | tail # to check for errors and see that flow control is disabled

The usnetd service assumes running as root and does not yet drop privileges but actually just access to `/dev/netmap` is needed and creation of `/run/usnetd.socket` with an optional `chown` call to change the group. Macvtap needs calls to the `ip` command to set up interfaces and access to `/dev/tapX`. The host kernel NIC access as virtual TAP device needs access to /dev/net/tun.
Because the IP for the virtual TAP device is copied from the original interface, run DHCP before you start usnetd if netmap is missing.

To start it, either provide at least the `INTERFACES` environment variable or write it to a configuration file which is an optional program argument.
Other variables can be set to configure a static netmap pipe or forwarding of a SSH port for the kernel as long as you just want to try usnetd.

    ARGS:
        <CONFFILE>    Optional configuration file where fallback env variables are loaded from
    
    Required and optional environment variables (<>: required, []: optional, |: alternative):
    <INTERFACES>: Names of NIC interfaces which should be claimed, separated by commas
    [ALLOW_GID]: Sets the user group ID which can access the control socket at /run/usnetd.socket
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

An example configuration file for usnet_sockets network services running with the group ID 1000 would be:

    RUST_LOG=debug
    INTERFACES=eth0
    DEBUG_PORTS=eth0:TCP:22
    ALLOW_GID=1000

For consistent performance you may want to pin it to a core by prepending `taskset -c 2` when starting it from the command line.

Hint: Outgoing packets of the Linux kernel network stack may be too large and dropped by a router because PMTU Discovery does not work since no ICMP packets are received through the firewall. Either disable PMTU Discovery `sysctl net.ipv4.ip_no_pmtu_disc=1` to allow the routers to fragment the packets that are too large, or enable dynamic MTU probing at the TCP layer (PLPMTU, RFC4821) `echo 1 > /proc/sys/net/ipv4/tcp_mtu_probing`.

## Adding support for usnetd to other network stacks
If you do not use usnet_sockets and want to add support for usnetd to your network stack, you can either use netmap pipes or Unix domain sockets as packet IPC channel.

The switch automatically adds port matching rules by sniffing outgoing packets.
Therefore, through a static netmap pipe configuration you can already use any network stack without modification as long as netmap is supported.

Ideally, your network stack implements the following protocol for dynamic creation of switch endpoints.
The interaction with userspace network stacks through the control socket is done through bound Unix domain sockets in datagram mode and the following protocol (JSON serialization through the serde Rust crate). The *→* symbol separates the request message from the usnetd answer. Only named protocol objects are encoded in JSON. The file descriptor handover uses the `sendmsg` syscall with the `ScmRights` control message.
The userspace network stack can either request netmap pipes or Unix domain sockets as packet IPC channels to be handed over.
Only packet matches for listening ports need to be registered. For outgoing connections the local ports in the range `/proc/sys/net/ipv4/ip_local_port_range` should not be used to avoid clashes. The userspace network stack needs to allocate kernel sockets at the loopback interface itself if it wants to connect to or be reachable by program that use the kernel network stack and share the same IP.

    * `RequestNetmapPipe(Interface, PID)` → `nmreq` struct (and file descriptor handover)
    * `RequestUDS(Interface, PID)` → `"$"` (and file descriptor handover)
    * `AddMatch(IP, Protocol, [Port], [Source IP], [Source Port])` → `"OK"`/`"ER"`
    * `RemoveMatch(IP, Protocol, [Port], [Source IP], [Source Port])`
    * `QueryUsedPorts` → `QueryUsedPortsAnswer(listening: (ipProtocol, localIP, localPort), …, connected: (ipProtocol, localIP, localPort), …)`
    * `DeleteClient`

# TODO

* ICMP handling and generation of error messages and TCP RSTs (maybe through spawning a dedicated userspace network stack on default)
* Handle broadcast and multicast packets (DHCP forwarding works already)
* IPv6
* macvtap: Detect broken connection (specially WiFi, and have a workaround for wpasupplicant to use the new interface), or use BPF instead of route entries to forward all packets
* Multiple entries for static configuration of netmap pipes as IPC channels
* Support static configuration for Unix domain sockets as packet IPC channels
* Multi-core scalability
* Other backends: DPDK (plus a KNI interface), or integration with VALE-bpf, AF_XDP, PFQ, or a manager for RAW sockets and a XDP kernel firewall
  * usnetd as manager for RAW sockets and a XDP kernel firewall: Userspace network stacks get RAW sockets with a cbpf filter for only their ports (to not send RSTs for each other); the kernel gets a XDP firewall to drop non-kernel connections; XDP answers/hands out ICMPs and RSTs.
  * AF_XDP: Kernel outgoing connections are sniffed with BPF (on syscall or tc/cgroup socket filter or similar)

# Ideas

* Pass all kernel connections through smoltcp with some possibility to break things:
  * a) Process connections in smoltcp sockets to get payload data and put it in a second group of smoltcp sockets that forward it to the kernel (beware: does not cover *inner* connections packet on top of UDP/IP unless usnetd is started a second time for e.g. the virtual VPN interface)
  * b) Provide a memory-safe network stack as transparent proxy based on usnet_sockets which forwards all incomming/outgoing connections to loopback connections, find out if UDP can be forwarded and otherwise just provide a local DNS to cover basic UDP usage
    * Special case for Kubernetes: port Linkerd service mesh to usnet_sockets since it already is a transparent proxy in Rust using tokio; add DNAT support to usnetd and use it as CNI plugin — or DNAT implemented in XDP; kernel veth interfaces are used through macvtap (or raw sockets but this needs some BPF code to drop packets early in the kernel network stack)
  * Benefit: Removes assumption that outgoing connections are trusted. Change in TCB: a) adds smoltcp→kernel connection to the TCB, while b) adds kernel→kernel (loopback) connections to the TCB.
* Offer a way for legacy applications to run on usnet_sockets (and thus usnetd): Implement a libc-compatible (for `LD_PRELOAD`) or Linux-ABI-compatible (for ptrace/KVM) wrapper around usnet_sockets
