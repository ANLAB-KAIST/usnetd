use super::{from_array, to_array};
use smoltcp::phy::wait as phy_wait;
use smoltcp::socket::SocketSet;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpProtocol};
use std::io::{self, Write};
use std::str::{self, FromStr};
use std::time::Instant as StdInstant;

use serde_json;
use std::env;
use usnet_sockets::usnetconfig::StcpBackend;

pub fn run(bufsize: usize, rxtx_size: usize, reverse: bool) {
    let nocopy = true;
    println!(
        "Server smoltcp on e.g. tap with RX/TX buffer size {}, recv buffer size {}",
        rxtx_size, bufsize
    );

    let confvar = env::var("USNET_SOCKETS").unwrap();
    let conf: StcpBackend = serde_json::from_str(&confvar).unwrap();
    let waiting_poll = env::var("USNET_SOCKETS_WAIT").unwrap_or("true".to_string()) == "true";
    println!("USNET_SOCKETS_WAIT: {}", waiting_poll);
    let reduce_mtu_by_nr = usize::from_str(&env::var("REDUCE_MTU_BY").unwrap_or("0".to_string()))
        .expect("BG_THREAD_PIN_CPU_ID not a number");
    let reduce_mtu_by = if reduce_mtu_by_nr == 0 {
        None
    } else {
        Some(reduce_mtu_by_nr)
    };
    println!("REDUCE_MTU_BY: {:?}", reduce_mtu_by);
    let (fd, mut iface) = conf.to_interface(waiting_poll, reduce_mtu_by);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; rxtx_size]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; rxtx_size]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
    let tcp_handle = sockets.add(tcp_socket);
    let mut tcp_active = false;

    let mut recv: u64 = 0;
    let mut start = StdInstant::now();
    let mut read_info = false;
    let mut bytes_to_read = 0;

    let mut inp = vec![0; bufsize];

    iface
        .add_port_match([0, 0, 0, 0].into(), Some(8080), None, None, IpProtocol::Tcp)
        .expect("cannot bind");

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(_) => {}
        };

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);
            if !socket.is_open() {
                println!("listening");
                socket.listen(8080).unwrap();
                read_info = false;
            }

            if socket.is_active() && !tcp_active {
                println!("new connection");
                start = StdInstant::now(); // assumes that sending will directly start
                recv = 0;
                if !nocopy {
                    inp.resize((bufsize) as usize, 0);
                }
                bytes_to_read = 0;
            } else if !socket.is_active() && tcp_active {
                // is disconnected
            }
            tcp_active = socket.is_active();

            if socket.may_recv() {
                if !read_info {
                    socket
                        .recv(|buffer| {
                            let r = if buffer.len() >= 8 {
                                bytes_to_read = from_array(&buffer[..8]);
                                if cfg!(feature = "printout") {
                                    print!("wait for {}", bytes_to_read);
                                    io::stdout().flush().unwrap();
                                }
                                read_info = true;
                                8
                            } else {
                                if cfg!(feature = "printout") {
                                    print!("(no enough data)");
                                    io::stdout().flush().unwrap();
                                }
                                0
                            };
                            (r, ())
                        })
                        .unwrap();
                }

                if read_info {
                    loop {
                        if !reverse {
                            let data_len = match socket.recv(|buffer| {
                                if buffer.len() > bufsize {
                                    (bufsize, buffer[..bufsize].len())
                                } else {
                                    (buffer.len(), buffer.len())
                                }
                            }) {
                                Ok(datam) => datam,
                                _ => {
                                    break;
                                }
                            };
                            if data_len == 0 {
                                if cfg!(feature = "printout") {
                                    print!("(no data)");
                                    io::stdout().flush().unwrap();
                                }
                                break;
                            } else {
                                recv += data_len as u64;
                                if cfg!(feature = "printout") {
                                    print!(".");
                                    io::stdout().flush().unwrap();
                                }

                                if recv >= bytes_to_read {
                                    let duration = start.elapsed();
                                    let sec = duration.as_secs() as f64
                                        + duration.subsec_nanos() as f64 * 1e-9;
                                    println!(
                                        "MBit/s {}, read {} bytes",
                                        recv as f64 / 1000f64 / 1000f64 * 8f64 / sec,
                                        recv
                                    );
                                    socket.send_slice(&to_array(recv)).unwrap();
                                    socket.close();
                                }
                            }
                        } else if socket.can_send() && recv < bytes_to_read {
                            if !nocopy && (recv + bufsize as u64 > bytes_to_read) {
                                inp.resize((bytes_to_read - recv) as usize, 0);
                            }
                            if nocopy {
                                let siz = if recv + bufsize as u64 > bytes_to_read {
                                    (bytes_to_read - recv) as usize
                                } else {
                                    bufsize
                                };
                                let write = socket
                                    .send(|buffer| {
                                        if buffer.len() > siz {
                                            (siz, siz)
                                        } else {
                                            (buffer.len(), buffer.len())
                                        }
                                    })
                                    .unwrap();
                                recv += write as u64;
                            } else {
                                let write = socket.send_slice(&inp).unwrap();
                                recv += write as u64;
                            }
                            if cfg!(feature = "printout") {
                                println!("({})", recv);
                            }
                            if socket.can_send() {
                                if recv >= bytes_to_read {
                                    let duration = start.elapsed();
                                    let sec = duration.as_secs() as f64
                                        + duration.subsec_nanos() as f64 * 1e-9;
                                    println!(
                                        "MBit/s {}, read {} bytes",
                                        recv as f64 / 1000f64 / 1000f64 * 8f64 / sec,
                                        recv
                                    );
                                    io::stdout().flush().unwrap();
                                    assert!(socket.send_slice(&to_array(recv)).unwrap() == 8);
                                    break;
                                }
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            } else if socket.may_send() {
                println!("closing");
                socket.close();
            }
        }
        if waiting_poll {
            phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
        }
    }
}

pub fn client(host: &str, bufsize: usize, amount: u64, reverse: bool, rxtx_size: usize) {
    let nocopy = true;
    println!(
        "Client smoltcp on e.g. TAP with RX/TX buffer size {}, recv buffer size {}",
        rxtx_size, bufsize
    );

    let confvar = env::var("USNET_SOCKETS").unwrap();
    let conf: StcpBackend = serde_json::from_str(&confvar).unwrap();
    let waiting_poll = env::var("USNET_SOCKETS_WAIT").unwrap_or("true".to_string()) == "true";
    println!("USNET_SOCKETS_WAIT: {}", waiting_poll);
    let reduce_mtu_by_nr = usize::from_str(&env::var("REDUCE_MTU_BY").unwrap_or("0".to_string()))
        .expect("BG_THREAD_PIN_CPU_ID not a number");
    let reduce_mtu_by = if reduce_mtu_by_nr == 0 {
        None
    } else {
        Some(reduce_mtu_by_nr)
    };
    println!("REDUCE_MTU_BY: {:?}", reduce_mtu_by);
    let (fd, mut iface) = conf.to_interface(waiting_poll, reduce_mtu_by);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; rxtx_size]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; rxtx_size]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
    let tcp_handle = sockets.add(tcp_socket);

    {
        let mut socket = sockets.get::<TcpSocket>(tcp_handle);
        let address = IpAddress::from_str(host).expect("invalid address format");
        socket.connect((address, 8080u16), 49500).unwrap();
    }

    let mut tcp_active = false;

    let mut send: u64 = 0;
    let mut start = StdInstant::now();
    let amount_in_bytes = amount * 1000u64;

    let mut outp = vec![0; bufsize];
    let mut send_info: bool = false;
    let mut recv_answer: bool = false;

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(_) => {}
        };

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);

            if socket.is_active() && !tcp_active {
                println!("connecting");
                start = StdInstant::now(); // assumes that sending will directly start
            } else if !socket.is_active() && tcp_active {
                println!("disconnected");
                break;
            }
            tcp_active = socket.is_active();

            if socket.may_recv() {
                if !send_info && socket.can_send() {
                    socket
                        .send(|buffer| {
                            let r = if buffer.len() >= 8 {
                                let a = to_array(amount_in_bytes);
                                for i in 0..a.len() {
                                    buffer[i] = a[i];
                                }
                                println!("announced {}", amount_in_bytes);
                                send_info = true;
                                8
                            } else {
                                if cfg!(feature = "printout") {
                                    print!("(no enough data)");
                                    io::stdout().flush().unwrap();
                                }
                                0
                            };
                            (r, ())
                        })
                        .unwrap();
                }

                if send_info && !recv_answer {
                    loop {
                        if reverse {
                            let data_len = match socket.recv(|buffer| {
                                if buffer.len() > bufsize {
                                    (bufsize, buffer[..bufsize].len())
                                } else {
                                    (buffer.len(), buffer.len())
                                }
                            }) {
                                Ok(datam) => datam,
                                _ => {
                                    break;
                                }
                            };
                            if data_len == 0 {
                                if cfg!(feature = "printout") {
                                    print!("(no data)");
                                    io::stdout().flush().unwrap();
                                }
                                break;
                            } else {
                                send += data_len as u64;
                                if cfg!(feature = "printout") {
                                    print!(".");
                                    io::stdout().flush().unwrap();
                                }

                                if send >= amount_in_bytes {
                                    recv_answer = true;
                                    break;
                                }
                            }
                        } else if socket.can_send() && send < amount_in_bytes {
                            if !nocopy && (send + bufsize as u64 > amount_in_bytes) {
                                outp.resize((amount_in_bytes - send) as usize, 0);
                            }
                            if nocopy {
                                let siz = if send + bufsize as u64 > amount_in_bytes {
                                    (amount_in_bytes - send) as usize
                                } else {
                                    bufsize
                                };
                                let write = socket
                                    .send(|buffer| {
                                        if buffer.len() > siz {
                                            (siz, siz)
                                        } else {
                                            (buffer.len(), buffer.len())
                                        }
                                    })
                                    .unwrap();
                                send += write as u64;
                            } else {
                                let write = socket.send_slice(&outp).unwrap();
                                send += write as u64;
                            }
                            if cfg!(feature = "printout") {
                                println!("({})", send);
                            }
                            if send >= amount_in_bytes {
                                recv_answer = true;
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                } else if recv_answer {
                    let mut bytes_to_read = 0;
                    socket
                        .recv(|buffer| {
                            let r = if buffer.len() >= 8 {
                                bytes_to_read = from_array(&buffer[..8]);
                                if cfg!(feature = "printout") {
                                    print!("wait for {}", bytes_to_read);
                                    io::stdout().flush().unwrap();
                                }
                                8
                            } else {
                                if cfg!(feature = "printout") {
                                    print!("(no enough data)");
                                    io::stdout().flush().unwrap();
                                }
                                0
                            };
                            (r, ())
                        })
                        .unwrap();
                    if bytes_to_read > 0 {
                        assert!(amount_in_bytes == bytes_to_read);
                        let duration = start.elapsed();
                        let sec = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
                        println!(
                            "MBit/s {}, send {} bytes",
                            send as f64 / 1000f64 / 1000f64 * 8f64 / sec,
                            send
                        );

                        socket.close();
                    }
                }
            } else if socket.may_send() {
                println!("closed");
                socket.close();
            }
        }

        if waiting_poll {
            phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
        }
    }
}
