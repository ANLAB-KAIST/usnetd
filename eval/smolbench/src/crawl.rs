use rand;
use smoltcp::phy::wait as phy_wait;
use smoltcp::socket::SocketSet;
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant; // Duration
use smoltcp::wire::IpAddress;
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::str;
use std::str::FromStr;
use std::time::Duration;

use std::io::prelude::*;

use twoway::find_bytes;

#[cfg(feature = "multi")]
use usnet_sockets::apimultithread::{TcpStream, UsnetToSocketAddrs};

#[cfg(feature = "single")]
use usnet_sockets::apisinglethread::TcpStream;

#[cfg(feature = "host")]
use std::net::TcpStream;

use usnet_sockets::usnetconfig::StcpBackend;

use serde_json;
use std::env;

#[cfg(not(feature = "single"))]
use std::thread;

#[cfg(not(feature = "single"))]
use std::sync::Arc;

#[cfg(not(feature = "single"))]
pub fn run(
    host: &str,
    path: &str,
    times: usize,
    parallel: usize,
    printing: bool,
    outfile: Option<String>,
    hostname: Option<String>,
) {
    run_h(
        Arc::new(Box::new(host.to_string())),
        Arc::new(Box::new(path.to_string())),
        times,
        parallel,
        printing,
        outfile,
        hostname,
    );
}
#[cfg(not(feature = "single"))]
pub fn run_h(
    host: Arc<Box<String>>,
    path: Arc<Box<String>>,
    times: usize,
    parallel: usize,
    printing: bool,
    outfile: Option<String>,
    hostname: Option<String>,
) {
    let mut handles = vec![];
    for _ in 0..parallel {
        let host_string = host.clone();
        let path_string = path.clone();
        let outfile_clone = outfile.clone();
        let hostname_clone = hostname.clone();
        let h = thread::spawn(move || {
            for _ in 0..times / parallel {
                handle_connection(
                    &host_string,
                    &path_string,
                    printing,
                    &outfile_clone,
                    &hostname_clone,
                );
            }
        });
        handles.push(h);
    }
    host.len();
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(feature = "single")]
pub fn run(
    host: &str,
    path: &str,
    times: usize,
    _parallel: usize,
    printing: bool,
    outfile: Option<String>,
    hostname: Option<String>,
) {
    for _ in 0..times {
        handle_connection(host, path, printing, &outfile, &hostname);
    }
}

fn handle_connection(
    host: &str,
    path: &str,
    printing: bool,
    outfile: &Option<String>,
    hostname: &Option<String>,
) {
    let mut stream = TcpStream::connect_timeout(&host.usnet_to_socket_addrs().unwrap().next().unwrap(), Duration::from_secs(10)).expect("Test DNS resolution or add REDUCE_MTU_BY=160");
    eprintln!("connected");
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path,
        hostname.as_ref().unwrap_or(&host.to_string())
    );
    stream.write_all(req.as_ref()).expect("cannot write");
    stream.flush().unwrap();
    let mut outp = vec![0; 1024];
    let mut reading_header = true;
    let mut writefile = if let Some(ref dumppath) = outfile {
        File::create(&dumppath).ok()
    } else {
        None
    };
    loop {
        match stream.read(&mut outp) {
            // could also use read_to_end/string but we want to see incoming data immediately
            Ok(0) => {
                eprintln!("reading EOF");
                break;
            }
            Ok(r) => {
                let mut content_start = 0;
                if reading_header {
                    if let Some(end) = find_bytes(&outp[..r], "\r\n\r\n".as_bytes()) {
                        content_start = end + 4;
                        reading_header = false;
                        eprintln!(
                            "{}",
                            str::from_utf8(&outp[..content_start]).unwrap_or("(invalid utf8)")
                        );
                    } else {
                        eprintln!("{}", str::from_utf8(&outp[..r]).unwrap_or("(invalid utf8)"));
                    }
                }
                // can now be true
                if !reading_header {
                    if printing {
                        print!(
                            "{}",
                            str::from_utf8(&outp[content_start..r]).unwrap_or("(invalid utf8)")
                        );
                    }
                    if let Some(ref mut dumpfile) = writefile {
                        eprintln!("writing {} bytes to file", r);
                        dumpfile
                            .write_all(&outp[content_start..r])
                            .expect("cannot write to file");
                    }
                }
            }
            Err(e) => {
                panic!("err: {}", e);
            }
        };
    }
    eprintln!("done, stream closed");
}

pub fn run2(host: &str, path: &str) {
    println!("small HTTP example");
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

    let socket_buffer_size =
        usize::from_str(&env::var("SOCKET_BUFFER").unwrap_or("500000".to_string()))
            .expect("SOCKET_BUFFER not an usize");
    let tcp_rx_buffer = TcpSocketBuffer::new(vec![0; socket_buffer_size]);
    let tcp_tx_buffer = TcpSocketBuffer::new(vec![0; socket_buffer_size]);
    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);

    let mut sockets = SocketSet::new(vec![]);
    let tcp_handle = sockets.add(tcp_socket);

    enum State {
        Connect,
        Request,
        Response,
    };
    let mut state = State::Connect;

    loop {
        let timestamp = Instant::now();
        let _ = iface.poll(&mut sockets, timestamp);

        {
            let mut socket = sockets.get::<TcpSocket>(tcp_handle);

            state = match state {
                State::Connect if !socket.is_active() => {
                    println!("connecting");
                    let local_port = 49152 + rand::random::<u16>() % 16384;
                    let addr = host.to_socket_addrs().unwrap().next().unwrap();
                    let ip_oct = match addr.ip() {
                        IpAddr::V4(ip) => ip.octets(),
                        _ => [0, 0, 0, 0],
                    };
                    socket
                        .connect(
                            (
                                IpAddress::v4(ip_oct[0], ip_oct[1], ip_oct[2], ip_oct[3]),
                                addr.port(),
                            ),
                            local_port,
                        )
                        .unwrap();
                    State::Request
                }
                State::Request if socket.may_send() && socket.may_recv() => {
                    println!("sending request");
                    let http_get = "GET ".to_owned() + path + " HTTP/1.1\r\n";
                    socket.send_slice(http_get.as_ref()).expect("cannot send");
                    let http_host = "Host: ".to_owned() + host + "\r\n";
                    socket.send_slice(http_host.as_ref()).expect("cannot send");
                    socket
                        .send_slice(b"Connection: close\r\n")
                        .expect("cannot send");
                    socket.send_slice(b"\r\n").expect("cannot send");
                    State::Response
                }
                State::Response if socket.can_recv() => {
                    socket
                        .recv(|data| {
                            print!("{}", str::from_utf8(data).unwrap_or("(invalid utf8)"));
                            (data.len(), ())
                        })
                        .unwrap();
                    State::Response
                }
                State::Response if !socket.may_recv() => {
                    println!("received complete response");
                    break;
                }
                _ => state,
            }
        }

        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
