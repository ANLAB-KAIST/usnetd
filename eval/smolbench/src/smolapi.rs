use super::{from_array, to_array};
use std::cmp::min;
use std::time::Instant;

use std::io::prelude::*;
use std::io::Write;

#[cfg(not(feature = "single"))]
use std::thread;

#[cfg(not(feature = "single"))]
use std::sync::Arc;

#[cfg(feature = "multi")]
use usnet_sockets::apimultithread::{TcpListener, TcpStream};

#[cfg(feature = "single")]
use usnet_sockets::apisinglethread::{TcpListener, TcpStream};

#[cfg(feature = "host")]
use std::net::{TcpListener, TcpStream};

#[cfg(feature = "host")]
use smoltcp;

#[cfg(feature = "host")]
pub trait NoCopyTcpStream {
    fn write_no_copy<F, R>(&mut self, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> (usize, R);
    fn read_no_copy<F, R>(&mut self, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> (usize, R);
}

// copying fallbacks for the OS TCP socket
#[cfg(feature = "host")]
impl NoCopyTcpStream for TcpStream {
    fn write_no_copy<F, R>(&mut self, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> (usize, R),
    {
        let mut g = vec![0; 8];
        let (u, r) = f(&mut g[..]);
        match self.write_all(&g[..u]) {
            Ok(_) => Ok(r),
            _ => Err(smoltcp::Error::Exhausted),
        }
    }
    fn read_no_copy<F, R>(&mut self, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> (usize, R),
    {
        let mut g = vec![0; 8];
        match self.peek(&mut g[..]) {
            Ok(v) => {
                g.resize(v, 0);
                let (u, r) = f(&mut g[..]);
                match self.read(&mut g[..u]) {
                    Ok(k) if k == u => Ok(r),
                    _ => Err(smoltcp::Error::Exhausted),
                }
            }
            _ => Err(smoltcp::Error::Exhausted),
        }
    }
}

fn handle_server_connection(
    mut stream: TcpStream,
    count: usize,
    bufsize: usize,
    reverse: bool,
    zapi: bool,
) {
    println!("new connection {}", count);
    let mut inp = vec![0; bufsize];
    let mut amount = vec![0; 8];
    assert!(stream.read(&mut amount).expect("not 8 bytes") == 8);
    let bytes_to_read = from_array(&amount[..8]);
    let mut recv: u64 = 0;
    let start = Instant::now(); // assumes that sending will directly start
    while recv < bytes_to_read {
        if reverse {
            if recv + bufsize as u64 > bytes_to_read {
                inp.resize((bytes_to_read - recv) as usize, 0);
            }
            let write = if zapi {
                stream
                    .write_no_copy(|buffer| {
                        let w = min(buffer.len(), inp.len());
                        (w, w)
                    })
                    .expect("write nc error")
            } else {
                stream.write(&inp).expect("write error")
            };
            if write == 0 {
                println!("nothing written");
                break;
            }
            recv += write as u64;
        } else {
            if zapi {
                match stream.read_no_copy(|buffer| {
                    let r = min(buffer.len(), inp.len());
                    (r, r)
                }) {
                    Ok(0) => {
                        println!("lost connection {}", count);
                        break;
                    }
                    Ok(read) => {
                        recv += read as u64;
                    }
                    Err(e) => {
                        println!("read zc error: {}", e);
                        break;
                    }
                };
            } else {
                match stream.read(&mut inp) {
                    Ok(0) => {
                        println!("lost connection {}", count);
                        break;
                    }
                    Ok(read) => {
                        recv += read as u64;
                    }
                    Err(e) => {
                        println!("read error: {}", e);
                        break;
                    }
                };
            }
        }
    }
    let payl = to_array(recv);
    assert_eq!(payl.len(), stream.write(&payl).expect("final write error"));
    stream.flush().expect("flush error");
    let duration = start.elapsed();
    let sec = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
    println!(
        "MBit/s {}, read {} bytes (connection {})",
        recv as f64 / 1000f64 / 1000f64 * 8f64 / sec,
        recv,
        count
    );
}

#[cfg(not(feature = "single"))]
fn handle_connection_impl(
    stream: TcpStream,
    count: usize,
    bufsize: usize,
    reverse: bool,
    zapi: bool,
) {
    thread::spawn(move || {
        handle_server_connection(stream, count, bufsize, reverse, zapi);
    });
}

#[cfg(feature = "single")]
fn handle_connection_impl(
    stream: TcpStream,
    count: usize,
    bufsize: usize,
    reverse: bool,
    zapi: bool,
) {
    handle_server_connection(stream, count, bufsize, reverse, zapi);
}

pub fn run(bufsize: usize, reverse: bool, zapi: bool) {
    println!("Server, read buffer size {}", bufsize);
    let listener = TcpListener::bind(format!("0.0.0.0:8080")).expect("no listener");
    let mut count = 0;
    for streamres in listener.incoming() {
        count += 1;
        handle_connection_impl(streamres.expect("no result"), count, bufsize, reverse, zapi);
    }
}

pub fn client_connection(
    host: &str,
    bufsize: usize,
    amount: u64,
    reverse: bool,
    zapi: bool,
    count: usize,
) {
    println!("Client {}, send buffer size {}", count, bufsize);
    let mut stream = TcpStream::connect(format!("{}:8080", host)).expect("no connection");
    let mut outp = vec![0; bufsize];
    let mut send: u64 = 0;
    let start = Instant::now();
    let amount_in_bytes = amount * 1000u64;
    let _ = stream
        .write(&to_array(amount_in_bytes))
        .expect("initial write error");
    stream.flush().expect("flush error");
    while send < amount_in_bytes {
        if !reverse {
            if send + bufsize as u64 > amount_in_bytes {
                outp.resize((amount_in_bytes - send) as usize, 0);
            }
            let write = if zapi {
                stream
                    .write_no_copy(|buffer| {
                        let w = min(buffer.len(), outp.len());
                        (w, w)
                    })
                    .expect("write nc error")
            } else {
                stream.write(&outp).expect("write error")
            };
            if write == 0 {
                println!("nothing written");
                break;
            }
            send += write as u64;
        } else {
            if send + bufsize as u64 > amount_in_bytes {
                outp.resize((amount_in_bytes - send) as usize, 0);
            }

            if zapi {
                match stream.read_no_copy(|buffer| {
                    let r = min(buffer.len(), outp.len());
                    (r, r)
                }) {
                    Ok(0) => {
                        println!("lost connection {}", count);
                        break;
                    }
                    Ok(read) => {
                        send += read as u64;
                    }
                    Err(e) => {
                        println!("read zc error: {}", e);
                        break;
                    }
                };
            } else {
                match stream.read(&mut outp) {
                    Ok(0) => {
                        println!("lost connection {}", count);
                        break;
                    }
                    Ok(read) => {
                        send += read as u64;
                    }
                    Err(e) => {
                        println!("read error: {}", e);
                        break;
                    }
                };
            }
        }
    }
    stream.flush().expect("flush error at end");
    let mut xamount = vec![0; 8];
    assert!(stream.read(&mut xamount).expect("not 8 bytes") == 8);
    let bytes_to_read = from_array(&xamount[..8]);
    assert_eq!(amount_in_bytes, bytes_to_read);
    let duration = start.elapsed();
    let sec = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
    println!(
        "MBit/s {}, send {} bytes (connection {})",
        send as f64 / 1000f64 / 1000f64 * 8f64 / sec,
        send,
        count
    );
}

#[cfg(not(feature = "single"))]
pub fn client(parallel: u16, host: &str, bufsize: usize, amount: u64, reverse: bool, zapi: bool) {
    client_h(
        parallel,
        Arc::new(Box::new(host.to_string())),
        bufsize,
        amount,
        reverse,
        zapi,
    );
}
#[cfg(not(feature = "single"))]
pub fn client_h(
    parallel: u16,
    host: Arc<Box<String>>,
    bufsize: usize,
    amount: u64,
    reverse: bool,
    zapi: bool,
) {
    let mut handles = vec![];
    for c in 0..parallel {
        let host_string = host.clone();
        let h = thread::spawn(move || {
            client_connection(&host_string, bufsize, amount, reverse, zapi, c as usize + 1);
        });
        handles.push(h);
    }
    host.len();
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(feature = "single")]
pub fn client(_parallel: u16, host: &str, bufsize: usize, amount: u64, reverse: bool, zapi: bool) {
    client_connection(host, bufsize, amount, reverse, zapi, 1);
}
