use std::io::prelude::*;
use std::str;

#[cfg(feature = "single")]
use usnet_sockets::apisinglethread::{TcpListener, TcpStream};

#[cfg(feature = "multi")]
use usnet_sockets::apimultithread::{TcpListener, TcpStream};

#[cfg(feature = "host")]
use std::net::{TcpListener, TcpStream};

#[cfg(not(feature = "single"))]
use std::thread;

pub fn run(bind_ip: &str, port: &str, printing: bool) {
    let listener = TcpListener::bind(bind_ip.to_owned() + ":" + port).unwrap();
    let content = "<!DOCTYPE html><html><head><title>smoltcp served html</title></head><body><b>Bold</b> font acbdefghijklmnop</body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r
Server: smoltcp
Content-Type: text/html; charset=utf-8\r
Content-Encoding: UTF-8\r
Content-Length: {}\r
Connection: close\r
\r
{}",
        content.len(),
        content
    );

    for streamres in listener.incoming() {
        handle_connection_impl(streamres.expect("no result"), resp.clone(), printing);
    }
}

fn handle_connection(mut stream: TcpStream, resp: String, printing: bool) {
    if printing {
        println!("new connection");
    }
    let mut inp = vec![0; 64000];
    let mut req = String::new();
    loop {
        let d = stream.read(&mut inp).unwrap();
        if d == 0 {
            return;
        }
        req += str::from_utf8(&inp[..d]).unwrap_or("(invalid utf8)");
        if req.ends_with("\r\n\r\n") {
            break;
        }
    }
    if printing {
        println!("{}", req);
    }
    stream.write_all(resp.as_ref()).expect("could not send");
    stream.flush().unwrap();
}

#[cfg(not(feature = "single"))]
fn handle_connection_impl(stream: TcpStream, resp: String, printing: bool) {
    thread::spawn(move || {
        handle_connection(stream, resp, printing);
    });
}

#[cfg(feature = "single")]
fn handle_connection_impl(stream: TcpStream, resp: String, printing: bool) {
    handle_connection(stream, resp, printing);
}
