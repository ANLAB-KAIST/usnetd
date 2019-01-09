use super::{from_array, to_array};
use std::io::prelude::*;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

pub fn client(host: &str, bufsize: usize, nodelay: bool, amount: u64, reverse: bool) {
    // equals nc localhost 8080 < /dev/zero
    println!("Client, send buffer size {}", bufsize);
    let mut stream = TcpStream::connect(format!("{}:8080", host)).unwrap();
    stream
        .set_nodelay(nodelay)
        .expect("can not change nodelay setting");
    let mut outp = vec![0; bufsize];
    let mut send: u64 = 0;
    let start = Instant::now();
    let amount_in_bytes = amount * 1000u64;
    let _ = stream.write(&to_array(amount_in_bytes)).unwrap();
    stream.flush().unwrap();
    while send < amount_in_bytes {
        if !reverse {
            if send + bufsize as u64 > amount_in_bytes {
                outp.resize((amount_in_bytes - send) as usize, 0);
            }
            let write = stream.write(&outp).expect("write error");
            if write == 0 {
                println!("nothing written");
                break;
            }
            send += write as u64;
            if cfg!(feature = "printout") {
                print!(".");
                io::stdout().flush().unwrap();
            }
        } else {
            if send + bufsize as u64 > amount_in_bytes {
                outp.resize((amount_in_bytes - send) as usize, 0);
                if cfg!(feature = "printout") {
                    print!("REDUCED");
                    io::stdout().flush().unwrap();
                }
            }
            match stream.read(&mut outp) {
                Ok(0) => {
                    println!("lost connection");
                    break;
                }
                Ok(read) => {
                    send += read as u64;
                    if cfg!(feature = "printout") {
                        println!("({})", send);
                    }
                }
                Err(e) => {
                    println!("read error: {}", e);
                    break;
                }
            };
        }
    }
    if cfg!(feature = "printout") {
        print!("ReadAmount");
        io::stdout().flush().unwrap();
    }
    stream.flush().unwrap();
    let mut xamount = vec![0; 8];
    assert!(stream.read(&mut xamount).expect("reading amount") == 8);
    let bytes_to_read = from_array(&xamount[..8]);
    assert_eq!(amount_in_bytes, bytes_to_read);
    let duration = start.elapsed();
    let sec = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
    println!(
        "MBit/s {}, send {} bytes",
        send as f64 / 1000f64 / 1000f64 * 8f64 / sec,
        send
    );
}

pub fn server(bufsize: usize, reverse: bool) {
    println!("Server, read buffer size {}", bufsize);
    let listener = TcpListener::bind(format!("0.0.0.0:8080")).unwrap();
    for streamres in listener.incoming() {
        println!("new connection");
        let mut stream = streamres.unwrap();
        let mut inp = vec![0; bufsize];
        let mut amount = vec![0; 8];
        assert!(stream.read(&mut amount).unwrap() == 8);
        let bytes_to_read = from_array(&amount[..8]);
        let mut recv: u64 = 0;
        let start = Instant::now(); // assumes that sending will directly start
        while recv < bytes_to_read {
            if reverse {
                if recv + bufsize as u64 > bytes_to_read {
                    inp.resize((bytes_to_read - recv) as usize, 0);
                }
                let write = stream.write(&inp).expect("write error"); // stream.flush().unwrap();
                if write == 0 {
                    println!("nothing written");
                    break;
                }
                recv += write as u64;
            } else {
                match stream.read(&mut inp) {
                    Ok(0) => {
                        println!("lost connection");
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
        let payl = to_array(recv);
        assert_eq!(payl.len(), stream.write(&payl).expect("final write error"));
        stream.flush().unwrap();
        let duration = start.elapsed();
        let sec = duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9;
        println!(
            "MBit/s {}, read {} bytes",
            recv as f64 / 1000f64 / 1000f64 * 8f64 / sec,
            recv
        );
    }
}
