extern crate usnet_sockets;

extern crate smoltcp;
#[macro_use]
extern crate clap;
use std::str::FromStr;

extern crate env_logger;
extern crate rand;

extern crate serde_json;

extern crate twoway;

mod smolapi;
mod smolserver;

mod crawl;
mod defaultserver;
mod httpd;

fn to_array(n: u64) -> [u8; 8] {
    let b1: u8 = ((n >> 56) & 0xff) as u8;
    let b2: u8 = ((n >> 48) & 0xff) as u8;
    let b3: u8 = ((n >> 40) & 0xff) as u8;
    let b4: u8 = ((n >> 32) & 0xff) as u8;
    let b5: u8 = ((n >> 24) & 0xff) as u8;
    let b6: u8 = ((n >> 16) & 0xff) as u8;
    let b7: u8 = ((n >> 8) & 0xff) as u8;
    let b8: u8 = (n & 0xff) as u8;
    [b1, b2, b3, b4, b5, b6, b7, b8]
}

fn from_array(a: &[u8]) -> u64 {
    let mut r: u64 = 0;
    for i in 0..8 {
        r <<= 8;
        r += a[i] as u64;
    }
    r
}

fn main() {
    env_logger::init();
    let matches = clap::App::new("simple benchmark on port 8080")
        .version(crate_version!())
        .args_from_usage("-b=[SIZE]           'The R/W buffer size'
                          --reverse           'Server sends data'")
        .subcommand(
            clap::SubCommand::with_name("client")
                .about("Run in client mode (via Linux host if not --api, otherwise env USNET_SOCKETS config)")
                .args_from_usage(
                    "<HOST>                  'The host for the client'
                     --delay                 'Disable nodelay (socket buffer), not yet for --api'
                     --amount=[SIZE]         'Amount to send in KB'",
                ).args_from_usage("--api     'Use blocking API (USNET_SOCKETS backend config)'")
                .args_from_usage("-x=[SIZE] 'Ringbuffer size (not --api)'")
                .args_from_usage("-p=[THREADS]                   'Parallel queries (requires multithread api)'")
                .args_from_usage("--nocopy     'Use (non-compatible) zero-copy blocking API (USNET_SOCKETS backend config)'")
                .args_from_usage("--smoltcp-no-api  'Use original smoltcp functions (-x is missing)'"),
        )
        .subcommand(clap::SubCommand::with_name("server").about(
            "Run in Linux socket server mode (default)"
        ))
        .subcommand(
            clap::SubCommand::with_name("smoltcp")
                .about("Run in smoltcp server (env var USNET_SOCKETS config)")
                .args_from_usage("-x=[SIZE] 'Ringbuffer size (not --api)'")
                .args_from_usage("--api     'Use blocking API'")
                .args_from_usage("--nocopy     'Use (non-compatible) zero-copy blocking API'"),
        )
        .subcommand(
            clap::SubCommand::with_name("crawl")
            .about("Fetch HTTP (USNET_SOCKETS backend config)")
            .args_from_usage("<ADDRESS>                  'addr:port (can use domain name when system resolver works, otherwise provide IP and use -h)'")
            .args_from_usage("[PATH]                  'HTTP path like /'")
            .args_from_usage("-d=[HOSTNAME]                   'Set hostname for HTTP request (adding :port is optional'")
            .args_from_usage("-t=[AMOUNT]                   'Number of queries'")
            .args_from_usage("-p=[THREADS]                   'Parallel queries'")
            .args_from_usage("-q                             'Do not print answers'")
            .args_from_usage("-o=[OUTFILE]                    'Dump response body to file'")
            .args_from_usage("--smoltcp-no-api     'Use original smoltcp functions (-x is missing)'")
        )
        .subcommand(
            clap::SubCommand::with_name("httpd")
            .about("Serve HTTP (USNET_SOCKETS backend config)")
            .args_from_usage("-a=[IP] 'Bind to IP (default 0.0.0.0)'")
            .args_from_usage("<PORT>                  'port'")
            .args_from_usage("-q                             'Do not print answers'")
        )
        .get_matches();
    let reverse = matches.is_present("reverse");
    let b = matches.value_of("b").unwrap_or("64");
    if let Some(clientmatches) = matches.subcommand_matches("client") {
        if clientmatches.is_present("api") {
            smolapi::client(
                u16::from_str(clientmatches.value_of("p").unwrap_or("1")).unwrap(),
                clientmatches.value_of("HOST").unwrap(),
                usize::from_str(b).unwrap(),
                u64::from_str(clientmatches.value_of("amount").unwrap_or("1000")).unwrap(),
                reverse,
                clientmatches.is_present("nocopy"),
            );
        } else if clientmatches.is_present("smoltcp-no-api") {
            smolserver::client(
                clientmatches.value_of("HOST").unwrap(),
                usize::from_str(b).unwrap(),
                u64::from_str(clientmatches.value_of("amount").unwrap_or("1000")).unwrap(),
                reverse,
                usize::from_str(clientmatches.value_of("x").unwrap_or("65535")).unwrap(),
            );
        } else {
            defaultserver::client(
                clientmatches.value_of("HOST").unwrap(),
                usize::from_str(b).unwrap(),
                !clientmatches.is_present("delay"),
                u64::from_str(clientmatches.value_of("amount").unwrap_or("1000")).unwrap(),
                reverse,
            );
        }
    } else if let Some(smoltcpmatches) = matches.subcommand_matches("smoltcp") {
        if !smoltcpmatches.is_present("api") {
            smolserver::run(
                usize::from_str(b).unwrap(),
                usize::from_str(smoltcpmatches.value_of("x").unwrap_or("65535")).unwrap(),
                reverse,
            );
        } else {
            smolapi::run(
                usize::from_str(b).unwrap(),
                reverse,
                smoltcpmatches.is_present("nocopy"),
            );
        }
    } else if let Some(crawlmatches) = matches.subcommand_matches("crawl") {
        if crawlmatches.is_present("smoltcp-no-api") {
            crawl::run2(
                crawlmatches.value_of("ADDRESS").unwrap(),
                crawlmatches.value_of("PATH").unwrap_or("/"),
            );
        } else {
            crawl::run(
                crawlmatches.value_of("ADDRESS").unwrap(),
                crawlmatches.value_of("PATH").unwrap_or("/"),
                usize::from_str(crawlmatches.value_of("t").unwrap_or("1")).unwrap(),
                usize::from_str(crawlmatches.value_of("p").unwrap_or("1")).unwrap(),
                !crawlmatches.is_present("q"),
                crawlmatches.value_of("o").map(|s| s.to_string()),
                crawlmatches.value_of("d").map(|s| s.to_string()),
            );
        }
    } else if let Some(httpdmatches) = matches.subcommand_matches("httpd") {
        let ip = httpdmatches.value_of("a").unwrap_or("0.0.0.0");
        httpd::run(
            ip,
            httpdmatches.value_of("PORT").unwrap(),
            !httpdmatches.is_present("q"),
        );
    } else {
        defaultserver::server(usize::from_str(b).unwrap(), reverse);
    }
}
