extern crate clap;
extern crate env_logger;
extern crate failure;
#[macro_use]
extern crate log;
extern crate pepbut;
extern crate tokio;
extern crate tokio_io;
extern crate users;

use clap::{App, Arg};
use env_logger::Builder;
use failure::ResultExt;
use log::LevelFilter;
use pepbut::authority::Authority;
use pepbut::codec::DnsCodec;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio_io::codec::Decoder;

static DEFAULT_LISTEN_ADDR: &str = "[::]:53";

fn main() -> Result<(), failure::Error> {
    // Command line argument parsing
    let matches = App::new("nsd")
        .arg(
            Arg::with_name("listen_addr")
                .short("l")
                .long("listen")
                .value_name("LISTEN_ADDR")
                .help(&format!(
                    "ipaddr:port to listen on (default {})",
                    DEFAULT_LISTEN_ADDR
                ))
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Sets verbosity level (max: -vvv)"),
        )
        .get_matches();

    // Set log level from -v option
    {
        let level = matches.occurrences_of("verbose");
        let mut builder = Builder::new();
        if level >= 3 {
            // Enables all log messages across all crates
            builder.filter_level(LevelFilter::Trace)
        } else {
            let level = match level {
                0 => LevelFilter::Info,
                1 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            };
            builder
                .filter_module("pepbut", level)
                .filter_module("nsd", level)
        };
        builder.init();
    }

    if users::get_effective_uid() == 0 {
        error!("pepbut will not run as root!");
        error!("to listen on a privileged port, run `setcap cap_net_bind_service=+ep` on the nsd binary");
        ::std::process::exit(1);
    }

    let addr_str = matches
        .value_of("listen_addr")
        .unwrap_or(DEFAULT_LISTEN_ADDR);
    let addr = SocketAddr::from_str(addr_str)
        .context(format!("Could not parse LISTEN_ADDR: {}", addr_str))?;
    let tcp_listener =
        TcpListener::bind(&addr).with_context(|e| format!("Failed to bind to TCP socket: {}", e))?;
    let udp_socket =
        UdpSocket::bind(&addr).with_context(|e| format!("Failed to bind to UDP socket: {}", e))?;
    info!("pepbut nsd listening on {}", addr);

    let authority = Arc::new(RwLock::new(Authority::new()));
    // FIXME temporary until we have dynamic zone loading
    authority
        .write()
        .unwrap()
        .load_zonefile("tests/data/example.invalid.zone")?;

    macro_rules! select {
        ( $first:expr, $( $fut:expr ),* ) => {
            $first
            $(
                .select($fut).map(|_| ()).map_err(|_| ())
            )*
        };
    }

    let tcp_server = {
        let authority = authority.clone();
        tcp_listener
            .incoming()
            .for_each(move |tcp| {
                let authority = authority.clone();
                let (sink, stream) = DnsCodec::tcp().framed(tcp).split();
                tokio::spawn(
                    sink.send_all(
                        stream.map(move |b| authority.read().unwrap().process_message(b)),
                    ).map(|_| ())
                        .map_err(|e| error!("error in TCP server: {:?}", e)),
                );
                Ok(())
            })
            .map_err(|e| error!("error in TCP server: {:?}", e))
    };

    let udp_server = {
        let authority = authority.clone();
        let (sink, stream) = UdpFramed::new(udp_socket, DnsCodec::udp()).split();
        sink.send_all(
            stream.map(move |(b, addr)| (authority.read().unwrap().process_message(b), addr)),
        ).map(|_| ())
            .map_err(|e| error!("error in UDP server: {:?}", e))
    };

    tokio::run(select!(tcp_server, udp_server));
    Err(failure::err_msg("core shutdown!"))
}
