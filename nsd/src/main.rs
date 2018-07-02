#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

extern crate bytes;
extern crate cast;
extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
#[macro_use]
extern crate pepbut;
extern crate pepbut_json_api;
extern crate regex;
extern crate serde_json;
extern crate tokio;
extern crate tokio_io;
extern crate tokio_signal;
extern crate tokio_uds;
extern crate users;

use clap::{App, Arg};
use env_logger::Builder;
use failure::ResultExt;
use hyper::Server;
use log::LevelFilter;
use pepbut::authority::Authority;
use std::fs;
use std::net::SocketAddr;
use std::process;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio_io::codec::Decoder;
use tokio_signal::unix::{Signal, SIGINT, SIGTERM};
use tokio_uds::UnixListener;

mod codec;
mod ctl;

use codec::DnsCodec;
use ctl::ControlService;

static DEFAULT_LISTEN_ADDR: &str = "[::]:53";
static DEFAULT_SOCKET_PATH: &str = "/run/pepbut/nsd.sock";

fn main() -> Result<(), failure::Error> {
    // Command line argument parsing
    let matches = App::new("pepbut-nsd")
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
            Arg::with_name("socket_path")
                .short("s")
                .long("socket")
                .value_name("SOCKET_PATH")
                .help(&format!(
                    "Unix control socket to listen on (default {})",
                    DEFAULT_SOCKET_PATH
                ))
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Sets verbosity level (max: -vvv)"),
        )
        .arg(
            Arg::with_name("ZONEFILE")
                .help("Zone files to load on start")
                .multiple(true),
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

    let ctl_socket_path = matches
        .value_of("socket_path")
        .unwrap_or(DEFAULT_SOCKET_PATH);
    let ctl_listener = UnixListener::bind(ctl_socket_path)
        .with_context(|e| format!("Failed to bind to Unix socket: {}", e))?;

    info!(
        "pepbut nsd listening on {}, control socket {}, PID {}",
        addr,
        ctl_socket_path,
        process::id()
    );

    let authority = Arc::new(RwLock::new(Authority::new()));
    if let Some(paths) = matches.values_of("ZONEFILE") {
        let mut authority = authority.write().unwrap();
        for path in paths {
            authority
                .load_zonefile(path)
                .context(format!("failed to load zone {}", path))?;
        }
    }

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

    let ctl_server = {
        let authority = authority.clone();
        Server::builder(ctl_listener.incoming())
            .serve(move || ControlService::new(authority.clone()))
            .map_err(|e| error!("error in control server: {:?}", e))
    };

    let clean_shutdown = Arc::new(AtomicBool::new(false));
    macro_rules! signal_handler {
        ($signal:expr) => {{
            let clean_shutdown = clean_shutdown.clone();
            Signal::new($signal)
                .flatten_stream()
                .into_future()
                .map(move |(s, _fut)| {
                    if let Some(s) = s {
                        info!("received signal {}, shutting down...", s);
                    } else {
                        error!("signal handler received None");
                        info!("shutting down...");
                    }
                    clean_shutdown.store(true, Ordering::Relaxed);
                })
                .map_err(|(e, _)| error!("error in signal handler: {:?}", e))
        }};
    }

    tokio::run(select!(
        tcp_server,
        udp_server,
        ctl_server,
        signal_handler!(SIGINT),
        signal_handler!(SIGTERM)
    ));
    if clean_shutdown.load(Ordering::Relaxed) {
        fs::remove_file(ctl_socket_path)
            .with_context(|_| format!("failed to remove control socket {}", ctl_socket_path))?;
        Ok(())
    } else {
        bail!("unexpected shutdown!");
    }
}
