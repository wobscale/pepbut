// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self, stutter))]

extern crate clap;
extern crate env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
extern crate pepbut;
extern crate pepbut_nsd;
extern crate safeword;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_jsoncodec;
extern crate tokio_uds;
extern crate users;

use clap::{App, Arg};
use env_logger::Builder;
use failure::ResultExt;
use log::LevelFilter;
use pepbut::authority::Authority;
use pepbut_nsd::{codec::DnsCodec, ctl};
use safeword::{Safeword, Shutdown};
use std::fs;
use std::net::SocketAddr;
use std::process;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::{future, Future, Sink, Stream};
use tokio_codec::Decoder;
use tokio_jsoncodec::Codec as JsonCodec;
use tokio_uds::UnixListener;

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
                )).takes_value(true),
        ).arg(
            Arg::with_name("socket_path")
                .short("s")
                .long("socket")
                .value_name("SOCKET_PATH")
                .help(&format!(
                    "Unix control socket to listen on (default {})",
                    DEFAULT_SOCKET_PATH
                )).takes_value(true),
        ).arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Sets verbosity level (max: -vvv)"),
        ).arg(
            Arg::with_name("ZONEFILE")
                .help("Zone files to load on start")
                .multiple(true),
        ).get_matches();

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
    let tcp_listener = TcpListener::bind(&addr)
        .with_context(|e| format!("Failed to bind to TCP socket on {}: {}", addr, e))?;
    let udp_socket = UdpSocket::bind(&addr)
        .with_context(|e| format!("Failed to bind to UDP socket on {}: {}", addr, e))?;

    let ctl_socket_path = matches
        .value_of("socket_path")
        .unwrap_or(DEFAULT_SOCKET_PATH);
    let ctl_listener = UnixListener::bind(ctl_socket_path).with_context(|e| {
        format!(
            "Failed to bind to Unix socket at {}: {}",
            ctl_socket_path, e
        )
    })?;

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

    let futs: Vec<Box<Future<Item = (), Error = ()> + Send>> = vec![
        // TCP server
        Box::new({
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
                }).map_err(|e| error!("error in TCP server: {:?}", e))
        }),
        // UDP server
        Box::new({
            let authority = authority.clone();
            let (sink, stream) = UdpFramed::new(udp_socket, DnsCodec::udp()).split();
            sink.send_all(
                stream.map(move |(b, addr)| (authority.read().unwrap().process_message(b), addr)),
            ).map(|_| ())
            .map_err(|e| error!("error in UDP server: {:?}", e))
        }),
        // Control server
        Box::new({
            ctl_listener
                .incoming()
                .for_each(move |stream| {
                    let authority = authority.clone();
                    let (sink, stream) = JsonCodec::default().framed(stream).split();
                    tokio::spawn(
                        sink.send_all(
                            stream.map(move |request| ctl::handle_request(request, &authority)),
                        ).map(|_| ())
                        .map_err(|e| error!("error in control server: {:?}", e)),
                    );
                    Ok(())
                }).map_err(|e| error!("error in control server: {:?}", e))
        }),
    ];

    if let Err(shutdown) = Safeword::default().run(future::select_all(futs)) {
        match shutdown {
            Shutdown::FutureFinished(_) | Shutdown::FutureErr(_) => bail!("unexpected shutdown!"),
            Shutdown::NoRuntime(err) | Shutdown::SignalError(err) => Err(failure::Error::from(err)),
        }
    } else {
        fs::remove_file(ctl_socket_path)
            .with_context(|_| format!("failed to remove control socket {}", ctl_socket_path))?;
        Ok(())
    }
}
