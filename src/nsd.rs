extern crate bytes;
extern crate cast;
#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate failure;
#[macro_use]
extern crate log;
extern crate pepbut;
extern crate tokio;
extern crate tokio_io;
extern crate users;

use bytes::{Buf, BufMut, Bytes, BytesMut, IntoBuf};
use cast::u16;
use env_logger::Builder;
use failure::ResultExt;
use log::LevelFilter;
use pepbut::authority::Authority;
use pepbut::wire::encode_err;
use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio_io::codec::{Decoder, Encoder};

/// Implements [`Encoder`] and [`Decoder`].
///
/// TCP messages start with a 2-byte length marker, so we get to handle those differently.
enum DnsCodec {
    Tcp { len: Option<u16> },
    Udp,
}

impl DnsCodec {
    fn tcp() -> DnsCodec {
        DnsCodec::Tcp { len: None }
    }

    fn udp() -> DnsCodec {
        DnsCodec::Udp
    }
}

impl Decoder for DnsCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        Ok(match self {
            DnsCodec::Tcp {
                len: ref mut self_len,
            } => {
                let len = match self_len {
                    Some(len) => *len,
                    None => {
                        if src.len() >= 2 {
                            src.split_to(2).into_buf().get_u16_be()
                        } else {
                            return Ok(None);
                        }
                    }
                };
                if src.len() >= (len as usize) {
                    *self_len = None;
                    Some(src.split_to(len as usize).freeze())
                } else {
                    *self_len = Some(len);
                    None
                }
            }
            DnsCodec::Udp => {
                if src.is_empty() {
                    None
                } else {
                    Some(src.take().freeze())
                }
            }
        })
    }
}

impl Encoder for DnsCodec {
    type Item = Bytes;
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        if let DnsCodec::Tcp { .. } = self {
            match u16(item.len()) {
                Ok(len) => {
                    dst.reserve(2);
                    dst.put_u16_be(len);
                }
                Err(_) => {
                    dst.reserve(8);
                    dst.put(encode_err(Cursor::new(item).get_u16_be(), 2));
                    return Ok(());
                }
            }
        }
        dst.reserve(item.len());
        dst.put(&item);
        Ok(())
    }
}

fn main() -> Result<(), failure::Error> {
    // Command line argument parsing
    let matches = clap_app!(nsd =>
        (@arg LISTEN_ADDR: -l --listen +takes_value "ipaddr:port to listen on (default [::]:53)")
        (@arg verbose: -v ... "Sets verbosity level (max: 3)")
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

    let addr_str = matches.value_of("LISTEN_ADDR").unwrap_or("[::]:53");
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

    tokio::run(tcp_server.select(udp_server).map(|_| ()).map_err(|_| ()));
    Err(failure::err_msg("core shutdown!"))
}
