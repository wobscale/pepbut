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
use pepbut::name::Name;
use pepbut::wire::{ProtocolDecode, ProtocolEncode, QueryMessage};
use pepbut::zone::{LookupResult, Zone};
use std::collections::hash_map::{self, HashMap};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, UdpFramed, UdpSocket};
use tokio::prelude::*;
use tokio_io::codec::{Decoder, Encoder};

fn encode_err(id: u16, rcode: u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(8);
    // ID
    buf.put_u16_be(id);
    // QR + Opcode + AA + TC + RD
    buf.put_u8(0b1000_0000_u8);
    // RA + Z + RCODE
    buf.put_u8(rcode);
    // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    buf.put_u64_be(0);
    buf.freeze()
}

struct Authority {
    zones: HashMap<Name, Zone>,
}

impl Authority {
    fn new() -> Authority {
        Authority {
            zones: HashMap::new(),
        }
    }

    /// Conditionally loads a zone into the authority. The zone's origin and serial are used to
    /// determine if the update is required before parsing the rest of the zone.
    fn load_zone(&mut self, reader: &mut (impl Read + Seek)) -> Result<(), failure::Error> {
        let partial_state = Zone::read_from_stage1(reader)?;
        match self.zones.entry(partial_state.origin.clone()) {
            hash_map::Entry::Occupied(mut entry) => {
                let current_serial = entry.get().serial;
                // There are rules for zone serial rollovers but we are only running master servers
                // and we are not implementing AXFR so it really doesn't matter because we can just
                // restart the server. ¯\_(ツ)_/¯
                if current_serial < partial_state.serial {
                    let new_zone = Zone::read_from_stage2(partial_state, reader)?;
                    info!(
                        "updated zone {}, serial {}",
                        new_zone.origin, new_zone.serial
                    );
                    entry.insert(new_zone);
                } else {
                    warn!(
                        "ignored update to {}, loaded serial {}, current serial {}",
                        partial_state.origin, partial_state.serial, current_serial
                    );
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let zone = Zone::read_from_stage2(partial_state, reader)?;
                info!("inserted zone {}, serial {}", zone.origin, zone.serial);
                entry.insert(zone);
            }
        };
        Ok(())
    }

    fn load_zonefile<P: AsRef<Path>>(&mut self, path: P) -> Result<(), failure::Error> {
        info!("loading zone from {}", path.as_ref().display());
        self.load_zone(&mut File::open(path)?)
    }

    fn find_zone(&self, name: &Name) -> Option<&Zone> {
        let mut name = name.clone();
        while !name.is_empty() {
            if let Some(zone) = self.zones.get(&name) {
                return Some(zone);
            }
            name = name.pop();
        }
        None
    }

    fn process_message(&self, buf: Bytes) -> Bytes {
        let mut buf = Cursor::new(buf);
        let query = match QueryMessage::decode(&mut buf) {
            Ok(query) => query,
            Err(_) => return encode_err(buf.get_u16_be(), 1),
        };
        let name = query.name.clone();
        let record_type = query.record_type;
        let response = query.respond(match self.find_zone(&name) {
            Some(zone) => zone.lookup(&name, record_type),
            None => LookupResult::NoZone,
        });
        let mut buf = BytesMut::new();
        match response.encode(&mut buf, &mut HashMap::new()) {
            Ok(()) => Bytes::from(buf),
            Err(err) => {
                error!("{:?}", err);
                encode_err(response.query.id, 2)
            }
        }
    }
}

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
