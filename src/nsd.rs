extern crate bytes;
#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate failure;
extern crate futures;
#[macro_use]
extern crate log;
extern crate pepbut;
extern crate rmp;
extern crate tokio_core;
extern crate users;

use bytes::{Buf, BufMut};
use env_logger::Builder;
use failure::ResultExt;
use futures::{Sink, Stream};
use log::LevelFilter;
use pepbut::name::Name;
use pepbut::wire::{ProtocolEncode, QueryMessage, ResponseBuffer, ResponseMessage};
use pepbut::zone::{LookupResult, Zone};
use std::collections::hash_map::{self, HashMap};
use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use tokio_core::net::{UdpCodec, UdpSocket};
use tokio_core::reactor::Core;

#[derive(Debug)]
struct FormatError {
    id: u16,
}

fn encode_err(id: u16, rcode: u8, buf: &mut Vec<u8>) {
    // ID
    buf.put_u16_be(id);
    // QR + Opcode + AA + TC + RD
    buf.put_u8(0b1000_0000_u8);
    // RA + Z + RCODE (2: SERVFAIL)
    buf.put_u8(rcode);
    // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    buf.put_u64_be(0);
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

    /// A minimal version of [`Zone::read_from`] which reads just the origin and serial to
    /// determine if a full load is necessary.
    fn load_zone(&mut self, reader: &mut (impl Read + Seek)) -> Result<(), failure::Error> {
        let partial_state = Zone::read_from_stage1(reader)?;
        match self.zones.entry(partial_state.origin.clone()) {
            hash_map::Entry::Occupied(mut entry) => {
                let current_serial = entry.get().serial;
                if current_serial < partial_state.serial {
                    let new_zone = Zone::read_from_stage2(partial_state, reader)?;
                    info!(
                        "updated zone {}, serial {}",
                        new_zone.origin, new_zone.serial
                    );
                    entry.insert(new_zone);
                } else {
                    warn!(
                        "ignored update to {}, new serial {}, current serial {}",
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
        info!("loading zone {}", path.as_ref().display());
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
}

struct NameServer<'a>(PhantomData<&'a ()>);

impl<'a> NameServer<'a> {
    fn new() -> NameServer<'a> {
        NameServer(PhantomData)
    }
}

impl<'a> UdpCodec for NameServer<'a> {
    type In = (SocketAddr, Result<QueryMessage, FormatError>);
    type Out = (SocketAddr, Result<ResponseMessage<'a>, FormatError>);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        if buf.len() < 2 {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok((
                *src,
                QueryMessage::decode(buf).map_err(|_| FormatError {
                    id: Cursor::new(buf).get_u16_be(),
                }),
            ))
        }
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (addr, msg) = msg;
        match msg {
            Ok(msg) => {
                if let Err(err) = msg.encode(&mut ResponseBuffer::new(buf)) {
                    // At this point we've had a rare error in ResponseMessage::encode
                    // Write out a SERVFAIL response
                    warn!(
                        "ResponseMessage::encode failed: err = {:?}, msg = {:?}",
                        err, msg
                    );
                    buf.clear();
                    encode_err(msg.query.id, 2, buf);
                }
            }
            Err(FormatError { id }) => encode_err(id, 1, buf),
        };
        addr
    }
}

fn main() -> Result<(), failure::Error> {
    let matches = clap_app!(nsd =>
        (@arg LISTEN_ADDR: -l --listen +takes_value "ipaddr:port to listen on (default [::]:53)")
        (@arg verbose: -v ... "Sets verbosity level (max: 3)")
    ).get_matches();

    {
        let level = matches.occurrences_of("verbose");
        let mut builder = Builder::new();
        if level >= 3 {
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

    let mut core = Core::new().context("Failed to create tokio Core")?;
    let addr_str = matches.value_of("LISTEN_ADDR").unwrap_or("[::]:53");
    let addr = SocketAddr::from_str(addr_str)
        .context(format!("Could not parse LISTEN_ADDR: {}", addr_str))?;
    let sock = UdpSocket::bind(&addr, &core.handle())
        .with_context(|e| format!("Failed to bind to socket: {}", e))?;
    info!("pepbut nsd listening on {}", addr);

    let mut authority = Authority::new();
    // FIXME temporary until we have dynamic zone loading
    authority.load_zonefile("tests/data/example.invalid.zone")?;

    let (udp_sink, udp_stream) = sock.framed(NameServer::new()).split();
    core.run({
        let udp_stream = udp_stream.map(|(addr, query)| {
            (
                addr,
                match query {
                    Ok(query) => {
                        let name = query.name.clone();
                        let record_type = query.record_type;
                        Ok(query.respond(match authority.find_zone(&name) {
                            Some(zone) => zone.lookup(&name, record_type),
                            None => LookupResult::NoZone,
                        }))
                    }
                    Err(err) => Err(err),
                },
            )
        });
        udp_sink.send_all(udp_stream)
    })?;
    Ok(())
}
