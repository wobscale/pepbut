extern crate bytes;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate pepbut;
extern crate tokio_core;

use bytes::{Buf, BufMut};
use futures::{Sink, Stream};
use pepbut::name::Name;
use pepbut::wire::{ProtocolEncode, QueryMessage, ResponseBuffer, ResponseMessage};
use pepbut::zone::{LookupResult, Zone};
use std::collections::HashMap;
use std::io::{self, Cursor};
use std::marker::PhantomData;
use std::net::SocketAddr;
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

struct Authority(HashMap<Name, Zone>);

impl Authority {
    fn new() -> Authority {
        Authority(HashMap::new())
    }

    fn find_zone(&self, name: &Name) -> Option<&Zone> {
        let mut name = name.clone();
        while !name.is_empty() {
            if let Some(zone) = self.0.get(&name) {
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
                if let Err(err) = {
                    let mut resp_buf = ResponseBuffer::new(buf);
                    msg.encode(&mut resp_buf)
                } {
                    // At this point we've had a rare error in ResponseMessage::encode
                    // Write out a SERVFAIL response
                    warn!("failed to encode: msg = {:?}, err = {:?}", msg, err);
                    buf.clear();
                    encode_err(msg.query.id, 2, buf);
                }
            }
            Err(FormatError { id }) => encode_err(id, 1, buf),
        };
        addr
    }
}

fn main() {
    env_logger::init();

    let mut authority = Authority::new();
    authority.0.insert(
        Name::from_str("example.invalid").unwrap(),
        Zone::read_from(&mut Cursor::new(
            &include_bytes!("../tests/data/example.invalid.zone")[..],
        )).unwrap(),
    );

    let mut core = Core::new().unwrap();
    let (udp_sink, udp_stream) = UdpSocket::bind(
        &SocketAddr::from_str("127.0.0.1:5355").unwrap(),
        &core.handle(),
    ).unwrap()
        .framed(NameServer::new())
        .split();
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
    }).unwrap();
}
