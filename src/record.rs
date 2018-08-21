// SPDX-License-Identifier: AGPL-3.0-only

//! Records and record data.

use bytes::{BufMut, Bytes, BytesMut};
use cast::{self, u16, u32, u8};
use failure;
use rmp;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use name::Name;
use wire::ProtocolEncode;
use Msgpack;

pub trait RecordTrait {
    /// The name the record belongs to.
    fn name(&self) -> &Name;

    /// The resource record type.
    fn record_type(&self) -> u16;

    /// The TTL of the record.
    fn ttl(&self) -> u32;

    /// Returns the length of the encoded rdata.
    fn encode_rdata_len(&self, names: &HashSet<Name>) -> Result<u16, cast::Error>;

    /// Encodes the rdata to a buffer.
    fn encode_rdata(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error>;
}

impl ProtocolEncode for RecordTrait {
    fn encode(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error> {
        self.name().encode(buf, names)?;
        buf.reserve(10);
        buf.put_u16_be(self.record_type());
        buf.put_u16_be(1); // IN class
        buf.put_u32_be(self.ttl());
        let rdata_len = self.encode_rdata_len(&names.keys().cloned().collect())?;
        buf.put_u16_be(rdata_len);
        buf.reserve(rdata_len as usize);
        self.encode_rdata(buf, names)
    }
}

/// A record maps an owner domain name to a record data value, associated with a time-to-live.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The name for the owner of this record.
    name: Name,
    /// The time-to-live for this record.
    ttl: u32,
    /// The data for this record.
    rdata: RData,
}

impl Record {
    /// Create a record from rdata.
    pub fn new(name: Name, ttl: u32, rdata: RData) -> Record {
        Record { name, ttl, rdata }
    }

    pub fn rdata(&self) -> &RData {
        &self.rdata
    }
}

impl RecordTrait for Record {
    fn name(&self) -> &Name {
        &self.name
    }

    fn record_type(&self) -> u16 {
        self.rdata.record_type()
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }

    fn encode_rdata_len(&self, names: &HashSet<Name>) -> Result<u16, cast::Error> {
        self.rdata.encode_len(names)
    }

    fn encode_rdata(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error> {
        self.rdata.encode(buf, names)
    }
}

impl Msgpack for Record {
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Record, failure::Error> {
        // rdata reads two values
        if rmp::decode::read_array_len(reader)? != 4 {
            bail!("record must be array of 4 elements");
        }

        let name = Name::from_msgpack(reader, labels)?;
        let ttl = rmp::decode::read_int(reader)?;
        let rdata = RData::from_msgpack(reader, labels)?;

        Ok(Record { name, ttl, rdata })
    }

    fn to_msgpack(
        &self,
        writer: &mut impl Write,
        labels: &mut Vec<Bytes>,
    ) -> Result<(), failure::Error> {
        // rdata writes two values
        rmp::encode::write_array_len(writer, 4)?;

        self.name.to_msgpack(writer, labels)?;
        rmp::encode::write_uint(writer, self.ttl.into())?;
        self.rdata.to_msgpack(writer, labels)?;

        Ok(())
    }
}

/// The data of a resource record.
#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    /// [A record data](https://tools.ietf.org/html/rfc1035#section-3.4.1), representing an IPv4
    /// address.
    A(Ipv4Addr),
    /// [AAAA record data](https://tools.ietf.org/html/rfc1886#section-2.2), representing an IPv6
    /// address.
    AAAA(Ipv6Addr),
    /// [CNAME record data](https://tools.ietf.org/html/rfc1035#section-3.3.1), representing a
    /// canonical name for an alias.
    CNAME(Name),
    /// [MX record data](https://tools.ietf.org/html/rfc1035#section-3.3.9), representing a mail
    /// server for a domain.
    MX {
        /// Specifies the preference given to this particular exchange among others with the same
        /// owner. Lower values are preferred.
        preference: u16,
        /// The domain name of the mail server.
        exchange: Name,
    },
    /// [NS record data](https://tools.ietf.org/html/rfc1035#section-3.3.11), representing an
    /// authoritative name server for a domain.
    NS(Name),
    /// [PTR record data](https://tools.ietf.org/html/rfc1035#section-3.3.12), commonly used for
    /// reverse DNS.
    PTR(Name),
    /// [SRV record data](https://tools.ietf.org/html/rfc2782), sometimes used to represent a set
    /// of hosts and ports specifying the location of a service.
    SRV {
        /// Specifies the priority of this target. Lower value targets must be attempted first.
        priority: u16,
        /// Specifies the weight for this target. Higher values are preferred.
        weight: u16,
        /// Specifies the port the service is running on for this target.
        port: u16,
        /// Specifies the name of the host the service is running on.
        target: Name,
    },
    /// [TXT record data](https://tools.ietf.org/html/rfc1035#section-3.3.14), used to represent
    /// descriptive text. The string is split up along 255-byte boundaries when encoded in a
    /// response message.
    TXT(String),
}

impl RData {
    /// The resource record type.
    pub fn record_type(&self) -> u16 {
        match *self {
            RData::A { .. } => 1,
            RData::AAAA { .. } => 28,
            RData::CNAME { .. } => 5,
            RData::MX { .. } => 15,
            RData::NS { .. } => 2,
            RData::PTR { .. } => 12,
            RData::SRV { .. } => 33,
            RData::TXT { .. } => 16,
        }
    }

    fn encode_len(&self, names: &HashSet<Name>) -> Result<u16, cast::Error> {
        Ok(match *self {
            RData::A { .. } => 4,
            RData::AAAA { .. } => 16,
            RData::CNAME(ref name) | RData::NS(ref name) | RData::PTR(ref name) => {
                name.encode_len(names)?.0
            }
            RData::MX { ref exchange, .. } => 2 + exchange.encode_len(names)?.0,
            RData::SRV { ref target, .. } => 6 + target.encode_len(names)?.0,
            RData::TXT(ref s) => {
                let l = s.len();
                u16((l / 255 + min(1, l % 255)) + l)?
            }
        })
    }
}

impl Msgpack for RData {
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<RData, failure::Error> {
        Ok(match rmp::decode::read_int(reader)? {
            // A: addr
            1 => {
                let bin_len = rmp::decode::read_bin_len(reader)?;
                if bin_len == 4 {
                    let mut addr = [0; 4];
                    reader.read_exact(&mut addr)?;
                    RData::A(addr.into())
                } else {
                    bail!("A rdata must be 4 bytes");
                }
            }
            // AAAA: addr
            28 => {
                let bin_len = rmp::decode::read_bin_len(reader)?;
                if bin_len == 16 {
                    let mut addr = [0; 16];
                    reader.read_exact(&mut addr)?;
                    RData::AAAA(addr.into())
                } else {
                    bail!("AAAA rdata must be 16 bytes");
                }
            }
            // CNAME: name
            5 => RData::CNAME(Name::from_msgpack(reader, labels)?),
            // MX: preference exchange
            15 => {
                if rmp::decode::read_array_len(reader)? != 2 {
                    bail!("MX rdata must be array of 2 elements");
                }
                let preference = rmp::decode::read_int(reader)?;
                let exchange = Name::from_msgpack(reader, labels)?;
                RData::MX {
                    preference,
                    exchange,
                }
            }
            // NS | PTR: name
            2 | 12 => RData::NS(Name::from_msgpack(reader, labels)?),
            // SRV: priority weight port target
            33 => {
                if rmp::decode::read_array_len(reader)? != 4 {
                    bail!("SRV rdata must be array of 4 elements");
                }
                let priority = rmp::decode::read_int(reader)?;
                let weight = rmp::decode::read_int(reader)?;
                let port = rmp::decode::read_int(reader)?;
                let target = Name::from_msgpack(reader, labels)?;
                RData::SRV {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            // TXT: [str]
            16 => {
                let len = rmp::decode::read_str_len(reader)?;
                RData::TXT(String::from_utf8(read_exact!(reader, len)?)?)
            }
            s => bail!("unrecognized rdata type: {}", s),
        })
    }

    fn to_msgpack(
        &self,
        writer: &mut impl Write,
        labels: &mut Vec<Bytes>,
    ) -> Result<(), failure::Error> {
        rmp::encode::write_uint(writer, self.record_type().into())?;

        match *self {
            RData::A(addr) => {
                rmp::encode::write_bin_len(writer, 4)?;
                writer.write_all(&addr.octets())?;
            }
            RData::AAAA(addr) => {
                rmp::encode::write_bin_len(writer, 16)?;
                writer.write_all(&addr.octets())?;
            }
            RData::CNAME(ref name) | RData::NS(ref name) | RData::PTR(ref name) => {
                name.to_msgpack(writer, labels)?
            }
            RData::MX {
                preference,
                ref exchange,
            } => {
                rmp::encode::write_array_len(writer, 2)?;
                rmp::encode::write_uint(writer, preference.into())?;
                exchange.to_msgpack(writer, labels)?;
            }
            RData::SRV {
                priority,
                weight,
                port,
                ref target,
            } => {
                rmp::encode::write_array_len(writer, 4)?;
                rmp::encode::write_uint(writer, priority.into())?;
                rmp::encode::write_uint(writer, weight.into())?;
                rmp::encode::write_uint(writer, port.into())?;
                target.to_msgpack(writer, labels)?;
            }
            RData::TXT(ref data) => {
                rmp::encode::write_str_len(writer, u32(data.len())?)?;
                writer.write_all(data.as_bytes())?;
            }
        }

        Ok(())
    }
}

impl ProtocolEncode for RData {
    fn encode(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error> {
        match *self {
            RData::A(addr) => {
                buf.reserve(4);
                buf.put_slice(&addr.octets());
            }
            RData::AAAA(addr) => {
                buf.reserve(16);
                buf.put_slice(&addr.octets());
            }
            RData::CNAME(ref name) | RData::NS(ref name) | RData::PTR(ref name) => {
                name.encode(buf, names)?
            }
            RData::MX {
                preference,
                ref exchange,
            } => {
                buf.reserve(2);
                buf.put_u16_be(preference);
                exchange.encode(buf, names)?;
            }
            RData::SRV {
                priority,
                weight,
                port,
                ref target,
            } => {
                buf.reserve(6);
                buf.put_u16_be(priority);
                buf.put_u16_be(weight);
                buf.put_u16_be(port);
                target.encode(buf, names)?;
            }
            RData::TXT(ref s) => {
                for chunk in s.as_bytes().chunks(255) {
                    buf.reserve(1 + chunk.len());
                    buf.put_u8(u8(chunk.len())?);
                    buf.put_slice(chunk);
                }
            }
        }
        Ok(())
    }
}
