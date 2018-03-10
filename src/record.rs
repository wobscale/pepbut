//! Records and record data.

use failure;
use rmp;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use Msgpack;
use name::{Label, Name};

/// A record maps an owner domain name to a record data value, associated with a time-to-live.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// The name for the owner of this record.
    pub name: Name,
    /// The time-to-live for this record.
    pub ttl: u32,
    /// The data for this record.
    pub rdata: RData,
}

impl Record {
    /// The resource record type.
    pub fn record_type(&self) -> u16 {
        self.rdata.record_type()
    }
}

impl Msgpack for Record {
    fn from_msgpack<R>(reader: &mut R, labels: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read,
    {
        // rdata reads two values
        if rmp::decode::read_array_len(reader)? != 4 {
            bail!("record must be array of 4 elements");
        }

        let name = Name::from_msgpack(reader, labels)?;
        let ttl = rmp::decode::read_int(reader)?;
        let rdata = RData::from_msgpack(reader, labels)?;

        Ok(Record { name, ttl, rdata })
    }

    fn to_msgpack<W>(&self, writer: &mut W, labels: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write,
    {
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
    ///
    /// In pepbut, PTR records use the `std::net::IpAddr` enum, which are translated into the
    /// relevant `in-addr.arpa` or `ip6.arpa` `Name`s.
    PTR(IpAddr),
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
    /// descriptive text.
    TXT(Vec<String>),
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
}

impl Msgpack for RData {
    fn from_msgpack<R>(reader: &mut R, labels: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read,
    {
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
            // NS: name
            2 => RData::NS(Name::from_msgpack(reader, labels)?),
            // PTR: addr
            12 => {
                let bin_len = rmp::decode::read_bin_len(reader)?;
                if bin_len == 4 {
                    let mut addr = [0; 4];
                    reader.read_exact(&mut addr)?;
                    RData::PTR(addr.into())
                } else if bin_len == 16 {
                    let mut addr = [0; 16];
                    reader.read_exact(&mut addr)?;
                    RData::PTR(addr.into())
                } else {
                    bail!("PTR rdata must be 4 or 16 bytes");
                }
            }
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
                let n = rmp::decode::read_array_len(reader)? as usize;
                let mut data = Vec::with_capacity(n);
                for _ in 0..n {
                    let len = rmp::decode::read_str_len(reader)? as usize;
                    let mut buf = Vec::with_capacity(len);
                    buf.resize(len, 0);
                    reader.read_exact(&mut buf[..])?;
                    data.push(String::from_utf8(buf)?);
                }
                RData::TXT(data)
            }
            s => bail!("unrecognized rdata type: {}", s),
        })
    }

    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    fn to_msgpack<W>(&self, writer: &mut W, labels: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_uint(writer, self.record_type().into())?;

        match *self {
            RData::A(addr) | RData::PTR(IpAddr::V4(addr)) => {
                rmp::encode::write_bin_len(writer, 4)?;
                writer.write_all(&addr.octets())?;
            }
            RData::AAAA(addr) | RData::PTR(IpAddr::V6(addr)) => {
                rmp::encode::write_bin_len(writer, 16)?;
                writer.write_all(&addr.octets())?;
            }
            RData::CNAME(ref name) | RData::NS(ref name) => name.to_msgpack(writer, labels)?,
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
                rmp::encode::write_array_len(writer, data.len() as u32)?;
                for datum in data {
                    rmp::encode::write_str_len(writer, datum.len() as u32)?;
                    writer.write_all(datum.as_bytes())?;
                }
            }
        }

        Ok(())
    }
}
