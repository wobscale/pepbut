use rmpv;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use name::Name;
use zone::{Msgpack, MsgpackError};

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub struct Record {
    pub name: Name,
    pub ttl: u32,
    pub rdata: RData,
}

impl Msgpack for Record {
    fn from_msgpack(value: &rmpv::Value, labels: &[String]) -> Result<Self, MsgpackError> {
        let value = value.as_array().ok_or(MsgpackError::NotArray)?;
        if value.len() != 3 {
            return Err(MsgpackError::WrongRecord);
        }

        Ok(Record {
            name: Name::from_msgpack(value.get(0).ok_or(MsgpackError::WrongRecord)?, labels)?,
            ttl: value
                .get(1)
                .ok_or(MsgpackError::WrongRecord)?
                .as_u64()
                .ok_or(MsgpackError::NotUint)? as u32,
            rdata: RData::from_msgpack(value.get(2).ok_or(MsgpackError::WrongRecord)?, labels)?,
        })
    }

    fn to_msgpack(&self, labels: &mut Vec<String>) -> rmpv::Value {
        rmpv::Value::Array(vec![
            self.name.to_msgpack(labels),
            self.ttl.into(),
            self.rdata.to_msgpack(labels),
        ])
    }
}

#[cfg(feature = "pepbutd")]
impl Record {
    pub fn into_record(
        self,
        origin: Option<&Name>,
    ) -> Result<::trust_dns::rr::Record, ::name::TrustDnsConversionError> {
        use trust_dns::rr;

        let rdata = self.rdata.into_rdata(origin)?;
        Ok(rr::Record::from_rdata(
            self.name.to_name(origin)?,
            self.ttl,
            rdata.to_record_type(),
            rdata,
        ))
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(Name),
    MX {
        preference: u16,
        exchange: Name,
    },
    NS(Name),
    PTR(IpAddr),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    TXT(Vec<String>),
}

impl RData {
    fn record_type(&self) -> u16 {
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
    fn from_msgpack(value: &rmpv::Value, labels: &[String]) -> Result<Self, MsgpackError> {
        let value = value.as_array().ok_or(MsgpackError::NotArray)?;
        let record_type = value
            .get(0)
            .ok_or(MsgpackError::WrongRData)?
            .as_u64()
            .ok_or(MsgpackError::NotUint)?;
        Ok(match record_type {
            1 => RData::A({
                let addr_slice = value
                    .get(1)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_slice()
                    .ok_or(MsgpackError::NotBinary)?;
                if addr_slice.len() == 4 {
                    let mut addr = [0; 4];
                    addr.copy_from_slice(addr_slice);
                    Ok(addr.into())
                } else {
                    Err(MsgpackError::WrongAddressLength)
                }
            }?),
            28 => RData::AAAA({
                let addr_slice = value
                    .get(1)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_slice()
                    .ok_or(MsgpackError::NotBinary)?;
                if addr_slice.len() == 16 {
                    let mut addr = [0; 16];
                    addr.copy_from_slice(addr_slice);
                    Ok(addr.into())
                } else {
                    Err(MsgpackError::WrongAddressLength)
                }
            }?),
            5 => RData::CNAME(Name::from_msgpack(
                value.get(1).ok_or(MsgpackError::WrongRData)?,
                labels,
            )?),
            15 => RData::MX {
                preference: value
                    .get(1)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_u64()
                    .ok_or(MsgpackError::NotUint)? as u16,
                exchange: Name::from_msgpack(
                    value.get(2).ok_or(MsgpackError::WrongRData)?,
                    labels,
                )?,
            },
            2 => RData::NS(Name::from_msgpack(
                value.get(1).ok_or(MsgpackError::WrongRData)?,
                labels,
            )?),
            12 => RData::PTR({
                let addr_slice = value
                    .get(1)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_slice()
                    .ok_or(MsgpackError::NotBinary)?;
                if addr_slice.len() == 16 {
                    let mut addr = [0; 16];
                    addr.copy_from_slice(addr_slice);
                    Ok(addr.into())
                } else if addr_slice.len() == 4 {
                    let mut addr = [0; 4];
                    addr.copy_from_slice(addr_slice);
                    Ok(addr.into())
                } else {
                    Err(MsgpackError::WrongAddressLength)
                }
            }?),
            33 => RData::SRV {
                priority: value
                    .get(1)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_u64()
                    .ok_or(MsgpackError::NotUint)? as u16,
                weight: value
                    .get(2)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_u64()
                    .ok_or(MsgpackError::NotUint)? as u16,
                port: value
                    .get(3)
                    .ok_or(MsgpackError::WrongRData)?
                    .as_u64()
                    .ok_or(MsgpackError::NotUint)? as u16,
                target: Name::from_msgpack(value.get(4).ok_or(MsgpackError::WrongRData)?, labels)?,
            },
            16 => RData::TXT(value[1..]
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(|x| x.to_owned())
                        .ok_or(MsgpackError::NotString)
                })
                .collect::<Result<Vec<_>, _>>()?),
            s => Err(MsgpackError::InvalidRecordType(s))?,
        })
    }

    fn to_msgpack(&self, labels: &mut Vec<String>) -> rmpv::Value {
        let mut vec: Vec<rmpv::Value> = Vec::with_capacity(match *self {
            RData::A { .. }
            | RData::AAAA { .. }
            | RData::CNAME { .. }
            | RData::NS { .. }
            | RData::PTR { .. } => 2,
            RData::MX { .. } => 3,
            RData::SRV { .. } => 5,
            RData::TXT(ref data) => 1 + data.len(),
        });
        vec.push(self.record_type().into());
        match *self {
            RData::A(addr) | RData::PTR(IpAddr::V4(addr)) => {
                vec.push(addr.octets().to_vec().into())
            }
            RData::AAAA(addr) | RData::PTR(IpAddr::V6(addr)) => {
                vec.push(addr.octets().to_vec().into())
            }
            RData::CNAME(ref name) | RData::NS(ref name) => vec.push(name.to_msgpack(labels)),
            RData::MX {
                preference,
                ref exchange,
            } => {
                vec.push(preference.into());
                vec.push(exchange.to_msgpack(labels));
            }
            RData::SRV {
                priority,
                weight,
                port,
                ref target,
            } => {
                vec.push(priority.into());
                vec.push(weight.into());
                vec.push(port.into());
                vec.push(target.to_msgpack(labels));
            }
            RData::TXT(ref data) => for datum in data {
                vec.push(datum.to_owned().into());
            },
        }
        vec.into()
    }
}

#[cfg(feature = "pepbutd")]
impl RData {
    pub fn into_rdata(
        self,
        origin: Option<&Name>,
    ) -> Result<::trust_dns::rr::RData, ::name::TrustDnsConversionError> {
        use trust_dns::rr;

        Ok(match self {
            RData::A(a) => rr::RData::A(a),
            RData::AAAA(a) => rr::RData::AAAA(a),
            RData::CNAME(n) => rr::RData::CNAME(n.to_name(origin)?),
            RData::MX {
                preference,
                exchange,
            } => rr::RData::MX(rr::rdata::MX::new(preference, exchange.to_name(origin)?)),
            RData::NS(n) => rr::RData::NS(n.to_name(origin)?),
            RData::PTR(a) => rr::RData::PTR(a.into()),
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => rr::RData::SRV(rr::rdata::SRV::new(
                priority,
                weight,
                port,
                target.to_name(origin)?,
            )),
            RData::TXT(v) => rr::RData::TXT(rr::rdata::TXT::new(v)),
        })
    }
}
