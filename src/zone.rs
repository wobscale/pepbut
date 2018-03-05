use failure;
use rmpv;
use std::io::{Read, Write};

use name::Name;
use record::Record;

#[derive(Fail, Debug)]
pub enum MsgpackError {
    #[fail(display = "invalid record type {}", _0)]
    InvalidRecordType(u64),
    #[fail(display = "expected array")]
    NotArray,
    #[fail(display = "expected binary")]
    NotBinary,
    #[fail(display = "expected string")]
    NotString,
    #[fail(display = "expected unsigned integer")]
    NotUint,
    #[fail(display = "wrong IP address length")]
    WrongAddressLength,
    #[fail(display = "wrong record data")]
    WrongRecord,
    #[fail(display = "wrong rdata data")]
    WrongRData,
    #[fail(display = "wrong zone data")]
    WrongZone,
}

pub trait Msgpack: Sized {
    fn from_msgpack(value: &rmpv::Value, labels: &[String]) -> Result<Self, MsgpackError>;
    fn to_msgpack(&self, labels: &mut Vec<String>) -> rmpv::Value;
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub struct Zone {
    pub origin: Name,
    pub serial: u32,
    pub records: Vec<Record>,
}

impl Zone {
    pub fn read_from<R>(reader: &mut R) -> Result<Zone, failure::Error>
    where
        R: Read,
    {
        let value = rmpv::decode::read_value(reader)?;
        let value = value.as_array().ok_or(MsgpackError::NotArray)?;
        if value.len() != 4 {
            return Err(MsgpackError::WrongZone.into());
        }

        let labels = value
            .get(0)
            .ok_or(MsgpackError::WrongRecord)?
            .as_array()
            .ok_or(MsgpackError::WrongRecord)?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_owned())
                    .ok_or(MsgpackError::NotString)
            })
            .collect::<Result<Vec<String>, _>>()?;

        Ok(Zone {
            origin: Name::from_msgpack(value.get(1).ok_or(MsgpackError::WrongRecord)?, &labels)?,
            serial: value
                .get(2)
                .ok_or(MsgpackError::WrongRecord)?
                .as_u64()
                .ok_or(MsgpackError::NotUint)? as u32,
            records: value
                .get(3)
                .ok_or(MsgpackError::WrongZone)?
                .as_array()
                .ok_or(MsgpackError::WrongZone)?
                .iter()
                .map(|r| Record::from_msgpack(r, &labels))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn write_to<W>(self, writer: &mut W) -> Result<(), failure::Error>
    where
        W: Write,
    {
        let mut labels = Vec::new();
        let origin = self.origin.to_msgpack(&mut labels);
        let records: Vec<_> = self.records
            .iter()
            .map(|r| r.to_msgpack(&mut labels))
            .collect();

        rmpv::encode::write_value(
            writer,
            &rmpv::Value::Array(vec![
                labels
                    .into_iter()
                    .map(rmpv::Value::from)
                    .collect::<Vec<_>>()
                    .into(),
                origin,
                self.serial.into(),
                records.into(),
            ]),
        )?;
        Ok(())
    }
}

#[cfg(feature = "pepbutd")]
impl Zone {
    pub fn into_authority(
        self,
    ) -> Result<::trust_dns_server::authority::Authority, ::name::TrustDnsConversionError> {
        use std::collections::BTreeMap;
        use std::str::FromStr;
        use trust_dns::rr::{self, IntoRecordSet};
        use trust_dns_server::authority::{Authority, ZoneType};

        let serial = self.serial;
        let mut records = BTreeMap::new();
        records.insert(
            rr::RrKey::new(
                self.origin.clone().to_lower_name(Some(&self.origin))?,
                rr::RecordType::SOA,
            ),
            rr::Record::from_rdata(
                self.origin.clone().to_name(Some(&self.origin))?,
                3600,
                rr::RecordType::SOA,
                rr::RData::SOA(rr::rdata::SOA::new(
                    rr::Name::from_str("ns1.wob.zone.").unwrap(),
                    rr::Name::from_str("admin.wobscale.website.").unwrap(),
                    serial,
                    10_000,
                    2_400,
                    604_800,
                    300,
                )),
            ).into_record_set(),
        );
        for record in self.records {
            let record: rr::Record = record.into_record(Some(&self.origin))?;
            let entry = records
                .entry(rr::RrKey::new(
                    rr::LowerName::new(record.name()),
                    record.rr_type(),
                ))
                .or_insert_with(|| rr::RecordSet::new(record.name(), record.rr_type(), serial));
            entry.insert(record, serial);
        }
        Ok(Authority::new(
            self.origin.clone().to_name(Some(&self.origin))?,
            records,
            ZoneType::Master,
            false,
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    #[cfg(feature = "nightly")]
    use test::Bencher;

    use name::Name;
    use record::RData;
    use zone::Zone;

    macro_rules! record {
        ($name: expr, $struct: expr) => {{
            use name::Name;
            use record::Record;

            Record {
                name: Name::from_str($name).unwrap(),
                ttl: 300,
                rdata: $struct,
            }
        }};
    }

    macro_rules! a {
        ($name: expr) => {
            a!($name, [192, 0, 2, 1].into())
        };

        ($name: expr, $addr: expr) => {
            record!($name, RData::A($addr))
        };
    }

    macro_rules! aaaa {
        ($name: expr) => {
            aaaa!($name, [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into())
        };

        ($name: expr, $addr: expr) => {
            record!($name, RData::AAAA($addr))
        };
    }

    macro_rules! cname {
        ($name: expr, $target: expr) => {
            record!($name, RData::CNAME(Name::from_str($target).unwrap()))
        };
    }

    macro_rules! mx {
        ($name: expr, $pref: expr, $exch: expr) => {
            record!(
                $name,
                RData::MX {
                    preference: $pref,
                    exchange: Name::from_str($exch).unwrap(),
                }
            )
        };
    }

    macro_rules! ns {
        ($name: expr, $ns: expr) => {
            record!($name, RData::NS(Name::from_str($ns).unwrap()))
        };
    }

    macro_rules! srv {
        ($name: expr, $pri: expr, $wei: expr, $port: expr, $target: expr) => {
            record!(
                $name,
                RData::SRV {
                    priority: $pri,
                    weight: $wei,
                    port: $port,
                    target: Name::from_str($target).unwrap(),
                }
            )
        };
    }

    macro_rules! txt {
        ($name: expr, $vs: expr) => {
            record!($name, RData::TXT($vs))
        };
    }

    macro_rules! zone_example_invalid {
        () => {
            Zone {
                origin: Name::from_str("example.invalid.").unwrap(),
                serial: 1234567890,
                records: vec![
                    ns!("", "ns1"),
                    ns!("", "ns2"),
                    a!("www"),
                    aaaa!("www"),
                    cname!("cdn", "d1234567890.cloudfront.invalid."),
                    mx!("", 10, "mx1.mail.invalid."),
                    mx!("", 20, "mx2.mail.invalid."),
                    srv!("_sip._tcp", 0, 5, 5060, "sip"),
                    txt!("", vec!["v=spf1 -all".to_owned()]),
                ],
            }
        };
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_read_example_invalid(b: &mut Bencher) {
        b.iter(|| {
            let mut buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
            Zone::read_from(&mut buf).unwrap();
        })
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_write_example_invalid(b: &mut Bencher) {
        b.iter(|| {
            let mut buf = Vec::new();
            zone_example_invalid!().write_to(&mut buf).unwrap();
        })
    }

    #[test]
    fn read_write_example_invalid() {
        let zone = zone_example_invalid!();
        let mut buf = Vec::new();
        zone.clone().write_to(&mut buf).unwrap();
        assert_eq!(zone, Zone::read_from(&mut buf.as_slice()).unwrap());
        assert_eq!(
            buf,
            &include_bytes!("../tests/data/example.invalid.zone")[..]
        );
    }

    #[cfg(all(feature = "pepbutd", feature = "nightly"))]
    #[bench]
    fn bench_into_authority(b: &mut Bencher) {
        b.iter(|| zone_example_invalid!().into_authority().unwrap());
    }

    #[test]
    fn too_many_records() {
        let mut zone = Zone {
            origin: Name::from_str("example.invalid.").unwrap(),
            serial: 1234567890,
            records: Vec::with_capacity(100000),
        };
        for _ in 1..100000 {
            zone.records.push(a!(""));
        }
        zone.records.push(a!("www"));
        let mut buf = Vec::new();
        zone.write_to(&mut buf).unwrap();
    }
}
