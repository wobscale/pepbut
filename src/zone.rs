use failure;
use rmp;
use rmp::Marker;
use std::io::{Read, Seek, SeekFrom, Write};
use trust_dns::rr::Label;

use name::Name;
use record::Record;

pub trait Msgpack: Sized {
    fn from_msgpack<R>(reader: &mut R, labels: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read;
    fn to_msgpack<W>(&self, &mut W, labels: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write;
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
        R: Read + Seek,
    {
        if rmp::decode::read_array_len(reader)? != 5 {
            bail!("zone must be array of 5 elements");
        }

        reader.seek(SeekFrom::End(-9))?;
        let label_offset = rmp::decode::read_u64(reader)?;

        reader.seek(SeekFrom::End(-(label_offset as i64)))?;
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        let mut labels = Vec::with_capacity(label_len);
        for _ in 0..label_len {
            let len = rmp::decode::read_str_len(reader)? as usize;
            let mut buf = Vec::with_capacity(len);
            buf.resize(len, 0);
            reader.read_exact(&mut buf[..])?;
            labels.push(match Label::from_raw_bytes(&buf[..]) {
                Ok(label) => label,
                Err(err) => bail!("{:?}", err),
            });
        }

        reader.seek(SeekFrom::Start(1))?;
        let origin = Name::from_msgpack(reader, &labels)?;

        let serial = rmp::decode::read_int(reader)?;

        let record_len = rmp::decode::read_array_len(reader)?;
        let mut records = Vec::with_capacity(record_len as usize);
        for _ in 0..record_len {
            records.push(Record::from_msgpack(reader, &labels)?);
        }

        Ok(Zone {
            origin,
            serial,
            records,
        })
    }

    pub fn write_to<W>(&self, writer: &mut W) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_array_len(writer, 5)?;
        let mut labels = Vec::new();

        self.origin.to_msgpack(writer, &mut labels)?;

        rmp::encode::write_uint(writer, self.serial as u64)?;

        rmp::encode::write_array_len(writer, self.records.len() as u32)?;
        for record in &self.records {
            record.to_msgpack(writer, &mut labels)?;
        }

        let mut bytes_written: u64 =
            match rmp::encode::write_array_len(writer, labels.len() as u32)? {
                Marker::FixArray(_) => 1,
                Marker::Array16 => 3,
                Marker::Array32 => 5,
                _ => unreachable!(),
            };
        for label in labels {
            let label = label.to_ascii();
            bytes_written += match rmp::encode::write_str_len(writer, label.len() as u32)? {
                Marker::FixStr(_) => 1,
                Marker::Str8 => 2,
                Marker::Str16 => 3,
                Marker::Str32 => 5,
                _ => unreachable!(),
            };
            writer.write_all(label.as_bytes())?;
            bytes_written += label.len() as u64;
        }

        rmp::encode::write_u64(writer, bytes_written + 9)?;

        Ok(())
    }
}

#[cfg(feature = "pepbutd")]
impl Zone {
    pub fn into_authority(
        self,
    ) -> Result<::trust_dns_server::authority::Authority, failure::Error> {
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
    use std::io::Cursor;
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
            let buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
            Zone::read_from(&mut Cursor::new(buf)).unwrap();
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
        assert_eq!(
            zone,
            Zone::read_from(&mut Cursor::new(buf.as_slice())).unwrap()
        );
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
