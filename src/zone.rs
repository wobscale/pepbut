//! Serialization and deserialization of zone files.

use failure;
use rmp::{self, Marker};
use std::io::{Read, Seek, SeekFrom, Write};

use Msgpack;
use name::{Label, Name, FQDN};
use record::Record;

/// A zone is a collection of records belonging to an origin.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub struct Zone {
    /// The origin of the zone. All records in the zone must be under the origin.
    pub origin: FQDN,
    /// The serial. This should generally always increase with zone updates, but pepbut does not
    /// implement zone transfers so the point is rather moot.
    pub serial: u32,
    /// The collection of records in the zone.
    records: Vec<Record>,
}

impl Zone {
    /// Deserializes a zone file from a reader.
    ///
    /// The reader is required to implement `Seek` due to the need to read the labels at the end of
    /// the zone file first before processing the rest of the zone.
    pub fn read_from<R>(reader: &mut R) -> Result<Zone, failure::Error>
    where
        R: Read + Seek,
    {
        if rmp::decode::read_array_len(reader)? != 5 {
            bail!("zone must be array of 5 elements");
        }

        reader.seek(SeekFrom::End(-9))?;
        let label_offset = rmp::decode::read_u64(reader)?;

        #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_wrap))]
        reader.seek(SeekFrom::End(-(label_offset as i64)))?;
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        let mut labels = Vec::with_capacity(label_len);
        for _ in 0..label_len {
            labels.push(Label::from_msgpack(reader, &[])?);
        }

        reader.seek(SeekFrom::Start(1))?;
        let origin = Name::from_msgpack(reader, &labels)?.to_full_name(None)?;

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

    /// Serializes a zone file to a writer in one pass.
    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    pub fn write_to<W>(&self, writer: &mut W) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_array_len(writer, 5)?;
        let mut labels = Vec::new();

        self.origin.to_name().to_msgpack(writer, &mut labels)?;

        rmp::encode::write_uint(writer, self.serial.into())?;

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
            label.to_msgpack(writer, &mut vec![])?;
            bytes_written += label.len() as u64 + if label.len() < 32 { 1 } else { 2 };
        }

        rmp::encode::write_u64(writer, bytes_written + 9)?;

        Ok(())
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

    lazy_static! {
        static ref ZONE_EXAMPLE_INVALID: Zone = Zone {
            origin: Name::from_str("example.invalid.")
                .unwrap()
                .to_full_name(None)
                .unwrap(),
            serial: 1234567890,
            records: vec![
                ns!("", "ns1"),
                ns!("", "ns2"),
                a!("www"),
                aaaa!("www"),
                cname!("☃", "d1234567890.cloudfront.invalid."),
                mx!("", 10, "mx1.mail.invalid."),
                mx!("", 20, "mx2.mail.invalid."),
                srv!("_sip._tcp", 0, 5, 5060, "sip"),
                txt!("", vec!["v=spf1 -all".to_owned()]),
            ],
        };
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_zone_clone(b: &mut Bencher) {
        ZONE_EXAMPLE_INVALID.clone();
        b.iter(|| ZONE_EXAMPLE_INVALID.clone());
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_read_example_invalid(b: &mut Bencher) {
        ZONE_EXAMPLE_INVALID.clone();
        b.iter(|| {
            let buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
            Zone::read_from(&mut Cursor::new(buf)).unwrap();
        });
    }

    #[cfg(feature = "nightly")]
    #[bench]
    fn bench_write_example_invalid(b: &mut Bencher) {
        ZONE_EXAMPLE_INVALID.clone();
        b.iter(|| {
            let mut buf = Vec::new();
            ZONE_EXAMPLE_INVALID.write_to(&mut buf).unwrap();
        });
    }

    #[test]
    fn read_write_example_invalid() {
        let mut buf = Vec::new();
        ZONE_EXAMPLE_INVALID.write_to(&mut buf).unwrap();
        assert_eq!(
            *ZONE_EXAMPLE_INVALID,
            Zone::read_from(&mut Cursor::new(buf.as_slice())).unwrap()
        );
        assert_eq!(
            buf,
            &include_bytes!("../tests/data/example.invalid.zone")[..]
        );
    }

    #[test]
    fn too_many_records() {
        let mut zone = Zone {
            origin: Name::from_str("example.invalid.")
                .unwrap()
                .to_full_name(None)
                .unwrap(),
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
