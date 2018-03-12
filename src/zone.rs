//! Serialization and deserialization of zone files.

use failure;
use rmp::{self, Marker};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

use Msgpack;
use name::{Label, Name};
use record::Record;

/// A zone is a collection of records belonging to an origin.
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    /// The origin of the zone. All records in the zone must be under the origin.
    pub origin: Name,
    /// The serial. This should generally always increase with zone updates, but pepbut does not
    /// implement zone transfers so the point is rather moot.
    pub serial: u32,
    /// The collection of records in the zone.
    records: HashMap<Name, HashMap<u16, Vec<Record>>>,
}

impl Zone {
    /// Creates a new zone.
    pub fn new(origin: Name, serial: u32) -> Zone {
        Zone {
            origin,
            serial,
            records: HashMap::new(),
        }
    }

    /// Creates a new zone from an iterator of records.
    pub fn with_records<I>(origin: Name, serial: u32, records: I) -> Zone
    where
        I: IntoIterator<Item = Record>,
    {
        let mut zone = Zone::new(origin, serial);
        for record in records {
            zone.push(record);
        }
        zone
    }

    /// Add a record to the zone.
    pub fn push(&mut self, record: Record) {
        self.records
            .entry(record.name.clone())
            .or_insert_with(HashMap::new)
            .entry(record.record_type())
            .or_insert_with(Vec::new)
            .push(record)
    }

    /// Remove a record from the zone.
    pub fn remove<'a>(&'a mut self, record: &'a Record) {
        if let Some(h) = self.records.get_mut(&record.name) {
            if let Some(mut v) = h.get_mut(&record.record_type()) {
                v.remove_item(record);
            }
        }
    }

    /// Return the number of records in the zone.
    pub fn len(&self) -> usize {
        self.records
            .values()
            .flat_map(|h| h.values())
            .map(|v| v.len())
            .sum()
    }

    /// Return if the zone is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return an iterator of all records in the zone.
    pub fn iter(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(|h| h.values().flat_map(|v| v))
    }

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
        let origin = Name::from_msgpack(reader, &labels)?;

        let serial = rmp::decode::read_int(reader)?;

        let mut zone = Zone::new(origin, serial);

        let record_len = rmp::decode::read_array_len(reader)?;
        for _ in 0..record_len {
            zone.push(Record::from_msgpack(reader, &labels)?);
        }

        Ok(zone)
    }

    /// Serializes a zone file to a writer in one pass.
    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    pub fn write_to<W>(&self, writer: &mut W) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_array_len(writer, 5)?;
        let mut labels = Vec::new();

        self.origin.to_msgpack(writer, &mut labels)?;

        rmp::encode::write_uint(writer, self.serial.into())?;

        rmp::encode::write_array_len(writer, self.len() as u32)?;
        for record in self.iter() {
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
    use test::Bencher;

    use name::Name;
    use record::RData;
    use zone::Zone;

    macro_rules! record {
        ($name: expr, $struct: expr) => {{
            use record::Record;

            Record {
                name: $name,
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
            record!($name, RData::CNAME($target))
        };
    }

    macro_rules! mx {
        ($name: expr, $pref: expr, $exch: expr) => {
            record!(
                $name,
                RData::MX {
                    preference: $pref,
                    exchange: $exch,
                }
            )
        };
    }

    macro_rules! ns {
        ($name: expr, $ns: expr) => {
            record!($name, RData::NS($ns))
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
                    target: $target,
                }
            )
        };
    }

    macro_rules! txt {
        ($name: expr, $vs: expr) => {
            record!($name, RData::TXT($vs))
        };
    }

    macro_rules! name {
        () => {
            ORIGIN_EXAMPLE_INVALID.clone()
        };

        ($name: expr) => {
            Name::from_str_on_origin($name, &ORIGIN_EXAMPLE_INVALID).unwrap()
        };
    }

    lazy_static! {
        static ref ORIGIN_EXAMPLE_INVALID: Name = Name::from_str("example.invalid.").unwrap();
        static ref ZONE_EXAMPLE_INVALID: Zone = Zone::with_records(
            ORIGIN_EXAMPLE_INVALID.clone(),
            1234567890,
            vec![
                ns!(name!(), name!("ns1")),
                ns!(name!(), name!("ns2")),
                a!(name!("www")),
                aaaa!(name!("www")),
                cname!(
                    name!("☃"),
                    Name::from_str("d1234567890.cloudfront.invalid.").unwrap()
                ),
                mx!(name!(), 10, Name::from_str("mx1.mail.invalid.").unwrap()),
                mx!(name!(), 20, Name::from_str("mx2.mail.invalid.").unwrap()),
                srv!(name!("_sip._tcp"), 0, 5, 5060, name!("sip")),
                txt!(name!(), vec!["v=spf1 -all".to_owned()]),
            ],
        );
    }

    #[bench]
    fn bench_zone_clone(b: &mut Bencher) {
        ZONE_EXAMPLE_INVALID.clone();
        b.iter(|| ZONE_EXAMPLE_INVALID.clone());
    }

    #[bench]
    fn bench_read_example_invalid(b: &mut Bencher) {
        ZONE_EXAMPLE_INVALID.clone();
        b.iter(|| {
            let buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
            Zone::read_from(&mut Cursor::new(buf)).unwrap();
        });
    }

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
    }

    #[test]
    fn len_example_invalid() {
        assert_eq!(ZONE_EXAMPLE_INVALID.len(), 9);
    }

    #[test]
    fn iter_example_invalid() {
        assert_eq!(
            *ZONE_EXAMPLE_INVALID,
            Zone::with_records(
                ZONE_EXAMPLE_INVALID.origin.clone(),
                ZONE_EXAMPLE_INVALID.serial,
                ZONE_EXAMPLE_INVALID.iter().map(|x| x.clone())
            )
        );
    }

    #[test]
    fn too_many_records() {
        let mut zone = Zone::new(Name::from_str("example.invalid.").unwrap(), 1234567890);
        for _ in 1..100000 {
            zone.push(a!(name!()));
        }
        zone.push(a!(name!("www")));
        let mut buf = Vec::new();
        zone.write_to(&mut buf).unwrap();
    }
}
