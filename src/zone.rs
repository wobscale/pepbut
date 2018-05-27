//! Serialization and deserialization of zone files.

use bytes::Bytes;
use cast::{self, i64, u32};
use failure;
use rmp::{self, Marker};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::str::FromStr;

use name::{Name, ParseNameError};
use record::{Record, RecordTrait};
use wire::{ProtocolEncode, ResponseBuffer};
use Msgpack;

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
    pub fn with_records(
        origin: Name,
        serial: u32,
        records: impl IntoIterator<Item = Record>,
    ) -> Zone {
        let mut zone = Zone::new(origin, serial);
        for record in records {
            zone.push(record);
        }
        zone
    }

    /// Add a record to the zone.
    pub fn push(&mut self, record: Record) {
        self.records
            .entry(record.name().clone())
            .or_insert_with(HashMap::new)
            .entry(record.record_type())
            .or_insert_with(Vec::new)
            .push(record)
    }

    /// Remove a record from the zone.
    pub fn remove<'a>(&'a mut self, record: &'a Record) {
        if let Some(h) = self.records.get_mut(&record.name()) {
            if let Some(mut v) = h.get_mut(&record.record_type()) {
                if let Some(pos) = v.iter().position(|x| x == record) {
                    v.remove(pos);
                }
            }
            if h.get(&record.record_type()).map(|v| v.is_empty()) == Some(true) {
                h.remove(&record.record_type());
            }
        }
        if self.records.get(&record.name()).map(|h| h.is_empty()) == Some(true) {
            self.records.remove(&record.name());
        }
    }

    /// Look up a record in a zone.
    ///
    /// Returns `LookupResult`, which provides two types of negative responses so that the NXDOMAIN
    /// error code can be set accurately.
    pub fn lookup(&self, name: &Name, record_type: u16) -> LookupResult {
        match self.records.get(name) {
            Some(h) => match h.get(&record_type) {
                Some(v) => LookupResult::Records(v),
                None => LookupResult::NameExists(self.soa_record()),
            },
            None => LookupResult::NoName(self.soa_record()),
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

    pub fn soa_record(&self) -> SOARecord {
        SOARecord {
            origin: self.origin.clone(),
            serial: self.serial,
        }
    }

    /// Deserializes a zone file from a reader.
    ///
    /// The reader is required to implement `Seek` due to the need to read the labels at the end of
    /// the zone file first before processing the rest of the zone.
    pub fn read_from(reader: &mut (impl Read + Seek)) -> Result<Zone, failure::Error> {
        let partial_state = Zone::read_from_stage1(reader)?;
        Zone::read_from_stage2(partial_state, reader)
    }

    /// Deserializes the origin and serial from a zone file reader in a manner that can be
    /// completed with `Zone::read_from_stage2`.
    ///
    /// You can call this to check if you need to load the rest of the zone by comparing the change
    /// in the serial number.
    pub fn read_from_stage1(
        reader: &mut (impl Read + Seek),
    ) -> Result<PartialZoneState, failure::Error> {
        if rmp::decode::read_array_len(reader)? != 5 {
            bail!("zone must be array of 5 elements");
        }

        let origin_len = rmp::decode::read_array_len(reader)? as usize;
        let mut origin_ids: Vec<usize> = Vec::with_capacity(origin_len);
        for _ in 0..origin_len {
            origin_ids.push(rmp::decode::read_int(reader)?);
        }
        let origin_id_max = origin_ids
            .iter()
            .max()
            .ok_or_else(|| format_err!("origin must have at least one label"))?;

        let serial: u32 = rmp::decode::read_int(reader)?;
        let record_start_pos = reader.seek(SeekFrom::Current(0))?;

        reader.seek(SeekFrom::End(-9))?;
        let label_offset = rmp::decode::read_u64(reader)?;

        reader.seek(SeekFrom::End(-i64(label_offset)?))?;
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        if label_len < origin_id_max + 1 {
            bail!("invalid label index: {}", origin_id_max);
        }
        let mut labels = Vec::with_capacity(label_len);
        for _ in 0..(origin_id_max + 1) {
            let len = rmp::decode::read_str_len(reader)?;
            let s = read_exact!(reader, len)?;
            ensure!(s.len() < 64, ParseNameError::LabelTooLong(s.len()));
            labels.push(Bytes::from(s));
        }
        let remaining_label_pos = reader.seek(SeekFrom::Current(0))?;
        let remaining_label_len = label_len - (origin_id_max + 1);

        let origin = origin_ids
            .iter()
            .map(|i| {
                labels
                    .get(*i)
                    .ok_or_else(|| format_err!("invalid label index: {}", i))
                    .map(|x| x.clone())
            })
            .collect::<Result<Name, _>>()?;

        Ok(PartialZoneState {
            origin,
            serial,
            labels,
            remaining_label_len,
            remaining_label_pos,
            record_start_pos,
        })
    }

    pub fn read_from_stage2(
        partial_state: PartialZoneState,
        reader: &mut (impl Read + Seek),
    ) -> Result<Zone, failure::Error> {
        let mut labels = partial_state.labels;

        reader.seek(SeekFrom::Start(partial_state.remaining_label_pos))?;
        for _ in 0..partial_state.remaining_label_len {
            let len = rmp::decode::read_str_len(reader)?;
            let s = read_exact!(reader, len)?;
            ensure!(s.len() < 64, ParseNameError::LabelTooLong(s.len()));
            labels.push(Bytes::from(s));
        }

        let mut zone = Zone::new(partial_state.origin, partial_state.serial);

        reader.seek(SeekFrom::Start(partial_state.record_start_pos))?;
        let record_len = rmp::decode::read_array_len(reader)?;
        for _ in 0..record_len {
            zone.push(Record::from_msgpack(reader, &labels)?);
        }

        Ok(zone)
    }

    /// Serializes a zone file to a writer in one pass.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), failure::Error> {
        rmp::encode::write_array_len(writer, 5)?;
        let mut labels = Vec::new();

        self.origin.to_msgpack(writer, &mut labels)?;

        rmp::encode::write_uint(writer, self.serial.into())?;

        rmp::encode::write_array_len(writer, u32(self.len())?)?;
        for record in self.iter() {
            record.to_msgpack(writer, &mut labels)?;
        }

        let mut bytes_written: u64 = match rmp::encode::write_array_len(writer, u32(labels.len())?)?
        {
            Marker::FixArray(_) => 1,
            Marker::Array16 => 3,
            Marker::Array32 => 5,
            _ => unreachable!(),
        };
        for label in labels {
            rmp::encode::write_str_len(writer, u32(label.len())?)?;
            writer.write_all(&label)?;
            bytes_written += label.len() as u64 + if label.len() < 32 { 1 } else { 2 };
        }

        rmp::encode::write_u64(writer, bytes_written + 9)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct SOARecord {
    origin: Name,
    serial: u32,
}

impl SOARecord {
    fn mname(&self) -> Name {
        Name::from_str("ns1.wob.zone").expect("cannot fail")
    }

    fn rname(&self) -> Name {
        Name::from_str("hostmistress.as64241.net").expect("cannot fail")
    }
}

impl RecordTrait for SOARecord {
    fn name(&self) -> &Name {
        &self.origin
    }

    fn record_type(&self) -> u16 {
        6
    }

    fn ttl(&self) -> u32 {
        3600
    }

    fn encode_rdata_len(&self, buf: &ResponseBuffer) -> Result<u16, cast::Error> {
        let (mname_len, names) = self.mname().encode_len(&buf.names())?;
        Ok(mname_len + self.rname().encode_len(&names)?.0 + 20)
    }

    fn encode_rdata(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        self.mname().encode(buf)?;
        self.rname().encode(buf)?;
        self.serial.encode(buf)?;
        10000_u32.encode(buf)?;
        2400_u32.encode(buf)?;
        604_800_u32.encode(buf)?;
        3600_u32.encode(buf)
    }
}

/// The result of a record lookup.
#[derive(Debug, PartialEq)]
pub enum LookupResult<'a> {
    /// Records of that name and type exist. The value is a reference to the `Vec<Record>` for that
    /// name and type. NOERROR is set and the records go to the ANSWER section.
    Records(&'a Vec<Record>),
    /// The name belongs to a zone delegated to another name server. NOERROR is set; the
    /// authorities go to the AUTHORITY section and the glue records go to the ADDITIONAL section.
    Delegated {
        authorities: &'a Vec<Record>,
        glue_records: Vec<Record>,
    },
    /// Records of that name exist, but not of that type. NOERROR is set and the SOA record goes to
    /// the ADDITIONAL section.
    NameExists(SOARecord),
    /// No records of that name exist, and we are authoritative for this zone. NXDOMAIN is set and
    /// the SOA record goes to the ADDITIONAL section.
    NoName(SOARecord),
    /// We have no record of this zone. REFUSED is set. No records go to any sections.
    NoZone,
}

impl<'a> LookupResult<'a> {
    pub(crate) fn authoritative(&self) -> bool {
        match *self {
            LookupResult::Records(_)
            | LookupResult::Delegated { .. }
            | LookupResult::NameExists(_)
            | LookupResult::NoName(_) => true,
            LookupResult::NoZone => false,
        }
    }

    pub(crate) fn rcode(&self) -> u8 {
        match *self {
            LookupResult::Records(_)
            | LookupResult::Delegated { .. }
            | LookupResult::NameExists(_) => 0,
            LookupResult::NoName(_) => 3,
            LookupResult::NoZone => 5,
        }
    }

    pub(crate) fn counts(&self) -> [usize; 3] {
        match *self {
            LookupResult::Records(v) => [v.len(), 0, 0],
            LookupResult::Delegated {
                ref authorities,
                ref glue_records,
            } => [0, authorities.len(), glue_records.len()],
            LookupResult::NameExists(_) | LookupResult::NoName(_) => [0, 0, 1],
            LookupResult::NoZone => [0, 0, 0],
        }
    }
}

pub struct PartialZoneState {
    pub origin: Name,
    pub serial: u32,
    labels: Vec<Bytes>,
    remaining_label_len: usize,
    remaining_label_pos: u64,
    record_start_pos: u64,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::str::FromStr;

    use name::Name;
    use record::{RData, Record};
    use zone::{LookupResult, SOARecord, Zone};

    impl<'a> LookupResult<'a> {
        /// Returns `true` if the lookup contains no records other than the SOA record.
        fn is_empty(&self) -> bool {
            match *self {
                LookupResult::Records(v) | LookupResult::Delegated { authorities: v, .. } => {
                    if v.is_empty() {
                        panic!("variant cannot be empty");
                    }
                    false
                }
                LookupResult::NameExists(_) | LookupResult::NoName(_) | LookupResult::NoZone => {
                    true
                }
            }
        }
    }

    macro_rules! r {
        ($name:expr, $struct:expr) => {
            Record::new($name, 300, $struct)
        };
    }

    fn zone_example_invalid() -> Zone {
        let origin = Name::from_str("example.invalid.").unwrap();

        macro_rules! name {
            () => {
                origin.clone()
            };

            ($name:expr) => {{
                let mut n = Name::from_str($name).unwrap();
                n.extend(&origin);
                n
            }};
        }

        Zone::with_records(
            origin.clone(),
            1234567890,
            vec![
                r!(name!(), RData::NS(name!("ns1"))),
                r!(name!(), RData::NS(name!("ns2"))),
                r!(name!("www"), RData::A([192, 0, 2, 1].into())),
                r!(
                    name!("www"),
                    RData::AAAA([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into())
                ),
                r!(
                    name!("☃"),
                    RData::CNAME(Name::from_str("d1234567890.cloudfront.invalid").unwrap())
                ),
                r!(
                    name!(),
                    RData::MX {
                        preference: 10,
                        exchange: Name::from_str("mx1.mail.invalid.").unwrap(),
                    }
                ),
                r!(
                    name!(),
                    RData::MX {
                        preference: 20,
                        exchange: Name::from_str("mx2.mail.invalid.").unwrap(),
                    }
                ),
                r!(
                    name!("_sip._tcp"),
                    RData::SRV {
                        priority: 0,
                        weight: 5,
                        port: 5060,
                        target: name!("sip"),
                    }
                ),
                r!(name!(), RData::TXT("v=spf1 -all".to_owned())),
            ],
        )
    }

    #[test]
    fn read_example_invalid() {
        let buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
        assert_eq!(
            Zone::read_from(&mut Cursor::new(buf)).unwrap(),
            zone_example_invalid()
        );
    }

    #[test]
    fn read_write_example_invalid() {
        let mut buf = Vec::new();
        let zone = zone_example_invalid();
        zone.write_to(&mut buf).unwrap();
        assert_eq!(
            zone,
            Zone::read_from(&mut Cursor::new(buf.as_slice())).unwrap()
        );
    }

    #[test]
    fn zone_soa_record() {
        assert_eq!(
            zone_example_invalid().soa_record(),
            SOARecord {
                origin: Name::from_str("example.invalid.").unwrap(),
                serial: 1234567890,
            }
        );
    }

    #[test]
    fn zone_remove() {
        let mut zone = zone_example_invalid();
        let www = Name::from_str("www.example.invalid").unwrap();
        zone.remove(&Record::new(
            www.clone(),
            300,
            RData::A([192, 0, 2, 1].into()),
        ));
        assert!(zone.lookup(&www, 1).is_empty());
        assert!(zone.records.get(&www).is_some());
        assert!(zone.records.get(&www).unwrap().get(&1).is_none());
        zone.remove(&Record::new(
            www.clone(),
            300,
            RData::AAAA([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()),
        ));
        assert!(zone.lookup(&www, 28).is_empty());
        assert!(zone.records.get(&www).is_none());
    }

    #[test]
    fn zone_empty() {
        let zone = zone_example_invalid();
        assert_eq!(zone.is_empty(), false);
        assert_eq!(Zone::new(zone.origin.clone(), 1234567890).is_empty(), true);
    }

    #[test]
    fn len_example_invalid() {
        assert_eq!(zone_example_invalid().len(), 9);
    }

    #[test]
    fn iter_example_invalid() {
        let zone = zone_example_invalid();
        assert_eq!(
            zone,
            Zone::with_records(
                zone.origin.clone(),
                zone.serial,
                zone.iter().map(|x| x.clone())
            )
        );
    }

    #[test]
    fn lookup_example_invalid() {
        let zone = zone_example_invalid();
        assert_eq!(
            zone.lookup(&Name::from_str("www.example.invalid").unwrap(), 1),
            LookupResult::Records(&vec![Record::new(
                Name::from_str("www.example.invalid").unwrap(),
                300,
                RData::A([192, 0, 2, 1].into()),
            )])
        );
    }

    #[test]
    fn too_many_records() {
        let origin = Name::from_str("example.invalid").unwrap();
        let mut zone = Zone::new(origin.clone(), 1234567890);
        for _ in 1..100000 {
            zone.push(Record::new(
                origin.clone(),
                300,
                RData::A([192, 0, 2, 1].into()),
            ));
        }
        zone.push(Record::new(
            Name::from_str("www.example.invalid").unwrap(),
            300,
            RData::A([192, 0, 2, 1].into()),
        ));
        let mut buf = Vec::new();
        zone.write_to(&mut buf).unwrap();
    }
}
