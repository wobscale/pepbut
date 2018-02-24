#[cfg(feature = "pepbutd")]
use std::collections::BTreeMap;
use trust_dns::rr::{Name, RData, Record, RecordType};
#[cfg(feature = "pepbutd")]
use trust_dns::rr::{LowerName, RecordSet, RrKey};
use trust_dns::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use trust_dns_proto::error::ProtoResult;
#[cfg(feature = "pepbutd")]
use trust_dns_server::authority::{Authority, ZoneType};

static ZONE_MAGIC: [u16; 3] = [0x4845, 0x434b, 0x4f1a]; // HECKO\x1a

#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Zone {
    soa_record: Record,
    records: Vec<Record>,
}

impl Zone {
    fn version(&self) -> u16 {
        0
    }

    pub fn origin(&self) -> &Name {
        self.soa_record.name()
    }

    pub fn serial(&self) -> u32 {
        match *self.soa_record.rdata() {
            RData::SOA(ref soa) => soa.serial(),
            _ => unreachable!(),
        }
    }

    /// Version 0 format:
    ///
    /// magic: [u16; 3],
    /// version: u16,
    /// record_len: u32,
    /// [records]
    fn read_v0<'r>(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        let record_len = u32::read(decoder)? as usize;
        let mut records = Vec::with_capacity(record_len);
        let soa_record = Record::read(decoder)?;
        if soa_record.rr_type() != RecordType::SOA {
            return Err("first record must be SOA".into());
        }
        // TODO verify all records fit within the origin
        for _ in 1..record_len {
            let record = Record::read(decoder)?;
            if record.rr_type() == RecordType::SOA {
                return Err("no records after the first may be SOA".into());
            }
            records.push(record);
        }
        Ok(Zone {
            soa_record,
            records,
        })
    }
}

#[cfg(feature = "pepbutd")]
impl From<Zone> for Authority {
    fn from(zone: Zone) -> Authority {
        let mut records = BTreeMap::new();
        let serial = zone.serial();
        let origin = zone.origin().to_lowercase();
        for record in vec![zone.soa_record].into_iter().chain(zone.records) {
            let entry = records
                .entry(RrKey::new(LowerName::new(record.name()), record.rr_type()))
                .or_insert_with(|| RecordSet::new(record.name(), record.rr_type(), serial));
            entry.insert(record, serial);
        }
        Authority::new(origin, records, ZoneType::Master, false, false)
    }
}

impl<'r> BinDecodable<'r> for Zone {
    fn read(decoder: &mut BinDecoder<'r>) -> ProtoResult<Self> {
        for magic in &ZONE_MAGIC {
            if u16::read(decoder)? != *magic {
                return Err("unknown magic".into());
            }
        }
        match u16::read(decoder)? {
            0 => Self::read_v0(decoder),
            s => Err(format!("unknown version: {}", s).into()),
        }
    }
}

impl BinEncodable for Zone {
    fn emit(&self, encoder: &mut BinEncoder) -> ProtoResult<()> {
        for magic in &ZONE_MAGIC {
            magic.emit(encoder)?;
        }
        self.version().emit(encoder)?;
        ((self.records.len() + 1) as u32).emit(encoder)?;
        self.soa_record.emit(encoder)?;
        for record in &self.records {
            record.emit(encoder)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use trust_dns_proto::rr::Name;
    use trust_dns_proto::rr::rdata::soa::SOA;
    use trust_dns_proto::rr::record_data::RData;
    use trust_dns_proto::rr::record_type::RecordType;
    use trust_dns_proto::rr::resource::Record;
    use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

    use zone::Zone;

    fn a() -> Record {
        Record::from_rdata(
            Name::from_str("example.invalid.").unwrap(),
            300,
            RecordType::A,
            RData::A([192, 0, 2, 1].into()),
        )
    }

    fn soa() -> Record {
        Record::from_rdata(
            Name::from_str("example.invalid.").unwrap(),
            300,
            RecordType::SOA,
            RData::SOA(SOA::new(
                Name::from_str("ns1.nic.invalid.").unwrap(),
                Name::from_str("hostmaster.nic.invalid.").unwrap(),
                1517625548,
                3600,
                900,
                1209600,
                300,
            )),
        )
    }

    #[test]
    fn test_one_record() {
        let zone = Zone {
            soa_record: soa(),
            records: vec![],
        };
        assert_eq!(zone, Zone::from_bytes(&zone.to_bytes().unwrap()).unwrap());
    }

    #[test]
    fn test_too_many_records() {
        let mut zone = Zone {
            soa_record: soa(),
            records: vec![],
        };
        for _ in 0..1 {
            zone.records.push(a());
        }
        assert_eq!(zone, Zone::from_bytes(&zone.to_bytes().unwrap()).unwrap());
    }
}
