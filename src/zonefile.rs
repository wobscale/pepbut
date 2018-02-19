use std::collections::BTreeMap;
use trust_dns::rr::{LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use trust_dns_proto::error::ProtoResult;
use trust_dns_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use trust_dns_server::authority::{Authority, ZoneType};

static ZONE_MAGIC: [u16; 3] = [0x4845, 0x434b, 0x4f1a]; // HECKO\x1a

#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Zone {
    records: Vec<Record>,
    origin: Name,
    serial: u32,
}

impl Zone {
    fn version(&self) -> u16 {
        0
    }

    pub fn origin(&self) -> &Name {
        &self.origin
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
        let (origin, serial) = match *soa_record.rdata() {
            RData::SOA(ref soa) => (soa_record.name().clone(), soa.serial()),
            _ => return Err("first record must be SOA".into()),
        };
        // TODO verify all records fit within the origin
        records.push(soa_record);
        for _i in 1..record_len {
            let record = Record::read(decoder)?;
            if record.rr_type() == RecordType::SOA {
                return Err("no records after the first may be SOA".into());
            }
            records.push(record);
        }
        Ok(Zone {
            records,
            origin,
            serial,
        })
    }
}

impl From<Zone> for Authority {
    fn from(zone: Zone) -> Authority {
        let mut records = BTreeMap::new();
        let serial = zone.serial;
        for record in zone.records {
            let entry = records
                .entry(RrKey::new(LowerName::new(record.name()), record.rr_type()))
                .or_insert_with(|| RecordSet::new(record.name(), record.rr_type(), serial));
            entry.insert(record, serial);
        }
        Authority::new(zone.origin, records, ZoneType::Master, false, false)
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
        (self.records.len() as u32).emit(encoder)?;
        // First emit the SOA record
        for record in &self.records {
            if record.rr_type() == RecordType::SOA {
                record.emit(encoder)?;
                break;
            }
        }
        // Now emit all further records
        for record in &self.records {
            if record.rr_type() == RecordType::SOA {
                continue;
            }
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

    use zonefile::Zone;

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
            records: vec![soa()],
            origin: Name::from_str("example.invalid.").unwrap(),
            serial: 1517625548,
        };
        assert_eq!(zone, Zone::from_bytes(&zone.to_bytes().unwrap()).unwrap());
    }

    #[test]
    fn test_too_many_records() {
        let mut zone = Zone {
            records: vec![soa()],
            origin: Name::from_str("example.invalid.").unwrap(),
            serial: 1517625548,
        };
        for _i in 0..1000 {
            zone.records.push(a());
        }
        assert_eq!(zone, Zone::from_bytes(&zone.to_bytes().unwrap()).unwrap());
    }
}
