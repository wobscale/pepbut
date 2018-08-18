// SPDX-License-Identifier: AGPL-3.0-only

use bytes::{Buf, Bytes, BytesMut};
use failure;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use name::Name;
use record::RData;
use wire::{encode_err, ProtocolDecode, ProtocolEncode, QueryMessage};
use zone::{LookupResult, Zone};

#[derive(Debug, Default)]
pub struct Authority {
    pub zones: HashMap<Name, Zone>,
}

impl Authority {
    pub fn new() -> Authority {
        Authority {
            zones: HashMap::new(),
        }
    }

    /// Loads a zone into the authority from a reader. Returns a tuple of the origin and serial.
    fn load_zone(
        &mut self,
        reader: &mut (impl Read + Seek),
    ) -> Result<(Name, u32), failure::Error> {
        let zone = Zone::read_from(reader)?;
        let ret = (zone.origin.clone(), zone.serial);
        self.zones.insert(ret.0.clone(), zone);
        Ok(ret)
    }

    /// Loads a zone file into the authority. Returns a tuple of the origin and serial.
    pub fn load_zonefile<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<(Name, u32), failure::Error> {
        info!("loading zone from {}", path.as_ref().display());
        self.load_zone(&mut File::open(path)?)
    }

    fn find_zone(&self, name: &Name) -> Option<&Zone> {
        let mut name = name.clone();
        while !name.is_empty() {
            if let Some(zone) = self.zones.get(&name) {
                return Some(zone);
            }
            name = name.pop();
        }
        None
    }

    pub fn process_message(&self, buf: Bytes) -> Bytes {
        let mut buf = Cursor::new(buf);
        let query = match QueryMessage::decode(&mut buf) {
            Ok(query) => query,
            Err(_) => return encode_err(buf.get_u16_be(), 1),
        };
        let name = query.name.clone();
        let record_type = query.record_type;
        let lookup = match self.find_zone(&name) {
            Some(zone) => zone.lookup(&name, record_type),
            None => LookupResult::NoZone,
        };
        let lookup = if let LookupResult::CNAMELookup(cname) = lookup {
            if let RData::CNAME(target) = cname.rdata() {
                match self.find_zone(target) {
                    Some(zone) => LookupResult::CNAME {
                        cname,
                        found: zone
                            .lookup(&target, record_type)
                            .records()
                            .cloned()
                            .unwrap_or_else(Vec::new),
                        authorities: zone
                            .lookup(&zone.origin, 2)
                            .records()
                            .cloned()
                            .unwrap_or_else(Vec::new),
                    },
                    None => lookup,
                }
            } else {
                lookup
            }
        } else {
            lookup
        };
        let response = query.respond(lookup);
        let mut buf = BytesMut::new();
        match response.encode(&mut buf, &mut HashMap::new()) {
            Ok(()) => Bytes::from(buf),
            Err(err) => {
                error!("{:?}", err);
                encode_err(response.query.id, 2)
            }
        }
    }
}
