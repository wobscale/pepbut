#![cfg(feature = "nsd")]

use bytes::{Buf, Bytes, BytesMut};
use failure;
use std::collections::hash_map::{self, HashMap};
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use name::Name;
use wire::{encode_err, ProtocolDecode, ProtocolEncode, QueryMessage};
use zone::{LookupResult, Zone};

#[derive(Debug, Default)]
pub struct Authority {
    zones: HashMap<Name, Zone>,
}

impl Authority {
    pub fn new() -> Authority {
        Authority {
            zones: HashMap::new(),
        }
    }

    /// Conditionally loads a zone into the authority. The zone's origin and serial are used to
    /// determine if the update is required before parsing the rest of the zone.
    fn load_zone(&mut self, reader: &mut (impl Read + Seek)) -> Result<(), failure::Error> {
        let partial_state = Zone::read_from_stage1(reader)?;
        match self.zones.entry(partial_state.origin.clone()) {
            hash_map::Entry::Occupied(mut entry) => {
                let current_serial = entry.get().serial;
                // There are rules for zone serial rollovers but we are only running authoritative
                // servers and we are not implementing AXFR so it really doesn't matter because we
                // can just restart the server. ¯\_(ツ)_/¯
                if current_serial < partial_state.serial {
                    let new_zone = Zone::read_from_stage2(partial_state, reader)?;
                    info!(
                        "updated zone {}, serial {}",
                        new_zone.origin, new_zone.serial
                    );
                    entry.insert(new_zone);
                } else {
                    warn!(
                        "ignored update to {}, loaded serial {}, current serial {}",
                        partial_state.origin, partial_state.serial, current_serial
                    );
                }
            }
            hash_map::Entry::Vacant(entry) => {
                let zone = Zone::read_from_stage2(partial_state, reader)?;
                info!("inserted zone {}, serial {}", zone.origin, zone.serial);
                entry.insert(zone);
            }
        };
        Ok(())
    }

    pub fn load_zonefile<P: AsRef<Path>>(&mut self, path: P) -> Result<(), failure::Error> {
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
        let response = query.respond(match self.find_zone(&name) {
            Some(zone) => zone.lookup(&name, record_type),
            None => LookupResult::NoZone,
        });
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
