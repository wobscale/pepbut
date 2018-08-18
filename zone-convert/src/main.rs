// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

//! RFC 1035 master file conversion for pepbut.
//!
//! We use trust-dns for parsing zone files because I really don't want to implement it myself, and
//! conversions from their types to our types are not the worst.

extern crate clap;
#[macro_use]
extern crate failure;
extern crate pepbut;
extern crate trust_dns;

use clap::{App, Arg};
use pepbut::name::Name;
use pepbut::record::{RData as RD, Record};
use pepbut::zone::Zone;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs::{self, File};
use std::iter::FromIterator;
use trust_dns::error::ParseErrorKind;
use trust_dns::rr::{LowerName, Name as TrustDnsName, RData};
use trust_dns::serialize::txt::{Lexer, Parser};

// This ridiculous mess is due to the fact that trust-dns errors do not implement Sync. We only
// really care about the inner error kind type because it contains everything we need to know, and
// they *just barely* don't implement Error.
#[derive(Debug)]
struct TrustDnsParseError(ParseErrorKind);

impl Display for TrustDnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for TrustDnsParseError {
    fn description(&self) -> &str {
        self.0.description()
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn from_name(name: TrustDnsName) -> Name {
    Name::from_iter(name.into_iter().map(|b| b.into()))
}

fn from_lower(name: LowerName) -> Name {
    from_name(TrustDnsName::from(name))
}

pub fn read(s: &str) -> Result<Zone, failure::Error> {
    let lexer = Lexer::new(s);
    let (origin, records) = Parser::new()
        .parse(lexer, None)
        .map_err(|e| TrustDnsParseError(e.into_kind()))?;
    let mut zone = Zone::new(from_name(origin), 0);
    let mut serial = None;
    for (rrkey, record_set) in records {
        let name = from_lower(rrkey.name);
        for record in record_set {
            zone.push(Record::new(
                name.clone(),
                record.ttl(),
                match record.rdata() {
                    RData::A(addr) => RD::A(*addr),
                    RData::AAAA(addr) => RD::AAAA(*addr),
                    RData::CNAME(name) => RD::CNAME(from_name(name.clone())),
                    RData::MX(mx) => RD::MX {
                        preference: mx.preference(),
                        exchange: from_name(mx.exchange().clone()),
                    },
                    RData::NS(name) => RD::NS(from_name(name.clone())),
                    RData::PTR(name) => RD::PTR(from_name(name.clone())),
                    RData::SOA(soa) => {
                        serial = Some(soa.serial());
                        continue;
                    }
                    RData::SRV(srv) => RD::SRV {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port(),
                        target: from_name(srv.target().clone()),
                    },
                    RData::TXT(txt) => RD::TXT(String::from_utf8(txt.txt_data().concat())?),
                    RData::CAA(_) => bail!("unsupported record type: CAA"),
                    RData::NULL(_) => bail!("unsupported record type: NULL"),
                    RData::OPT(_) => bail!("unsupported record type: OPT"),
                    RData::TLSA(_) => bail!("unsupported record type: TLSA"),
                    RData::DNSSEC(_) => bail!("DNSSEC record types are unsupported"),
                    RData::Unknown { code, .. } => bail!("unsupported record type code: {}", code),
                    RData::ZERO => bail!("unsupported record type code: 0"),
                },
            ))
        }
    }
    match serial {
        Some(serial) => zone.serial = serial,
        None => bail!("no SOA record present in zone"),
    }
    Ok(zone)
}

fn main() -> Result<(), failure::Error> {
    let matches = App::new("pepbut-zone-convert")
        .arg(Arg::with_name("INPUT").help("input file").required(true))
        .arg(Arg::with_name("OUTPUT").help("output file").required(true))
        .get_matches();

    read(&fs::read_to_string(matches.value_of("INPUT").unwrap())?)?
        .write_to(&mut File::create(matches.value_of("OUTPUT").unwrap())?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pepbut::zone::Zone;
    use std::io::Cursor;

    use super::read;

    #[test]
    fn it_works() {
        let bin: &[u8] = include_bytes!("../../tests/data/example.invalid.zone");
        let from_bin = Zone::read_from(&mut Cursor::new(bin)).unwrap();
        let from_text = read(include_str!("../../tests/data/example.invalid.zone.txt")).unwrap();
        assert_eq!(from_bin, from_text);
    }
}
