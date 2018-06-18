#![cfg(feature = "zone-convert")]

//! Textual zone file parsing.
//!
//! We use trust-dns for parsing textual zone files because I really don't want to implement it
//! myself and conversions from their types to our types are not the worst.

use failure;
use std::error::Error;
use std::fmt::{self, Display};
use std::iter::FromIterator;
use trust_dns::error::ParseErrorKind;
use trust_dns::rr::{LowerName, Name as TrustDnsName, RData};
use trust_dns::serialize::txt::{Lexer, Parser};

use name::Name;
use record::{RData as RD, Record};
use zone::Zone;

impl From<TrustDnsName> for Name {
    fn from(name: TrustDnsName) -> Name {
        Name::from_iter(name.into_iter().map(|b| b.into()))
    }
}

impl From<LowerName> for Name {
    fn from(name: LowerName) -> Name {
        TrustDnsName::from(name).into()
    }
}

// This ridiculous mess is due to the fact that trust-dns errors do not implement Sync. We only
// really care about the inner error kind type because it contains everything we need to know, and
// they *just barely* don't implement Error.
#[derive(Debug)]
#[allow(dead_code)]
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

pub fn read(s: &str) -> Result<Zone, failure::Error> {
    let lexer = Lexer::new(s);
    let (origin, records) = Parser::new()
        .parse(lexer, None)
        .map_err(|e| TrustDnsParseError(e.into_kind()))?;
    let mut zone = Zone::new(origin.into(), 0);
    let mut serial = None;
    for (rrkey, record_set) in records {
        let name = Name::from(rrkey.name);
        for record in record_set {
            zone.push(Record::new(
                name.clone(),
                record.ttl(),
                match record.rdata() {
                    RData::A(addr) => RD::A(*addr),
                    RData::AAAA(addr) => RD::AAAA(*addr),
                    RData::CNAME(name) => RD::CNAME(name.clone().into()),
                    RData::MX(mx) => RD::MX {
                        preference: mx.preference(),
                        exchange: mx.exchange().clone().into(),
                    },
                    RData::NS(name) => RD::NS(name.clone().into()),
                    RData::PTR(name) => RD::PTR(name.clone().into()),
                    RData::SOA(soa) => {
                        serial = Some(soa.serial());
                        continue;
                    }
                    RData::SRV(srv) => RD::SRV {
                        priority: srv.priority(),
                        weight: srv.weight(),
                        port: srv.port(),
                        target: srv.target().clone().into(),
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
