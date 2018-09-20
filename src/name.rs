// SPDX-License-Identifier: AGPL-3.0-only

//! Domain names and labels.

// Internals note: there's some deliberate inconsistency into what gets lowercased and what doesn't
// when creating Name structs. The goal is that authoritative uses are always lowercase, but
// non-authoritative uses such as requests are not.
//
// Name::from_str and Msgpack::from_msgpack always lowercase; ProtocolDecode::decode does not, as a
// wire client might expect the response to have the same name case as the request.
// FromIterator<Bytes> for Name expects the caller to make an appropriate decision.
//
// PartialEq / Eq / Hash are written in a case-insensitive manner.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use cast::{self, u16, u32, u8, usize};
use failure;
use idna::uts46;
use rmp;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};

use msgpack::Msgpack;
use wire::{ProtocolDecode, ProtocolDecodeError, ProtocolEncode};

/// Errors that can occur while parsing a `Name`.
#[derive(Debug, Fail)]
pub enum NameParseError {
    /// The label is empty.
    #[fail(display = "empty label")]
    EmptyLabel,
    /// The label contains invalid characters according to UTS #46.
    #[fail(display = "label contains invalid characters: {:?}", _0)]
    InvalidLabel(uts46::Errors),
    /// The label is longer than 63 characters.
    #[fail(display = "label exceeds maximum length of 63: {}", _0)]
    LabelTooLong(usize),
}

/// Validates and constructs a label from a string. This method normalizes the label to
/// lowercase ASCII, converting non-ASCII characters into Punycode according to UTS #46.
fn label_from_str(s: &str) -> Result<Bytes, NameParseError> {
    /// Checks if a byte is valid for a DNS label.
    fn byte_ok(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-'
    }

    if s.is_empty() {
        Err(NameParseError::EmptyLabel)
    } else if (s.starts_with('_') && s.bytes().skip(1).all(byte_ok)) || s.bytes().all(byte_ok) {
        if s.len() > 63 {
            Err(NameParseError::LabelTooLong(s.len()))
        } else {
            Ok(Bytes::from(s.to_lowercase()))
        }
    } else {
        let s = uts46::to_ascii(
            s,
            uts46::Flags {
                use_std3_ascii_rules: true,
                transitional_processing: true,
                verify_dns_length: true,
            },
        ).map_err(NameParseError::InvalidLabel)?;
        if s.len() > 63 {
            Err(NameParseError::LabelTooLong(s.len()))
        } else {
            Ok(Bytes::from(s))
        }
    }
}

/// A fully-qualified domain name.
///
/// Domain names are made up of labels. For the domain name `example.invalid`, there are two
/// labels, `example` and `invalid`.
///
/// A domain name is fully-qualified if the rightmost label is a top-level domain.
///
/// Labels in pepbut are [`Bytes`]. The byte arrays always represent the ASCII/Punycode
/// representation of a label (the result of [UTS #46][uts46] processing). Labels may contain
/// mixed-case characters but are always hashed and compared as lowercase.
///
/// [uts46]: https://www.unicode.org/reports/tr46/
///
/// Making the byte arrays reference-counted is part of making the pepbut name server more memory
/// efficient. The other part is `Zone`'s packing of labels by reference, allowing each label to be
/// stored in memory exactly once per zone when read from a zone file.
///
/// Because the labels are reference-counted byte arrays, we can more efficiently copy the normally
/// repetitive origins of names without having to handle whether or not domains are fully-qualified
/// or not.
#[derive(Clone, Debug)]
pub struct Name(Vec<Bytes>);

impl Name {
    /// Clones and appends all labels in an origin `Name` to this `Name`.
    pub fn extend(&mut self, origin: &Name) {
        self.0.extend(origin.0.iter().cloned())
    }

    /// Returns a cloned Name, skipping the first label.
    pub fn pop(&self) -> Name {
        Name(self.0.iter().skip(1).cloned().collect())
    }

    /// Returns the number of labels in the Name.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns if the Name is empty (the root name).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn encode_len(
        &self,
        names: &HashSet<Name>,
    ) -> Result<(u16, HashSet<Name>), cast::Error> {
        let mut names = names.clone();
        let mut name = self.clone();
        let mut len = 0;
        while !name.0.is_empty() {
            if names.contains(&name) {
                return Ok((len + 2, names));
            } else {
                names.insert(name.clone());
                len += 1 + u16(name
                    .0
                    .first()
                    .expect("unreachable, we already checked name is not empty")
                    .len())?;
                name = name.pop();
            }
        }
        len += 1;
        trace!("{:?} predicted length = {} bytes", self, len);
        Ok((len, names))
    }
}

fn eq_lower(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(a, b)| match (*a, *b) {
        (a, b) if a == b => true,
        (a, b) if b'a' <= a && a <= b'z' && b'A' <= b && b <= b'Z' => a == (b | 0x20),
        (a, b) if b'A' <= a && a <= b'Z' && b'a' <= b && b <= b'z' => (a | 0x20) == b,
        _ => false,
    })
}

impl PartialEq for Name {
    fn eq(&self, rhs: &Name) -> bool {
        if self.0.len() != rhs.0.len() {
            return false;
        }
        self.0.iter().zip(rhs.0.iter()).all(|(a, b)| eq_lower(a, b))
    }
}

impl Eq for Name {}

impl hash::Hash for Name {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        // See impl<T: Hash> Hash for [T]
        self.0.len().hash(state);
        for label in &self.0 {
            label.to_ascii_lowercase().as_slice().hash(state);
        }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, label) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(
                f,
                "{}",
                uts46::to_unicode(
                    str::from_utf8(label).expect("label can only contain UTF-8 bytes"),
                    uts46::Flags {
                        use_std3_ascii_rules: true,
                        transitional_processing: true,
                        verify_dns_length: true,
                    },
                ).0
            )?;
        }
        Ok(())
    }
}

impl FromStr for Name {
    type Err = NameParseError;

    fn from_str(s: &str) -> Result<Name, NameParseError> {
        Ok(Name(
            (if s.ends_with('.') {
                s.split_at(s.len() - 1).0
            } else {
                s
            }).split('.')
            .map(label_from_str)
            .collect::<Result<Vec<_>, _>>()?,
        ))
    }
}

impl FromIterator<Bytes> for Name {
    fn from_iter<T: IntoIterator<Item = Bytes>>(iter: T) -> Name {
        Name(iter.into_iter().collect())
    }
}

impl Msgpack for Name {
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Name, failure::Error> {
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        let mut name_labels = Vec::with_capacity(label_len);
        for _ in 0..label_len {
            let label_idx: usize = rmp::decode::read_int(reader)?;
            name_labels.push(
                labels
                    .get(label_idx)
                    .ok_or_else(|| format_err!("invalid label index: {}", label_idx))?
                    .clone(),
            );
        }

        Ok(Name(name_labels))
    }

    fn to_msgpack(
        &self,
        writer: &mut impl Write,
        labels: &mut Vec<Bytes>,
    ) -> Result<(), failure::Error> {
        rmp::encode::write_array_len(writer, u32(self.0.len())?)?;

        for label in &self.0 {
            rmp::encode::write_uint(
                writer,
                if let Some(n) = labels.iter().position(|x| x == label) {
                    n
                } else {
                    labels.push(label.clone());
                    labels.len() - 1
                } as u64,
            )?;
        }

        Ok(())
    }
}

impl ProtocolDecode for Name {
    fn decode(buf: &mut Cursor<Bytes>) -> Result<Name, ProtocolDecodeError> {
        let mut name = Name(Vec::new());
        let mut orig_pos = 0;
        let mut jumps = 0;

        loop {
            let length = buf.get_u8();
            if length == 0 {
                if jumps > 0 {
                    buf.set_position(orig_pos);
                }
                return Ok(name);
            } else if length > 63 {
                let offset = ((u16::from(length) & 0x3f) << 8) + u16::from(buf.get_u8());
                if jumps == 0 {
                    orig_pos = buf.position();
                } else if jumps == 20 {
                    return Err(ProtocolDecodeError::NamePointerRecursionLimitReached);
                }
                jumps += 1;
                buf.set_position(offset.into());
            } else {
                let start = usize(buf.position());
                let end = start + length as usize;
                buf.advance(length as usize);
                name.0.push(buf.get_ref().slice(start, end))
            }
        }
    }
}

impl ProtocolEncode for Name {
    fn encode(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error> {
        let mut name = self.clone();
        while !name.0.is_empty() {
            let maybe_pos = names.get(&name).cloned();
            if let Some(pos) = maybe_pos {
                buf.reserve(2);
                buf.put_u16_be(
                    0xc000_u16
                        .checked_add(pos)
                        .ok_or(::cast::Error::Underflow)?,
                );
                return Ok(());
            } else {
                names.insert(name.clone(), u16(buf.len())?);
                let label = name
                    .0
                    .first()
                    .expect("unreachable, we already checked name is not empty")
                    .clone();
                buf.reserve(1 + label.len());
                buf.put_u8(u8(label.len())?);
                buf.put_slice(&label);
                name = name.pop();
            }
        }
        buf.reserve(1);
        buf.put_u8(0);
        Ok(())
    }
}

static LABEL_ARPA: &[u8] = b"arpa";
static LABEL_IN_ADDR: &[u8] = b"in-addr";
static LABEL_IP6: &[u8] = b"ip6";
// This is the digits 0 through 255 concatenated
static OCTET_DECIMAL: &[u8] =
    b"012345678910111213141516171819202122232425262728293031323334353637383940414243444546474849505\
      152535455565758596061626364656667686970717273747576777879808182838485868788899091929394959697\
      989910010110210310410510610710810911011111211311411511611711811912012112212312412512612712812\
      913013113213313413513613713813914014114214314414514614714814915015115215315415515615715815916\
      016116216316416516616716816917017117217317417517617717817918018118218318418518618718818919019\
      119219319419519619719819920020120220320420520620720820921021121221321421521621721821922022122\
      222322422522622722822923023123223323423523623723823924024124224324424524624724824925025125225\
      3254255";
static HEX_DIGITS: &[u8] = b"0123456789abcdef";

impl From<IpAddr> for Name {
    fn from(addr: IpAddr) -> Name {
        match addr {
            IpAddr::V4(a) => a.into(),
            IpAddr::V6(a) => a.into(),
        }
    }
}

impl From<Ipv4Addr> for Name {
    fn from(addr: Ipv4Addr) -> Name {
        let dec = Bytes::from_static(OCTET_DECIMAL);
        let mut name = Vec::with_capacity(6);
        for octet in addr.octets().iter().rev() {
            name.push(if *octet < 10 {
                dec.slice(*octet as usize, (*octet + 1) as usize)
            } else if *octet < 100 {
                let x = 2 * ((*octet - 10) as usize);
                dec.slice(x + 10, x + 12)
            } else {
                let x = 3 * ((*octet - 100) as usize);
                dec.slice(x + 190, x + 193)
            });
        }
        name.push(Bytes::from_static(LABEL_IN_ADDR));
        name.push(Bytes::from_static(LABEL_ARPA));
        Name(name)
    }
}

impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        let hex = Bytes::from_static(HEX_DIGITS);
        let mut name = Vec::with_capacity(34);
        for octet in addr.octets().iter().rev() {
            let (low, high) = ((octet & 0xf) as usize, (octet >> 4) as usize);
            name.push(hex.slice(low, low + 1));
            name.push(hex.slice(high, high + 1));
        }
        name.push(Bytes::from_static(LABEL_IP6));
        name.push(Bytes::from_static(LABEL_ARPA));
        Name(name)
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::net::IpAddr;
    use std::str::FromStr;

    use name::{label_from_str, Name};
    use wire::{ProtocolDecode, ProtocolEncode};

    macro_rules! label {
        ($e:expr) => {
            if $e.is_ascii() {
                Bytes::from_static($e.as_bytes())
            } else {
                label_from_str($e).unwrap()
            }
        };
    }

    #[test]
    fn display() {
        for s in &[
            "buttslol.net",
            "tld",
            "☃.net",
            "_sip._udp.wobscale.website",
        ] {
            assert_eq!(format!("{}", Name::from_str(s).unwrap()), s.to_owned());
        }
    }

    #[test]
    fn pop() {
        assert_eq!(
            Name::from_str("www.example.net").unwrap().pop(),
            Name::from_str("example.net").unwrap()
        );
    }

    #[test]
    fn empty_label() {
        assert!(Name::from_str("").is_err());
    }

    #[test]
    fn too_long() {
        assert!(
            Name::from_str("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_err()
        );
    }

    #[test]
    fn from_str() {
        assert_eq!(
            Name::from_str("buttslol.net.").unwrap().0,
            Name(vec![label!("buttslol"), label!("net")]).0
        );
        assert_eq!(
            Name::from_str("BUTTSLOL.net.").unwrap().0,
            Name(vec![label!("buttslol"), label!("net")]).0
        );
        assert_eq!(
            Name::from_str("tld").unwrap().0,
            Name(vec![label!("tld")]).0
        );
        assert_eq!(
            Name::from_str("☃.net.").unwrap().0,
            Name(vec![label!("☃"), label!("net")]).0
        );
        assert_eq!(
            Name::from_str("EXAMPLE-☃.net.").unwrap().0,
            Name(vec![label!("example-☃"), label!("net")]).0
        );
        assert_eq!(
            Name::from_str("_sip._udp.wobscale.website").unwrap().0,
            Name(vec![
                label!("_sip"),
                label!("_udp"),
                label!("wobscale"),
                label!("website"),
            ]).0
        );
    }

    #[test]
    fn decode() {
        let mut buf = Cursor::new(Bytes::from_static(
            b"\x07example\x07INVALID\0\x04blah\xc0\x08",
        ));
        assert_eq!(
            Name::decode(&mut buf).unwrap().0,
            Name(vec![label!("example"), label!("INVALID")]).0
        );
        assert_eq!(buf.position(), 17);
        assert_eq!(
            Name::decode(&mut buf).unwrap().0,
            Name(vec![label!("blah"), label!("INVALID")]).0
        );
        assert_eq!(buf.position(), 24);
    }

    #[test]
    fn decode_infinite() {
        let mut buf = Cursor::new(Bytes::from_static(b"\xc0\x00"));
        assert!(Name::decode(&mut buf).is_err());
    }

    #[test]
    fn from_ipv4addr() {
        assert_eq!(
            format!("{}", Name::from(IpAddr::V4([192, 0, 2, 1].into()))),
            "1.2.0.192.in-addr.arpa"
        );
    }

    #[test]
    fn from_ipv6addr() {
        assert_eq!(
            format!(
                "{}",
                Name::from(IpAddr::V6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1].into()))
            ),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn encode_smoke() {
        let mut buf = BytesMut::new();
        let mut names = HashMap::new();
        Name::from_str("example.com")
            .unwrap()
            .encode(&mut buf, &mut names)
            .unwrap();
        assert_eq!(buf, Bytes::from_static(b"\x07example\x03com\x00"));
        assert_eq!(
            names,
            hashmap! {
                Name::from_str("example.com").unwrap() => 0,
                Name::from_str("com").unwrap() => 8,
            }
        );
    }

    #[test]
    fn encode_ns() {
        let mut buf = BytesMut::new();
        let mut names = HashMap::new();
        Name::from_str("ns1.example.com")
            .unwrap()
            .encode(&mut buf, &mut names)
            .unwrap();
        Name(vec![label!("NS2"), label!("example"), label!("com")])
            .encode(&mut buf, &mut names)
            .unwrap();
        assert_eq!(
            buf,
            Bytes::from_static(b"\x03ns1\x07example\x03com\x00\x03NS2\xc0\x04")
        );
        assert_eq!(
            names,
            hashmap! {
                Name::from_str("ns1.example.com").unwrap() => 0,
                Name::from_str("example.com").unwrap() => 4,
                Name::from_str("com").unwrap() => 12,
                Name::from_str("ns2.example.com").unwrap() => 17,
            }
        );
    }
}
