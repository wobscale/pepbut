// SPDX-License-Identifier: AGPL-3.0-only

//! Domain names and labels.

// Internals note: there's some deliberate inconsistency into what gets lowercased and what doesn't
// when creating Name structs. The goal is that authoritative uses are always lowercase, but
// non-authoritative uses such as requests are not.
//
// Name::from_str and Msgpack::from_msgpack always lowercase labels; ProtocolDecode::decode does
// not, as a wire client might expect the response to have the same name case as the request.
// FromIterator<Bytes> for Name expects the caller to make an appropriate decision.
//
// PartialEq / Eq / Hash are written in a case-insensitive manner.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use cast::{self, u16, u32, u8, usize};
use idna::uts46;
use rmp;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::convert::AsRef;
use std::fmt;
use std::hash;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::{self, FromStr};

use msgpack::{Msgpack, ZoneReadError, ZoneWriteError};
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
            Ok(s.bytes().map(|b| b.to_ascii_lowercase()).collect())
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
/// Domain names are made up of labels. For the domain name `example.invalid` there are two labels,
/// `example` and `invalid`.
///
/// A domain name is fully-qualified if the rightmost label is a top-level domain.
///
/// Labels in pepbut are [`Bytes`]. The byte arrays always represent the ASCII/Punycode
/// representation of a label (the result of [UTS #46][uts46] processing). Labels may contain
/// mixed-case characters but are always compared case-insensitively hashed as lowercase.
///
/// [uts46]: https://www.unicode.org/reports/tr46/
///
/// ```
/// use pepbut::name::Name;
/// use std::str::FromStr;
///
/// let name = Name::from(vec!["EXAMPLE".into(), "INVALID".into()]);
/// let another = Name::from_str("example.invalid").unwrap();
/// assert_eq!(name, another);
/// ```
///
/// ## A note on binary names / RFC 2181 § 11
///
/// `Name` does not support arbitrary binary data.
///
/// [RFC 2181 § 11](https://tools.ietf.org/html/rfc2181#section-11) states:
///
/// > The DNS itself places only one restriction on the particular labels that can be used to
/// > identify resource records. That one restriction relates to the length of the label and the
/// > full name. The length of any one label is limited to between 1 and 63 octets. A full domain
/// > name is limited to 255 octets (including the separators). The zero length full name is
/// > defined as representing the root of the DNS tree, and is typically written and displayed as
/// > ".". Those restrictions aside, any binary string whatever can be used as the label of any
/// > resource record.
///
/// However, DNS servers are also expected to make case-insensitive matches on record names, and we
/// believe that is more important than binary names. If arbitrary binary data is used as a name
/// and any of the bytes happen to be ASCII lowercase letters, data corruption *will* occur.
#[derive(Clone, Debug, Default)]
pub struct Name(Vec<Bytes>);

impl Name {
    /// Returns a cloned name, skipping the first label.
    pub fn pop(&self) -> Name {
        Name(self.0.iter().skip(1).cloned().collect())
    }

    /// Extracts a slice of the labels in the name.
    pub fn as_slice(&self) -> &[Bytes] {
        self.0.as_slice()
    }

    /// Determine the number of bytes it will take to encode this label in a DNS message,
    /// accounting for name compression.
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
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| {
        a == b || ((a | 0x20) == (b | 0x20) && a.is_ascii_alphabetic() && b.is_ascii_alphabetic())
    })
}

macro_rules! eq_impl {
    ($a:expr, $b:expr) => {{
        $a.len() == $b.len() && $a.iter().zip($b.iter()).all(|(a, b)| eq_lower(a, b))
    }};
}

impl PartialEq for Name {
    fn eq(&self, rhs: &Name) -> bool {
        eq_impl!(self.0, rhs.0)
    }
}

impl PartialEq<Vec<Bytes>> for Name {
    fn eq(&self, rhs: &Vec<Bytes>) -> bool {
        eq_impl!(self.0, rhs)
    }
}

impl PartialEq<Vec<Vec<u8>>> for Name {
    fn eq(&self, rhs: &Vec<Vec<u8>>) -> bool {
        eq_impl!(self.0, rhs)
    }
}

impl<'a> PartialEq<Vec<&'a [u8]>> for Name {
    fn eq(&self, rhs: &Vec<&'a [u8]>) -> bool {
        eq_impl!(self.0, rhs)
    }
}

impl PartialEq<[Bytes]> for Name {
    fn eq(&self, rhs: &[Bytes]) -> bool {
        eq_impl!(self.0, rhs)
    }
}

impl PartialEq<[Vec<u8>]> for Name {
    fn eq(&self, rhs: &[Vec<u8>]) -> bool {
        eq_impl!(self.0, rhs)
    }
}

impl<'a> PartialEq<[&'a [u8]]> for Name {
    fn eq(&self, rhs: &[&'a [u8]]) -> bool {
        eq_impl!(self.0, rhs)
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

impl AsRef<[Bytes]> for Name {
    fn as_ref(&self) -> &[Bytes] {
        self.0.as_ref()
    }
}

impl AsRef<Vec<Bytes>> for Name {
    fn as_ref(&self) -> &Vec<Bytes> {
        self.0.as_ref()
    }
}

impl Borrow<[Bytes]> for Name {
    fn borrow(&self) -> &[Bytes] {
        self.0.borrow()
    }
}

impl Deref for Name {
    type Target = [Bytes];

    fn deref(&self) -> &[Bytes] {
        self.0.deref()
    }
}

impl Extend<Bytes> for Name {
    fn extend<T: IntoIterator<Item = Bytes>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

impl<'a> Extend<&'a Bytes> for Name {
    fn extend<T: IntoIterator<Item = &'a Bytes>>(&mut self, iter: T) {
        self.0.extend(iter.into_iter().cloned())
    }
}

impl From<Vec<Bytes>> for Name {
    fn from(v: Vec<Bytes>) -> Name {
        Name(v)
    }
}

impl<'a> From<&'a [Bytes]> for Name {
    fn from(v: &'a [Bytes]) -> Name {
        Name(v.to_vec())
    }
}

impl From<Name> for Vec<Bytes> {
    fn from(name: Name) -> Vec<Bytes> {
        name.0
    }
}

static LABEL_ARPA: &[u8] = b"arpa";
static LABEL_IN_ADDR: &[u8] = b"in-addr";
static LABEL_IP6: &[u8] = b"ip6";
static HEX_DIGITS: [&'static [u8; 1]; 16] = [
    b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9", b"a", b"b", b"c", b"d", b"e", b"f",
];
static OCTET_DECIMAL_2: [&'static [u8; 2]; 90] = [
    b"10", b"11", b"12", b"13", b"14", b"15", b"16", b"17", b"18", b"19", b"20", b"21", b"22",
    b"23", b"24", b"25", b"26", b"27", b"28", b"29", b"30", b"31", b"32", b"33", b"34", b"35",
    b"36", b"37", b"38", b"39", b"40", b"41", b"42", b"43", b"44", b"45", b"46", b"47", b"48",
    b"49", b"50", b"51", b"52", b"53", b"54", b"55", b"56", b"57", b"58", b"59", b"60", b"61",
    b"62", b"63", b"64", b"65", b"66", b"67", b"68", b"69", b"70", b"71", b"72", b"73", b"74",
    b"75", b"76", b"77", b"78", b"79", b"80", b"81", b"82", b"83", b"84", b"85", b"86", b"87",
    b"88", b"89", b"90", b"91", b"92", b"93", b"94", b"95", b"96", b"97", b"98", b"99",
];
static OCTET_DECIMAL_3: [&'static [u8; 3]; 156] = [
    b"100", b"101", b"102", b"103", b"104", b"105", b"106", b"107", b"108", b"109", b"110", b"111",
    b"112", b"113", b"114", b"115", b"116", b"117", b"118", b"119", b"120", b"121", b"122", b"123",
    b"124", b"125", b"126", b"127", b"128", b"129", b"130", b"131", b"132", b"133", b"134", b"135",
    b"136", b"137", b"138", b"139", b"140", b"141", b"142", b"143", b"144", b"145", b"146", b"147",
    b"148", b"149", b"150", b"151", b"152", b"153", b"154", b"155", b"156", b"157", b"158", b"159",
    b"160", b"161", b"162", b"163", b"164", b"165", b"166", b"167", b"168", b"169", b"170", b"171",
    b"172", b"173", b"174", b"175", b"176", b"177", b"178", b"179", b"180", b"181", b"182", b"183",
    b"184", b"185", b"186", b"187", b"188", b"189", b"190", b"191", b"192", b"193", b"194", b"195",
    b"196", b"197", b"198", b"199", b"200", b"201", b"202", b"203", b"204", b"205", b"206", b"207",
    b"208", b"209", b"210", b"211", b"212", b"213", b"214", b"215", b"216", b"217", b"218", b"219",
    b"220", b"221", b"222", b"223", b"224", b"225", b"226", b"227", b"228", b"229", b"230", b"231",
    b"232", b"233", b"234", b"235", b"236", b"237", b"238", b"239", b"240", b"241", b"242", b"243",
    b"244", b"245", b"246", b"247", b"248", b"249", b"250", b"251", b"252", b"253", b"254", b"255",
];

impl From<IpAddr> for Name {
    fn from(addr: IpAddr) -> Name {
        match addr {
            IpAddr::V4(a) => a.into(),
            IpAddr::V6(a) => a.into(),
        }
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(indexing_slicing))]
impl From<Ipv4Addr> for Name {
    fn from(addr: Ipv4Addr) -> Name {
        macro_rules! idx {
            ($idx:expr) => {
                Bytes::from_static(match $idx {
                    0...9 => HEX_DIGITS[$idx as usize],
                    10...99 => OCTET_DECIMAL_2[($idx - 10) as usize],
                    100...255 => OCTET_DECIMAL_3[($idx - 100) as usize],
                    _ => unreachable!(),
                })
            };
        }

        let octets = addr.octets();
        Name(vec![
            idx!(octets[3]),
            idx!(octets[2]),
            idx!(octets[1]),
            idx!(octets[0]),
            Bytes::from_static(LABEL_IN_ADDR),
            Bytes::from_static(LABEL_ARPA),
        ])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(indexing_slicing))]
impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        macro_rules! idx {
            ($idx:expr) => {
                Bytes::from_static(HEX_DIGITS[$idx as usize])
            };
        }

        let octets = addr.octets();
        Name(vec![
            idx!(octets[15] & 0xf),
            idx!(octets[15] >> 4),
            idx!(octets[14] & 0xf),
            idx!(octets[14] >> 4),
            idx!(octets[13] & 0xf),
            idx!(octets[13] >> 4),
            idx!(octets[12] & 0xf),
            idx!(octets[12] >> 4),
            idx!(octets[11] & 0xf),
            idx!(octets[11] >> 4),
            idx!(octets[10] & 0xf),
            idx!(octets[10] >> 4),
            idx!(octets[9] & 0xf),
            idx!(octets[9] >> 4),
            idx!(octets[8] & 0xf),
            idx!(octets[8] >> 4),
            idx!(octets[7] & 0xf),
            idx!(octets[7] >> 4),
            idx!(octets[6] & 0xf),
            idx!(octets[6] >> 4),
            idx!(octets[5] & 0xf),
            idx!(octets[5] >> 4),
            idx!(octets[4] & 0xf),
            idx!(octets[4] >> 4),
            idx!(octets[3] & 0xf),
            idx!(octets[3] >> 4),
            idx!(octets[2] & 0xf),
            idx!(octets[2] >> 4),
            idx!(octets[1] & 0xf),
            idx!(octets[1] >> 4),
            idx!(octets[0] & 0xf),
            idx!(octets[0] >> 4),
            Bytes::from_static(LABEL_IP6),
            Bytes::from_static(LABEL_ARPA),
        ])
    }
}

impl FromStr for Name {
    type Err = NameParseError;

    fn from_str(s: &str) -> Result<Name, NameParseError> {
        if s.is_empty() || s == "." {
            return Ok(Name(Vec::new()));
        }
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

impl FromIterator<Vec<u8>> for Name {
    fn from_iter<T: IntoIterator<Item = Vec<u8>>>(iter: T) -> Name {
        iter.into_iter().map(Bytes::from).collect()
    }
}

impl<'a> FromIterator<&'a [u8]> for Name {
    fn from_iter<T: IntoIterator<Item = &'a [u8]>>(iter: T) -> Name {
        iter.into_iter().map(Bytes::from).collect()
    }
}

impl IntoIterator for Name {
    type Item = Bytes;
    type IntoIter = ::std::vec::IntoIter<Bytes>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Name {
    type Item = &'a Bytes;
    type IntoIter = ::std::slice::Iter<'a, Bytes>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Msgpack for Name {
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Name, ZoneReadError> {
        let label_len = rmp::decode::read_array_len(reader)? as usize;
        let mut name_labels = Vec::with_capacity(label_len);
        for _ in 0..label_len {
            let label_idx: usize = rmp::decode::read_int(reader)?;
            name_labels.push(
                labels
                    .get(label_idx)
                    .ok_or_else(|| ZoneReadError::LabelIndexOutOfRange)?
                    .clone(),
            );
        }

        Ok(Name(name_labels))
    }

    fn to_msgpack(
        &self,
        writer: &mut impl Write,
        labels: &mut Vec<Bytes>,
    ) -> Result<(), ZoneWriteError> {
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

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::net::IpAddr;
    use std::str::FromStr;

    use name::Name;
    use wire::{ProtocolDecode, ProtocolEncode};

    macro_rules! label {
        ($e:expr) => {
            if $e.is_ascii() {
                Bytes::from_static($e.as_bytes())
            } else {
                use name::label_from_str;
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
        assert!(Name::from_str("example..invalid").is_err());
    }

    #[test]
    fn root() {
        assert_eq!(Name::from_str("").unwrap(), Name::default());
        assert_eq!(Name::from_str(".").unwrap(), Name::default());
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
            format!("{}", Name::from(IpAddr::V4([192, 0, 2, 42].into()))),
            "42.2.0.192.in-addr.arpa"
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

    // Check for slicing panics in impl From<IpAddr> for Name.
    #[test]
    fn from_ipaddr_exhaustive() {
        for i in 0..=u8::max_value() {
            Name::from(IpAddr::V4([i, 0, 0, 0].into()));
            Name::from(IpAddr::V6([i as u16, 0, 0, 0, 0, 0, 0, 0].into()));
        }
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
