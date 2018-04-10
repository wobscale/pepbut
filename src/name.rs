//! Domain names and labels.

// ParseNameError uses a Debug format for uts46::Errors which is an opaque type. Because Fail is
// derived, we can't apply this cfg_attr to only that struct.
#![cfg_attr(feature = "cargo-clippy", allow(use_debug))]

use failure;
use idna::uts46;
use rmp;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use std::str::{self, FromStr};

use Msgpack;
use wire::{ProtocolDecode, ProtocolDecodeError};

/// Errors that can occur while parsing a `Name`.
#[derive(Debug, Fail)]
pub enum ParseNameError {
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

/// Constructs a label from a raw byte array. This method only checks that the length of the
/// label is 63 characters or less, and assumes that the bytes are lowercase ASCII.
///
/// This method should only be used if you already know the label has been encoded and is lowercase
/// (e.g. you are reading from a binary zone file or from a lowercased DNS query message).
pub fn label_from_raw_bytes(bytes: &[u8]) -> Result<Rc<[u8]>, ParseNameError> {
    if bytes.len() > 63 {
        Err(ParseNameError::LabelTooLong(bytes.len()))
    } else {
        Ok(Rc::from(bytes))
    }
}

/// Validates and constructs a label from a string. This method normalizes the label to
/// lowercase ASCII, converting non-ASCII characters into Punycode according to UTS #46.
fn label_from_str(s: &str) -> Result<Rc<[u8]>, ParseNameError> {
    /// Checks if a byte is valid for a DNS label.
    fn byte_ok(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-'
    }

    if s.is_empty() {
        Err(ParseNameError::EmptyLabel)
    } else if (s.starts_with('_') && s.bytes().skip(1).all(byte_ok)) || s.bytes().all(byte_ok) {
        label_from_raw_bytes(s.to_lowercase().as_bytes())
    } else {
        label_from_raw_bytes(
            uts46::to_ascii(
                s,
                uts46::Flags {
                    use_std3_ascii_rules: true,
                    transitional_processing: true,
                    verify_dns_length: true,
                },
            ).map_err(ParseNameError::InvalidLabel)?
                .as_bytes(),
        )
    }
}

/// A fully-qualified domain name.
///
/// Domain names are made up of labels. For the domain name `example.invalid`, there are two
/// labels, `example` and `invalid`.
///
/// A domain name is fully-qualified if the rightmost label is a top-level domain.
///
/// Labels in pepbut are atomically reference-counted byte arrays (`Rc<[u8]>`). The byte arrays
/// always represent the canonical representation of a label (the result of [UTS #46][uts46]
/// processing, commonly the lowercase ASCII/Punycode form).
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Name(Vec<Rc<[u8]>>);

impl Name {
    /// Clones and appends all labels in an origin `Name` to this `Name`.
    pub fn extend(&mut self, origin: &Name) {
        self.0.extend(origin.0.iter().cloned())
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
    type Err = ParseNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Name((if s.ends_with('.') {
            &s[0..(s.len() - 1)]
        } else {
            s
        }).split('.')
            .map(label_from_str)
            .collect::<Result<Vec<_>, _>>()?))
    }
}

impl Msgpack for Name {
    fn from_msgpack<R>(reader: &mut R, labels: &[Rc<[u8]>]) -> Result<Self, failure::Error>
    where
        R: Read,
    {
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

    #[cfg_attr(feature = "cargo-clippy", allow(cast_possible_truncation))]
    fn to_msgpack<W>(
        &self,
        writer: &mut W,
        labels: &mut Vec<Rc<[u8]>>,
    ) -> Result<(), failure::Error>
    where
        W: Write,
    {
        rmp::encode::write_array_len(writer, self.0.len() as u32)?;

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
    fn decode<T>(buf: &mut Cursor<T>) -> Result<Self, ProtocolDecodeError>
    where
        T: AsRef<[u8]>,
    {
        let mut name = Name(Vec::new());
        let mut orig_pos = 0;
        let mut jumps = 0;

        loop {
            let length = u8::decode(buf)?;
            if length == 0 {
                if jumps > 0 {
                    buf.set_position(orig_pos);
                }
                return Ok(name);
            } else if length > 63 {
                let offset = ((u16::from(length) & 0x3f) << 8) + u16::from(u8::decode(buf)?);
                if jumps == 0 {
                    orig_pos = buf.position();
                } else if jumps == 20 {
                    return Err(ProtocolDecodeError::NamePointerRecursionLimitReached);
                }
                jumps += 1;
                buf.set_position(offset.into());
            } else {
                name.0.push(Rc::from(read_exact!(buf, length)?));
            }
        }
    }
}

thread_local! {
    static LABEL_ARPA: Rc<[u8]> = Rc::from(*b"arpa");
    static LABEL_IN_ADDR: Rc<[u8]> = Rc::from(*b"in-addr");
    static LABEL_IP6: Rc<[u8]> = Rc::from(*b"ip6");
}

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
        LABEL_ARPA.with(|arpa| {
            LABEL_IN_ADDR.with(|in_addr| {
                let mut name = Vec::with_capacity(6);
                let octets = addr.octets();
                for i in 0..4 {
                    name.push(Rc::from(format!("{}", octets[3 - i]).as_bytes()));
                }
                name.push(in_addr.clone());
                name.push(arpa.clone());
                Name(name)
            })
        })
    }
}

impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        LABEL_ARPA.with(|arpa| {
            LABEL_IP6.with(|ip6| {
                let mut name = Vec::with_capacity(34);
                let octets = addr.octets();
                for i in 0..16 {
                    name.push(Rc::from(format!("{:x}", octets[15 - i] & 0xf).as_bytes()));
                    name.push(Rc::from(format!("{:x}", octets[15 - i] >> 4).as_bytes()));
                }
                name.push(ip6.clone());
                name.push(arpa.clone());
                Name(name)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use test::Bencher;

    use name::{label_from_str, Name};
    use wire::ProtocolDecode;

    macro_rules! label {
        ($e: expr) => {
            label_from_str($e).unwrap()
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
    fn empty_label() {
        assert!(Name::from_str("").is_err());
    }

    #[test]
    fn from_str() {
        assert_eq!(
            Name::from_str("buttslol.net.").unwrap(),
            Name(vec![label!("buttslol"), label!("net")])
        );
        assert_eq!(
            Name::from_str("BUTTSLOL.net.").unwrap(),
            Name(vec![label!("buttslol"), label!("net")])
        );
        assert_eq!(Name::from_str("tld").unwrap(), Name(vec![label!("tld")]));
        assert_eq!(
            Name::from_str("☃.net.").unwrap(),
            Name(vec![label!("☃"), label!("net")])
        );
        assert_eq!(
            Name::from_str("EXAMPLE-☃.net.").unwrap(),
            Name(vec![label!("example-☃"), label!("net")])
        );
        assert_eq!(
            Name::from_str("_sip._udp.wobscale.website").unwrap(),
            Name(vec![
                label!("_sip"),
                label!("_udp"),
                label!("wobscale"),
                label!("website"),
            ])
        );
    }

    #[test]
    fn decode() {
        let mut buf = Cursor::new(b"\x07example\x07invalid\0\x04blah\xc0\x08");
        assert_eq!(
            Name::decode(&mut buf).unwrap(),
            Name(vec![label!("example"), label!("invalid")])
        );
        assert_eq!(buf.position(), 17);
        assert_eq!(
            Name::decode(&mut buf).unwrap(),
            Name(vec![label!("blah"), label!("invalid")])
        );
        assert_eq!(buf.position(), 24);
    }

    #[test]
    fn decode_infinite() {
        let mut buf = Cursor::new(b"\xc0\x00");
        assert!(Name::decode(&mut buf).is_err());
    }

    #[test]
    fn from_ipv4addr() {
        assert_eq!(
            format!("{}", Name::from(IpAddr::V4([192, 0, 2, 1].into()))),
            "1.2.0.192.in-addr.arpa"
        );
    }

    #[bench]
    fn bench_from_ipv4addr(b: &mut Bencher) {
        b.iter(|| Name::from(Ipv4Addr::new(192, 0, 2, 1)))
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

    #[bench]
    fn bench_from_ipv6addr(b: &mut Bencher) {
        b.iter(|| Name::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    }
}
