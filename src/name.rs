//! Domain names and labels.

use bytes::{Buf, BufMut, Bytes};
use cast::{self, u16, u32, u8, usize};
use failure;
use idna::uts46;
use rmp;
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::iter::FromIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};

use wire::{ProtocolDecode, ProtocolDecodeError, ProtocolEncode, ResponseBuffer};
use Msgpack;

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

/// Validates and constructs a label from a string. This method normalizes the label to
/// lowercase ASCII, converting non-ASCII characters into Punycode according to UTS #46.
fn label_from_str(s: &str) -> Result<Bytes, ParseNameError> {
    /// Checks if a byte is valid for a DNS label.
    fn byte_ok(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-'
    }

    if s.is_empty() {
        Err(ParseNameError::EmptyLabel)
    } else if (s.starts_with('_') && s.bytes().skip(1).all(byte_ok)) || s.bytes().all(byte_ok) {
        if s.len() > 63 {
            Err(ParseNameError::LabelTooLong(s.len()))
        } else {
            Ok(Bytes::from(s.to_lowercase().as_bytes()))
        }
    } else {
        let s = uts46::to_ascii(
            s,
            uts46::Flags {
                use_std3_ascii_rules: true,
                transitional_processing: true,
                verify_dns_length: true,
            },
        ).map_err(ParseNameError::InvalidLabel)?;
        if s.len() > 63 {
            Err(ParseNameError::LabelTooLong(s.len()))
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
/// Labels in pepbut are [`Bytes`]. The byte arrays always represent the canonical representation
/// of a label (the result of [UTS #46][uts46] processing, commonly the lowercase ASCII/Punycode
/// form).
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

    fn from_str(s: &str) -> Result<Name, ParseNameError> {
        Ok(Name((if s.ends_with('.') {
            &s[0..(s.len() - 1)]
        } else {
            s
        }).split('.')
            .map(label_from_str)
            .collect::<Result<Vec<_>, _>>()?))
    }
}

impl FromIterator<Bytes> for Name {
    fn from_iter<T: IntoIterator<Item = Bytes>>(iter: T) -> Name {
        Name(Vec::from_iter(iter))
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
    fn decode(buf: &mut Cursor<impl AsRef<[u8]>>) -> Result<Name, ProtocolDecodeError> {
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
                let start = usize(buf.position());
                let end = start + length as usize;
                buf.advance(length as usize);
                let label = &buf.get_ref().as_ref()[start..end];
                name.0.push(Bytes::from(label));
            }
        }
    }
}

impl ProtocolEncode for Name {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        let mut name = self.clone();
        while !name.0.is_empty() {
            let maybe_pos = buf.names.get(&name).cloned();
            if let Some(pos) = maybe_pos {
                return 0xc000_u16
                    .checked_add(pos)
                    .ok_or(::cast::Error::Underflow)?
                    .encode(buf);
            } else {
                buf.names.insert(name.clone(), u16(buf.writer.len())?);
                let label = name
                    .0
                    .first()
                    .expect("unreachable, we already checked name is not empty")
                    .clone();
                u8(label.len())?.encode(buf)?;
                buf.writer.put_slice(&label);
                name = name.pop();
            }
        }
        0_u8.encode(buf)
    }
}

thread_local! {
    static LABEL_ARPA: Bytes = Bytes::from_static(b"arpa");
    static LABEL_IN_ADDR: Bytes = Bytes::from_static(b"in-addr");
    static LABEL_IP6: Bytes = Bytes::from_static(b"ip6");
    static LABEL_INT_IPV4: Vec<Bytes> = (0..256).map(|i| Bytes::from(format!("{}", i).as_bytes())).collect();
    static LABEL_INT_IPV6: Vec<Bytes> = (0..16).map(|i| Bytes::from(format!("{:x}", i).as_bytes())).collect();
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
                LABEL_INT_IPV4.with(|int_vec| {
                    let mut name = Vec::with_capacity(6);
                    let octets = addr.octets();
                    for i in 0..4 {
                        name.push(int_vec[octets[3 - i] as usize].clone());
                    }
                    name.push(in_addr.clone());
                    name.push(arpa.clone());
                    Name(name)
                })
            })
        })
    }
}

impl From<Ipv6Addr> for Name {
    fn from(addr: Ipv6Addr) -> Name {
        LABEL_ARPA.with(|arpa| {
            LABEL_IP6.with(|ip6| {
                LABEL_INT_IPV6.with(|int_vec| {
                    let mut name = Vec::with_capacity(34);
                    let octets = addr.octets();
                    for i in 0..16 {
                        name.push(int_vec[(octets[15 - i] & 0xf) as usize].clone());
                        name.push(int_vec[(octets[15 - i] >> 4) as usize].clone());
                    }
                    name.push(ip6.clone());
                    name.push(arpa.clone());
                    Name(name)
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::net::IpAddr;
    use std::str::FromStr;

    use name::{label_from_str, Name};
    use wire::{ProtocolDecode, ProtocolEncode, ResponseBuffer};

    macro_rules! label {
        ($e:expr) => {
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
        let mut v = Vec::new();
        let mut buf = ResponseBuffer::new(&mut v);
        Name::from_str("example.com")
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        assert_eq!(
            buf,
            ResponseBuffer {
                writer: &mut b"\x07example\x03com\x00".to_vec(),
                names: hashmap! {
                    Name::from_str("example.com").unwrap() => 0,
                    Name::from_str("com").unwrap() => 8,
                },
            }
        );
    }

    #[test]
    fn encode_ns() {
        let mut v = Vec::new();
        let mut buf = ResponseBuffer::new(&mut v);
        Name::from_str("ns1.example.com")
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        Name::from_str("ns2.example.com")
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        assert_eq!(
            buf,
            ResponseBuffer {
                writer: &mut b"\x03ns1\x07example\x03com\x00\x03ns2\xc0\x04".to_vec(),
                names: hashmap! {
                    Name::from_str("ns1.example.com").unwrap() => 0,
                    Name::from_str("example.com").unwrap() => 4,
                    Name::from_str("com").unwrap() => 12,
                    Name::from_str("ns2.example.com").unwrap() => 17,
                },
            }
        );
    }
}
