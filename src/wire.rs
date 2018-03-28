//! DNS wire message encoding and decoding.

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Seek, SeekFrom};

use name::Name;

/// Types that implement `ProtocolDecode` can be decoded from a DNS message packet.
pub trait ProtocolDecode {
    /// Read this type off the buffer.
    fn decode<T>(buf: &mut Cursor<T>) -> Result<Self, ProtocolDecodeError>
    where
        Self: Sized,
        T: AsRef<[u8]>;
}

impl ProtocolDecode for u8 {
    fn decode<T>(buf: &mut Cursor<T>) -> Result<Self, ProtocolDecodeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(buf.read_u8()?)
    }
}

impl ProtocolDecode for u16 {
    fn decode<T>(buf: &mut Cursor<T>) -> Result<Self, ProtocolDecodeError>
    where
        T: AsRef<[u8]>,
    {
        Ok(buf.read_u16::<BigEndian>()?)
    }
}

/// The various types of errors that can occur when attempting to decode a protocol message on the
/// wire.
#[derive(Debug, Fail)]
pub enum ProtocolDecodeError {
    /// Generic IO error.
    #[fail(display = "IO error: {}", _0)]
    IOError(::std::io::Error),
    /// Too many name compression pointers were present in the name to be reasonable to decode.
    #[fail(display = "too many name compression pointers to be reasonable")]
    NamePointerRecursionLimitReached,
    /// No questions were present in the query.
    #[fail(display = "no questions present in query")]
    NoQuestions,
    /// Unacceptable query class.
    ///
    /// pepbut only responds to queries in the IN (Internet) class.
    #[fail(display = "unacceptable query class")]
    UnacceptableClass,
    /// Unacceptable query message header.
    ///
    /// pepbut only responds to queries where QR, OPCODE, and TC are all 0.
    #[fail(display = "unacceptable query header")]
    UnacceptableHeader,
}

#[cfg_attr(feature = "cargo-clippy", allow(fallible_impl_from))]
impl From<::std::io::Error> for ProtocolDecodeError {
    fn from(err: ::std::io::Error) -> Self {
        ProtocolDecodeError::IOError(err)
    }
}

/// A query message, one of the two message types in the DNS protocol (the other being
/// `ResponseMessage`).
#[derive(Debug, PartialEq)]
pub struct QueryMessage {
    /// A random identifier. Response packets must reply with the same `id`. Due to UDP being
    /// stateless, this is needed to prevent confusing responses with each other.
    pub id: u16,
    /// The name being queried.
    pub name: Name,
    /// The record type being queried.
    pub record_type: u16,
}

impl QueryMessage {
    /// Decodes a DNS query message.
    ///
    /// This does not implement `ProtocolDecode` because we are lazily skipping the answer,
    /// authority, and additional sections in the message.
    pub fn decode(buf: &[u8]) -> Result<QueryMessage, ProtocolDecodeError> {
        let mut buf = Cursor::new(buf);

        // A message begins with a header, length 12, then the question, answer, authority, and
        // additional sections.
        //
        // RFC 1035 § 4.1.1, Header section format:
        //
        // ```text
        // The header contains the following fields:
        //
        //                                     1  1  1  1  1  1
        //       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                      ID                       |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                    QDCOUNT                    |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                    ANCOUNT                    |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                    NSCOUNT                    |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                    ARCOUNT                    |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // ```
        //
        // In the context of a query that we care to respond to:
        //
        // * QR must be 0
        // * OPCODE must be 0
        // * AA is ignored
        // * TC must be 0
        // * RD is ignored
        // * RA is ignored
        // * Z is ignored
        // * RCODE is ignored
        //
        // First, check the length of `buf` is at least 12. Then, verify that QR, OPCODE, and TC
        // are all 0 (which is relatively easy as they all reside in the same byte).
        let id = u16::decode(&mut buf)?;
        if u8::decode(&mut buf)? & 0b1111_1010 != 0 {
            return Err(ProtocolDecodeError::UnacceptableHeader);
        }
        buf.seek(SeekFrom::Current(1))?;

        // Next, check that QDCOUNT is at least 1. Questions after the first are ignored, but if
        // there's at least one question then we don't have an issue.
        if u16::decode(&mut buf)? < 1 {
            return Err(ProtocolDecodeError::NoQuestions);
        }
        buf.seek(SeekFrom::Current(6))?;

        // Next after the header is the question section.
        //
        // RFC 1035 § 4.1.2, Question section format:
        //
        // ```text
        // The question section is used to carry the "question" in most queries,
        // i.e., the parameters that define what is being asked.  The section
        // contains QDCOUNT (usually 1) entries, each of the following format:
        //
        //                                     1  1  1  1  1  1
        //       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                                               |
        //     /                     QNAME                     /
        //     /                                               /
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                     QTYPE                     |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //     |                     QCLASS                    |
        //     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // ```
        let name = Name::decode(&mut buf)?;
        let record_type = u16::decode(&mut buf)?;
        if u16::decode(&mut buf)? != 1 {
            return Err(ProtocolDecodeError::UnacceptableClass);
        }

        Ok(QueryMessage {
            id,
            name,
            record_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use test::Bencher;

    use name::Name;
    use std::str::FromStr;
    use wire::QueryMessage;

    #[test]
    fn decode_query() {
        assert_eq!(
            QueryMessage::decode(&[
                0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            ]).unwrap(),
            QueryMessage {
                id: 0x862a,
                name: Name::from_str("google.com").unwrap(),
                record_type: 1,
            }
        );
    }

    #[bench]
    fn bench_decode(b: &mut Bencher) {
        b.iter(|| {
            QueryMessage::decode(&[
                0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            ]).unwrap()
        })
    }
}
