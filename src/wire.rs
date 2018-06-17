//! DNS wire message encoding and decoding.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use cast::{self, u16};
use std::collections::HashMap;
use std::io::Cursor;

use name::Name;
use zone::LookupResult;

pub fn encode_err(id: u16, rcode: u8) -> Bytes {
    let mut buf = BytesMut::with_capacity(8);
    // ID
    buf.put_u16_be(id);
    // QR + Opcode + AA + TC + RD
    buf.put_u8(0b1000_0000_u8);
    // RA + Z + RCODE
    buf.put_u8(rcode);
    // QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    buf.put_u64_be(0);
    buf.freeze()
}

/// Types that implement `ProtocolDecode` can be decoded from a DNS message packet.
pub trait ProtocolDecode: Sized {
    /// Read this type off the buffer.
    fn decode(buf: &mut Cursor<Bytes>) -> Result<Self, ProtocolDecodeError>;
}

pub trait ProtocolEncode {
    /// Write this type onto a buffer.
    fn encode(&self, buf: &mut BytesMut, names: &mut HashMap<Name, u16>)
        -> Result<(), cast::Error>;
}

/// The various types of errors that can occur when attempting to decode a protocol message on the
/// wire.
#[derive(Debug, Fail)]
pub enum ProtocolDecodeError {
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
    /// Creates a [`ResponseMessage`] given a [`LookupResult`].
    pub fn respond(self, answer: LookupResult) -> ResponseMessage {
        ResponseMessage {
            query: self,
            answer,
        }
    }
}

impl ProtocolDecode for QueryMessage {
    fn decode(buf: &mut Cursor<Bytes>) -> Result<QueryMessage, ProtocolDecodeError> {
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
        let id = buf.get_u16_be();
        if buf.get_u8() & 0b1111_1010 != 0 {
            return Err(ProtocolDecodeError::UnacceptableHeader);
        }
        buf.advance(1);

        // Next, check that QDCOUNT is at least 1. Questions after the first are ignored, but if
        // there's at least one question then we don't have an issue.
        let qdcount = buf.get_u16_be();
        if qdcount < 1 {
            return Err(ProtocolDecodeError::NoQuestions);
        }
        let other_count = buf.get_u16_be() + buf.get_u16_be() + buf.get_u16_be();

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
        let name = Name::decode(buf)?;
        let record_type = buf.get_u16_be();
        if buf.get_u16_be() != 1 {
            return Err(ProtocolDecodeError::UnacceptableClass);
        }

        // Read off the rest of the questions and other sections to reach EDNS
        for _ in 1..qdcount {
            Name::decode(buf)?;
            buf.advance(4);
        }
        for _ in 0..other_count {
            Name::decode(buf)?;
            buf.advance(8);
            let len = buf.get_u16_be();
            buf.advance(len as usize);
        }

        Ok(QueryMessage {
            id,
            name,
            record_type,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct ResponseMessage<'a> {
    pub query: QueryMessage,
    pub answer: LookupResult<'a>,
}

impl<'a> ProtocolEncode for ResponseMessage<'a> {
    fn encode(
        &self,
        buf: &mut BytesMut,
        names: &mut HashMap<Name, u16>,
    ) -> Result<(), cast::Error> {
        buf.reserve(12);
        // ID
        buf.put_u16_be(self.query.id);

        // +--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|
        // +--+--+--+--+--+--+--+--+
        buf.put_u8(if self.answer.authoritative() {
            0b1000_0100_u8
        } else {
            0b1000_0000_u8
        });

        // +--+--+--+--+--+--+--+--+
        // |RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+
        buf.put_u8(self.answer.rcode());

        // QDCOUNT
        buf.put_u16_be(1);
        // ANCOUNT, NSCOUNT, ARCOUNT
        for x in &self.answer.counts() {
            buf.put_u16_be(u16(*x)?);
        }

        // Question section
        self.query.name.encode(buf, names)?;
        buf.reserve(8);
        buf.put_u16_be(self.query.record_type);
        buf.put_u16_be(1);

        // Answer, authority, and additional sections
        self.answer.encode(buf, names)
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::str::FromStr;

    use name::Name;
    use record::{RData, Record};
    use wire::{ProtocolDecode, ProtocolEncode, QueryMessage, ResponseMessage};
    use zone::LookupResult;

    #[test]
    fn decode_query() {
        assert_eq!(
            QueryMessage::decode(&mut Cursor::new(Bytes::from_static(&[
                0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            ]))).unwrap(),
            QueryMessage {
                id: 0x862a,
                name: Name::from_str("google.com").unwrap(),
                record_type: 1,
            }
        );
    }

    #[test]
    fn encode_response() {
        let mut buf = BytesMut::new();
        let mut names = HashMap::new();
        ResponseMessage {
            query: QueryMessage {
                id: 0x862a,
                name: Name::from_str("google.com").unwrap(),
                record_type: 1,
            },
            answer: LookupResult::Records(&vec![Record::new(
                Name::from_str("google.com").unwrap(),
                293,
                RData::A([216, 58, 211, 142].into()),
            )]),
        }.encode(&mut buf, &mut names)
            .unwrap();
        assert_eq!(
            buf,
            vec![
                0x86, 0x2a, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
                0xd3, 0x8e,
            ]
        );
    }
}
