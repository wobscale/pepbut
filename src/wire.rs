//! DNS wire message encoding and decoding.

use bytes::{Buf, BufMut};
use cast::{self, u16};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Seek, SeekFrom};

use name::Name;
use record::RecordTrait;
use zone::LookupResult;

/// Types that implement `ProtocolDecode` can be decoded from a DNS message packet.
pub trait ProtocolDecode: Sized {
    /// Read this type off the buffer.
    fn decode(buf: &mut Cursor<impl AsRef<[u8]>>) -> Result<Self, ProtocolDecodeError>;
}

impl ProtocolDecode for u8 {
    fn decode(buf: &mut Cursor<impl AsRef<[u8]>>) -> Result<u8, ProtocolDecodeError> {
        Ok(buf.get_u8())
    }
}

impl ProtocolDecode for u16 {
    fn decode(buf: &mut Cursor<impl AsRef<[u8]>>) -> Result<u16, ProtocolDecodeError> {
        Ok(buf.get_u16_be())
    }
}

impl ProtocolDecode for u32 {
    fn decode(buf: &mut Cursor<impl AsRef<[u8]>>) -> Result<u32, ProtocolDecodeError> {
        Ok(buf.get_u32_be())
    }
}

#[derive(Debug, PartialEq)]
pub struct ResponseBuffer {
    pub(crate) writer: Vec<u8>,
    pub(crate) names: HashMap<Name, u16>,
}

impl ResponseBuffer {
    pub fn new() -> ResponseBuffer {
        ResponseBuffer {
            writer: Vec::new(),
            names: HashMap::new(),
        }
    }

    pub(crate) fn names(&self) -> HashSet<Name> {
        self.names.keys().cloned().collect()
    }
}

impl Default for ResponseBuffer {
    fn default() -> ResponseBuffer {
        ResponseBuffer::new()
    }
}

pub trait ProtocolEncode {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error>;
}

impl ProtocolEncode for u8 {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        buf.writer.put_u8(*self);
        Ok(())
    }
}

impl ProtocolEncode for u16 {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        buf.writer.put_u16_be(*self);
        Ok(())
    }
}

impl ProtocolEncode for u32 {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        buf.writer.put_u32_be(*self);
        Ok(())
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

impl From<::std::io::Error> for ProtocolDecodeError {
    fn from(err: ::std::io::Error) -> ProtocolDecodeError {
        ProtocolDecodeError::IOError(err)
    }
}

/// A query message, one of the two message types in the DNS protocol (the other being
/// `ResponseMessage`).
#[derive(Debug, PartialEq)]
pub struct QueryMessage {
    /// A random identifier. Response packets must reply with the same `id`. Due to UDP being
    /// stateless, this is needed to prevent confusing responses with each other.
    id: u16,
    /// The name being queried.
    name: Name,
    /// The record type being queried.
    record_type: u16,
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

    /// Creates a [`ResponseMessage`] given a [`LookupResult`].
    pub fn respond(self, answer: LookupResult) -> ResponseMessage {
        ResponseMessage {
            query: self,
            answer,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ResponseMessage<'a> {
    query: QueryMessage,
    answer: LookupResult<'a>,
}

impl<'a> ProtocolEncode for ResponseMessage<'a> {
    fn encode(&self, buf: &mut ResponseBuffer) -> Result<(), cast::Error> {
        // ID
        self.query.id.encode(buf)?;

        // +--+--+--+--+--+--+--+--+
        // |QR|   Opcode  |AA|TC|RD|
        // +--+--+--+--+--+--+--+--+
        (if self.answer.authoritative() {
            0b1000_0100_u8
        } else {
            0b1000_0000_u8
        }).encode(buf)?;

        // +--+--+--+--+--+--+--+--+
        // |RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+
        self.answer.rcode().encode(buf)?;

        // QDCOUNT
        1_u16.encode(buf)?;
        // ANCOUNT, NSCOUNT, ARCOUNT
        for x in &self.answer.counts() {
            u16(*x)?.encode(buf)?;
        }

        // Question section
        self.query.name.encode(buf)?;
        self.query.record_type.encode(buf)?;
        1_u16.encode(buf)?;

        // Answer, authority, and additional sections
        macro_rules! encode_vec {
            ($v:expr) => {
                $v.iter()
                    .map(|record| (record as &RecordTrait).encode(buf))
                    .collect::<Result<Vec<()>, _>>()
                    .map(|_| ())
            };
        }
        match self.answer {
            LookupResult::Records(v) => encode_vec!(v)?,
            LookupResult::Delegated {
                authorities,
                ref glue_records,
            } => {
                encode_vec!(authorities)?;
                encode_vec!(glue_records)?;
            }
            LookupResult::NameExists(ref soa) | LookupResult::NoName(ref soa) => {
                (soa as &RecordTrait).encode(buf)?
            }
            LookupResult::NoZone => {}
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use name::Name;
    use record::{RData, Record};
    use wire::{ProtocolEncode, QueryMessage, ResponseBuffer, ResponseMessage};
    use zone::LookupResult;

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

    #[test]
    fn encode_response() {
        let mut buf = ResponseBuffer::new();
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
        }.encode(&mut buf)
            .unwrap();
        assert_eq!(
            vec![
                0x86, 0x2a, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
                0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
                0xd3, 0x8e,
            ],
            buf.writer,
        );
    }
}
