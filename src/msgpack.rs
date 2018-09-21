// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use cast;
use rmp::decode::{NumValueReadError, ValueReadError};
use rmp::encode::ValueWriteError;
use rmp::Marker;
use std::io::{self, Read, Write};
use std::str::Utf8Error;

/// Convenience function for checking the length of a msgpack type and returning the appropriate
/// error if there is a mismatch.
pub(crate) fn check_len(ty: &'static str, expected: u32, actual: u32) -> Result<(), ZoneReadError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ZoneReadError::ArrayLength {
            ty,
            expected,
            actual,
        })
    }
}

/// Errors that can occur while reading a zone file.
#[derive(Debug, Fail)]
pub enum ZoneReadError {
    /// The array or bin was the wrong length.
    #[fail(
        display = "{} array size mismatch: expected {} but found {}",
        ty,
        expected,
        actual
    )]
    ArrayLength {
        ty: &'static str,
        expected: u32,
        actual: u32,
    },
    /// An [`io::Error`] occurred.
    #[fail(display = "IO error: {}", _0)]
    Io(io::Error),
    /// The label index was out of range for the number of labels defined at the end of the zone.
    #[fail(display = "label index out of range")]
    LabelIndexOutOfRange,
    /// The label is longer than 63 characters.
    #[fail(display = "label exceeds maximum length of 63: {}", _0)]
    LabelTooLong(usize),
    /// The number read was not in range for the type.
    #[fail(display = "out of range integral type conversion attempted")]
    NumberOutOfRange,
    /// The TXT record's data is not UTF-8 as pepbut requires.
    #[fail(display = "TXT record data is not UTF-8: {}", _0)]
    TxtRecordNotUtf8(Utf8Error),
    /// The data type read was not the data type expected.
    #[fail(display = "msgpack type mismatch: {:?}", _0)]
    TypeMismatch(Marker),
    /// The record type read is not supported by pepbut.
    #[fail(display = "unsupported record type: {}", _0)]
    UnsupportedRecordType(u16),
}

impl From<io::Error> for ZoneReadError {
    fn from(err: io::Error) -> ZoneReadError {
        ZoneReadError::Io(err)
    }
}

impl From<NumValueReadError> for ZoneReadError {
    fn from(err: NumValueReadError) -> ZoneReadError {
        match err {
            NumValueReadError::InvalidMarkerRead(err) | NumValueReadError::InvalidDataRead(err) => {
                ZoneReadError::Io(err)
            }
            NumValueReadError::TypeMismatch(marker) => ZoneReadError::TypeMismatch(marker),
            NumValueReadError::OutOfRange => ZoneReadError::NumberOutOfRange,
        }
    }
}

impl From<ValueReadError> for ZoneReadError {
    fn from(err: ValueReadError) -> ZoneReadError {
        match err {
            ValueReadError::InvalidMarkerRead(err) | ValueReadError::InvalidDataRead(err) => {
                ZoneReadError::Io(err)
            }
            ValueReadError::TypeMismatch(marker) => ZoneReadError::TypeMismatch(marker),
        }
    }
}

/// Errors that can occur while writing a zone file.
#[derive(Debug, Fail)]
pub enum ZoneWriteError {
    /// A [`cast::Error`] occurred.
    #[fail(display = "cast error: {}", _0)]
    Cast(cast::Error),
    /// An [`io::Error`] occurred.
    #[fail(display = "IO error: {}", _0)]
    Io(io::Error),
}

impl From<cast::Error> for ZoneWriteError {
    fn from(err: cast::Error) -> ZoneWriteError {
        ZoneWriteError::Cast(err)
    }
}

impl From<io::Error> for ZoneWriteError {
    fn from(err: io::Error) -> ZoneWriteError {
        ZoneWriteError::Io(err)
    }
}

impl From<ValueWriteError> for ZoneWriteError {
    fn from(err: ValueWriteError) -> ZoneWriteError {
        match err {
            ValueWriteError::InvalidMarkerWrite(err) | ValueWriteError::InvalidDataWrite(err) => {
                ZoneWriteError::Io(err)
            }
        }
    }
}

/// A trait for objects that can be serialized to or deserialized within the context of serializing
/// or deserializing zones.
pub(crate) trait Msgpack: Sized {
    /// Deserialize this object from a MessagePack reader.
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Self, ZoneReadError>;

    /// Serialize this object to a MessagePack writer.
    fn to_msgpack(
        &self,
        writer: &mut impl Write,
        labels: &mut Vec<Bytes>,
    ) -> Result<(), ZoneWriteError>;
}
