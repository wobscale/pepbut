// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use failure;
use std::io::{Read, Write};

/// A trait for objects that can be serialized to or deserialized within the context of serializing
/// or deserializing zones.
pub(crate) trait Msgpack: Sized {
    /// Deserialize this object from a MessagePack reader.
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Self, failure::Error>;

    /// Serialize this object to a MessagePack reader.
    fn to_msgpack(&self, &mut impl Write, labels: &mut Vec<Bytes>) -> Result<(), failure::Error>;
}
