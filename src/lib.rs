//! pepbut is the code for [Wobscale](https://wobscale.website)'s authoritative DNS service.
//!
//! It consists of an API service for updating records, a web interface that uses the API for users
//! to update records, and the authoritative DNS server itself.

#![feature(conservative_impl_trait)]
#![feature(test)]
#![feature(vec_remove_item)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

#[macro_use]
extern crate failure;
extern crate idna;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
extern crate rmp;
extern crate test;

pub mod name;
pub mod record;
pub mod zone;

use std::io::{Read, Write};

use name::Label;

/// A trait for objects that can be serialized to or deserialized within the context of serializing
/// or deserializing zones.
trait Msgpack: Sized {
    /// Deserialize this object from a MessagePack reader.
    fn from_msgpack<R>(reader: &mut R, labels: &[Label]) -> Result<Self, failure::Error>
    where
        R: Read;

    /// Serialize this object to a MessagePack reader.
    fn to_msgpack<W>(&self, &mut W, labels: &mut Vec<Label>) -> Result<(), failure::Error>
    where
        W: Write;
}
