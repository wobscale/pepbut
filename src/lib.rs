//! pepbut is the code for [Wobscale](https://wobscale.website)'s authoritative DNS service.
//!
//! It consists of an API service for updating records, a web interface that uses the API for users
//! to update records, and the authoritative DNS server itself.

#![feature(test)]
#![feature(vec_remove_item)]
#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

extern crate byteorder;
#[macro_use]
extern crate failure;
extern crate idna;
extern crate rmp;
extern crate test;

/// Macros used globally across pepbut.
#[macro_use]
mod macros {
    macro_rules! read_exact {
        ($r: expr, $c: expr) => {{
            #[allow(unused_imports)]
            use std::io::Read;

            let mut buf = Vec::with_capacity($c as usize);
            buf.resize($c as usize, 0);
            $r.read_exact(&mut buf[..]).map(|()| buf)
        }};
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn read_exact() {
            assert_eq!(read_exact!(&b"hello world"[..], 5).unwrap(), b"hello");
            assert!(read_exact!(&b"hello world"[..], 15).is_err());
        }
    }
}

pub mod name;
pub mod record;
pub mod wire;
pub mod zone;

use std::io::{Read, Write};
use std::rc::Rc;

/// A trait for objects that can be serialized to or deserialized within the context of serializing
/// or deserializing zones.
trait Msgpack: Sized {
    /// Deserialize this object from a MessagePack reader.
    fn from_msgpack<R>(reader: &mut R, labels: &[Rc<[u8]>]) -> Result<Self, failure::Error>
    where
        R: Read;

    /// Serialize this object to a MessagePack reader.
    fn to_msgpack<W>(&self, &mut W, labels: &mut Vec<Rc<[u8]>>) -> Result<(), failure::Error>
    where
        W: Write;
}
