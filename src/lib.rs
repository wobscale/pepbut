//! pepbut is the code for [Wobscale](https://wobscale.website)'s authoritative DNS service.
//!
//! It consists of an API service for updating records, a web interface that uses the API for users
//! to update records, and the authoritative DNS server itself.
//!
//! If you are looking for a general-purpose DNS message library, this may provide the types you
//! want. Please keep in mind that the API is at the whim of what we need for the DNS service
//! project, and that support for record types is purposely limited.

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

extern crate bytes;
extern crate cast;
#[macro_use]
extern crate failure;
extern crate idna;
#[macro_use]
extern crate log;
#[cfg(test)]
#[macro_use]
extern crate maplit;
extern crate rmp;

/// Macros used globally across pepbut.
#[macro_use]
mod macros {
    macro_rules! read_exact {
        ($r:expr, $c:expr) => {{
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

pub mod authority;
pub mod name;
pub mod record;
pub mod wire;
pub mod zone;

use bytes::Bytes;
use std::io::{Read, Write};

/// A trait for objects that can be serialized to or deserialized within the context of serializing
/// or deserializing zones.
trait Msgpack: Sized {
    /// Deserialize this object from a MessagePack reader.
    fn from_msgpack(reader: &mut impl Read, labels: &[Bytes]) -> Result<Self, failure::Error>;

    /// Serialize this object to a MessagePack reader.
    fn to_msgpack(&self, &mut impl Write, labels: &mut Vec<Bytes>) -> Result<(), failure::Error>;
}
