// SPDX-License-Identifier: AGPL-3.0-only

//! pepbut is the code for [Wobscale](https://wobscale.website)'s authoritative DNS service.
//!
//! It consists of an API service for updating records, a web interface that uses the API for users
//! to update records, and the authoritative DNS server itself.
//!
//! If you are looking for a general-purpose DNS message library, this may provide the types you
//! want. Please keep in mind that the API is at the whim of what we need for the DNS service
//! project, and that support for record types is purposely limited.

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self, stutter))]

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

macro_rules! read_exact {
    ($r:expr, $c:expr) => {{
        #[allow(unused_imports)]
        use std::io::Read;

        let mut buf = Vec::with_capacity($c as usize);
        buf.resize($c as usize, 0);
        $r.read_exact(&mut buf[..]).map(|()| buf)
    }};
}

pub mod authority;
mod msgpack;
pub mod name;
pub mod record;
pub mod wire;
pub mod zone;
