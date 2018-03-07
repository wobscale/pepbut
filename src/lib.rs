#![cfg_attr(feature = "nightly", feature(test))]

#[macro_use]
extern crate failure;
extern crate rmp;
#[cfg(feature = "nightly")]
extern crate test;
extern crate trust_dns;
#[cfg(feature = "pepbutd")]
extern crate trust_dns_server;

pub mod name;
pub mod record;
pub mod zone;

#[cfg(feature = "pepbutd")]
pub use zone::Zone;
