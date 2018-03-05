#![cfg_attr(feature = "nightly", feature(test))]

#[macro_use]
extern crate failure;
extern crate rmpv;
#[cfg(feature = "nightly")]
extern crate test;
#[cfg(feature = "pepbutd")]
extern crate trust_dns;
#[cfg(feature = "pepbutd")]
extern crate trust_dns_server;

pub mod name;
pub mod record;
pub mod zone;

#[cfg(feature = "pepbutd")]
pub use name::TrustDnsConversionError;
pub use zone::Zone;
