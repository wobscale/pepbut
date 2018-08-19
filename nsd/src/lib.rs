// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self))]

extern crate bytes;
extern crate cast;
extern crate erased_serde;
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate pepbut;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate tokio_codec;

pub mod codec;
pub mod ctl;
