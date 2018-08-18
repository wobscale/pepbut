// SPDX-License-Identifier: AGPL-3.0-only

extern crate bytes;
#[macro_use]
extern crate criterion;
extern crate pepbut;

mod name;
mod wire;
mod zone;

criterion_main!(name::name, wire::wire, zone::zone);
