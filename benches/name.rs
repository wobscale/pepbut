// SPDX-License-Identifier: AGPL-3.0-only

use criterion::Criterion;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use pepbut::name::Name;

fn from_str(c: &mut Criterion) {
    c.bench_function("Name from ASCII", |b| {
        let s = "example.invalid";
        b.iter(|| Name::from_str(s).unwrap());
    });
}

fn from_unicode(c: &mut Criterion) {
    c.bench_function("Name from Unicode", |b| {
        let s = "☃.香港";
        b.iter(|| Name::from_str(s).unwrap());
    });
}

fn eq(c: &mut Criterion) {
    c.bench_function("impl PartialEq for Name", |b| {
        let addr = Ipv4Addr::new(192, 0, 2, 42);
        b.iter(|| addr.eq(&addr))
    });
}

fn hash(c: &mut Criterion) {
    c.bench_function("impl Hash for Name", |b| {
        let addr = Ipv4Addr::new(192, 0, 2, 42);
        b.iter(|| addr.hash(&mut DefaultHasher::new()));
    });
}

fn from_ipv4addr(c: &mut Criterion) {
    c.bench_function("Name from Ipv4Addr", |b| {
        let addr = Ipv4Addr::new(192, 0, 2, 42);
        b.iter(|| Name::from(addr))
    });
}

fn from_ipv6addr(c: &mut Criterion) {
    c.bench_function("Name from Ipv6Addr", |b| {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        b.iter(|| Name::from(addr))
    });
}

criterion_group!(
    name,
    from_str,
    from_unicode,
    eq,
    hash,
    from_ipv4addr,
    from_ipv6addr
);
