use criterion::Criterion;
use std::net::{Ipv4Addr, Ipv6Addr};

use pepbut::name::Name;

fn from_ipv4addr(c: &mut Criterion) {
    c.bench_function("Name from Ipv4Addr", |b| {
        b.iter(|| Name::from(Ipv4Addr::new(192, 0, 2, 1)))
    });
}

fn from_ipv6addr(c: &mut Criterion) {
    c.bench_function("Name from Ipv6Addr", |b| {
        b.iter(|| Name::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
    });
}

criterion_group!(name, from_ipv4addr, from_ipv6addr);
