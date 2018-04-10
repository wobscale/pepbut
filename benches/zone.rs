use criterion::Criterion;
use std::io::Cursor;

use pepbut::zone::Zone;

fn read_example_invalid(c: &mut Criterion) {
    let buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
    c.bench_function("read example.invalid.zone", move |b| {
        b.iter(|| {
            Zone::read_from(&mut Cursor::new(buf)).unwrap();
        });
    });
}

fn write_example_invalid(c: &mut Criterion) {
    let zone_buf: &[u8] = include_bytes!("../tests/data/example.invalid.zone");
    let zone = Zone::read_from(&mut Cursor::new(zone_buf)).unwrap();
    c.bench_function("write example.invalid.zone", move |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            zone.write_to(&mut buf).unwrap();
        })
    });
}

criterion_group!(zone, read_example_invalid, write_example_invalid);
