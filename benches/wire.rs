// SPDX-License-Identifier: AGPL-3.0-only

use bytes::{Bytes, BytesMut};
use criterion::Criterion;
use std::collections::HashMap;
use std::io::Cursor;
use std::str::FromStr;

use pepbut::name::Name;
use pepbut::record::{RData, Record};
use pepbut::wire::{ProtocolDecode, ProtocolEncode, QueryMessage};
use pepbut::zone::LookupResult;

fn decode(c: &mut Criterion) {
    c.bench_function("QueryMessage::decode", |b| {
        b.iter(|| {
            QueryMessage::decode(&mut Cursor::new(Bytes::from_static(&[
                0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
                0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            ]))).unwrap()
        })
    });
}

fn encode(c: &mut Criterion) {
    c.bench_function("ResponseMessage::encode", |b| {
        let records = vec![Record::new(
            Name::from_str("google.com").unwrap(),
            293,
            RData::A([216, 58, 211, 142].into()),
        )];
        let message = QueryMessage::decode(&mut Cursor::new(Bytes::from_static(&[
            0x86, 0x2a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ]))).unwrap()
            .respond(LookupResult::Records(&records));
        b.iter(|| {
            message
                .encode(&mut BytesMut::new(), &mut HashMap::new())
                .unwrap();
        })
    });
}

criterion_group!(wire, decode, encode);
