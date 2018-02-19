#[macro_use]
extern crate lazy_static;
extern crate trust_dns;
extern crate trust_dns_proto;
extern crate trust_dns_server;

mod handler;
mod zonefile;

use std::env;
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use trust_dns::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns_server::ServerFuture;

use handler::Handler;
use zonefile::Zone;

fn main() {
    let mut handler = Handler::new();
    for zonefile in env::args().skip(1) {
        let mut buf = vec![];
        File::open(zonefile).unwrap().read_to_end(&mut buf).unwrap();
        handler.upsert(Zone::read(&mut BinDecoder::new(&buf)).unwrap());
    }
    let mut server = ServerFuture::new(handler).unwrap();
    server.register_socket(UdpSocket::bind("127.0.0.1:5335").unwrap());
    server.listen().unwrap();
}
