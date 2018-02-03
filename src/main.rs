extern crate trust_dns;
extern crate trust_dns_server;

use std::net::UdpSocket;
use trust_dns::op::{Message, ResponseCode};
use trust_dns_server::server::{Request, RequestHandler, ServerFuture};

struct Handler {}

impl RequestHandler for Handler {
    fn handle_request(&self, request: &Request) -> Message {
        Message::error_msg(
            request.message.id(),
            request.message.op_code(),
            ResponseCode::ServFail,
        )
    }
}

fn main() {
    let mut server = ServerFuture::new(Handler {}).unwrap();
    server.register_socket(UdpSocket::bind("127.0.0.1:5335").unwrap());
    server.listen().unwrap();
}
