#[macro_use]
extern crate lazy_static;
extern crate pepbut;
extern crate trust_dns;
extern crate trust_dns_server;

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;
use trust_dns::op::{Header, MessageType, OpCode, ResponseCode};
use trust_dns::rr::LowerName;
use trust_dns::rr::dnssec::SupportedAlgorithms;
use trust_dns::serialize::binary::{BinDecodable, BinDecoder};
use trust_dns_server::authority::{AuthLookup, Authority, MessageRequest, MessageResponse};
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler};
use trust_dns_server::ServerFuture;

use pepbut::Zone;

lazy_static! {
    static ref DNSSEC_ALGOS: SupportedAlgorithms = SupportedAlgorithms::new();
}

struct Handler {
    authorities: HashMap<LowerName, Authority>,
}

impl Handler {
    fn new() -> Self {
        Handler {
            authorities: HashMap::new(),
        }
    }

    fn upsert(&mut self, zone: Zone) {
        self.authorities
            .insert(LowerName::new(zone.origin()), zone.into());
    }

    fn find_auth_recurse<'a>(&'a self, name: &LowerName) -> Option<&'a Authority> {
        self.authorities.get(name).or_else(|| {
            let name = name.base_name();
            if name.is_root() {
                None
            } else {
                self.find_auth_recurse(&name)
            }
        })
    }

    fn lookup<'q, 'a>(&'a self, request: &'q MessageRequest) -> MessageResponse<'q, 'a> {
        for query in request.queries() {
            if let Some(authority) = self.find_auth_recurse(query.name()) {
                let mut response = MessageResponse::new(Some(request.raw_queries()));
                let mut response_header = Header::new();
                response_header.set_id(request.id());
                response_header.set_op_code(OpCode::Query);
                response_header.set_message_type(MessageType::Response);

                let lookup = authority.search(query, false, *DNSSEC_ALGOS);
                match lookup {
                    AuthLookup::Records(_) => {
                        if let AuthLookup::Records(ns) = authority.ns(false, *DNSSEC_ALGOS) {
                            response.name_servers(ns);
                        }
                    }
                    AuthLookup::NoName | AuthLookup::NameExists => {
                        if let AuthLookup::Records(soa) = authority.soa_secure(false, *DNSSEC_ALGOS)
                        {
                            response.name_servers(soa);
                        }
                    }
                };
                response_header.set_response_code(match lookup {
                    AuthLookup::NoName => ResponseCode::NXDomain,
                    AuthLookup::Records(_) | AuthLookup::NameExists => ResponseCode::NoError,
                });
                if let AuthLookup::Records(records) = lookup {
                    response_header.set_authoritative(true);
                    response.answers(records);
                }

                return response.build(response_header);
            }
        }

        MessageResponse::new(Some(request.raw_queries())).error_msg(
            request.id(),
            request.op_code(),
            ResponseCode::NXDomain,
        )
    }
}

impl RequestHandler for Handler {
    fn handle_request<R>(&self, request: &Request, response_handle: R) -> ::std::io::Result<()>
    where
        R: ResponseHandler + 'static,
    {
        response_handle.send(match request.message.message_type() {
            MessageType::Query => match request.message.op_code() {
                OpCode::Query => self.lookup(&request.message),
                _ => MessageResponse::new(Some(request.message.raw_queries())).error_msg(
                    request.message.id(),
                    request.message.op_code(),
                    ResponseCode::NotImp,
                ),
            },
            MessageType::Response => MessageResponse::new(Some(request.message.raw_queries()))
                .error_msg(
                    request.message.id(),
                    request.message.op_code(),
                    ResponseCode::FormErr,
                ),
        })
    }
}

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
