use std::collections::HashMap;
use trust_dns::op::{Header, MessageType, OpCode, ResponseCode};
use trust_dns::rr::dnssec::SupportedAlgorithms;
use trust_dns::rr::LowerName;
use trust_dns_server::authority::{AuthLookup, Authority, MessageRequest, MessageResponse};
use trust_dns_server::server::ResponseHandler;
use trust_dns_server::server::{Request, RequestHandler};

use zonefile::Zone;

lazy_static! {
    static ref DNSSEC_ALGOS: SupportedAlgorithms = SupportedAlgorithms::new();
}

pub struct Handler {
    authorities: HashMap<LowerName, Authority>,
}

impl Handler {
    pub fn new() -> Self {
        Handler {
            authorities: HashMap::new(),
        }
    }

    pub fn upsert(&mut self, zone: Zone) {
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
