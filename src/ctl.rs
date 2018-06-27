#![cfg(feature = "nsd")]

use failure;
use futures::future::{self, FutureResult, IntoFuture};
use hyper::service::Service;
use hyper::{Body, Method, Request, Response, StatusCode};
use serde_json::Value;
use std::sync::{Arc, RwLock};

use authority::Authority;
use never::Never;

pub struct ControlService {
    authority: Arc<RwLock<Authority>>,
}

impl ControlService {
    pub fn new(authority: Arc<RwLock<Authority>>) -> ControlService {
        ControlService { authority }
    }

    fn get_zones(&self) -> Result<Value, failure::Error> {
        Ok(Value::Object(
            self.authority
                .read()
                .map_err(|_| failure::err_msg("unable to lock authority for reading"))?
                .zones
                .iter()
                .map(|(name, zone)| (name.to_string(), zone.serial.into()))
                .collect(),
        ))
    }
}

impl Service for ControlService {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Never;
    type Future = FutureResult<Response<Body>, Never>;

    fn call(&mut self, req: Request<Body>) -> FutureResult<Response<Body>, Never> {
        future::ok({
            let mut response = Response::new(Body::empty());

            macro_rules! try500 {
                ($e:expr) => {
                    match $e {
                        Ok(x) => x,
                        Err(e) => {
                            error!("error in handler for {}: {}", req.uri().path(), e);
                            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            return future::ok(response);
                        }
                    }
                };
            }

            if let Some(value) = match (req.method(), req.uri().path()) {
                (&Method::GET, "/zones") => Some(try500!(self.get_zones())),
                _ => {
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    None
                }
            } {
                *response.body_mut() = Body::from(format!("{:#}\n", &value));
            }

            info!(
                "{} {} {}",
                response.status().as_u16(),
                req.method(),
                req.uri().path(),
            );
            response
        })
    }
}

impl IntoFuture for ControlService {
    type Future = FutureResult<ControlService, Never>;
    type Item = ControlService;
    type Error = Never;

    fn into_future(self) -> FutureResult<ControlService, Never> {
        future::ok(self)
    }
}
