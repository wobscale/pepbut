use futures::future::FutureResult;
use futures::IntoFuture;
use hyper::{Request, Response};
use pepbut::authority::Authority;
use pepbut_json_api::Service;
use regex;
use serde_json::Value;
use std::sync::{Arc, RwLock};

#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn get_zones(req: Request<Option<Value>>) -> Response<Option<Value>> {
    let authority = req
        .extensions()
        .get::<Arc<RwLock<Authority>>>()
        .unwrap_or_else(|| fatal!("unable to get authority"));
    Response::new(Some(Value::Object(
        authority
            .read()
            .unwrap_or_else(|_| fatal!("authority is poisoned"))
            .zones
            .iter()
            .map(|(name, zone)| (name.to_string(), zone.serial.into()))
            .collect(),
    )))
}

pub struct ControlService(Arc<RwLock<Authority>>);

impl ControlService {
    pub fn new(authority: Arc<RwLock<Authority>>) -> ControlService {
        ControlService(authority)
    }

    fn build(&self) -> Result<Service, regex::Error> {
        let authority = self.0.clone();
        let mut service = Service::builder().get("/zones", get_zones).finalize()?;
        service.before(move |req: &mut Request<Option<Value>>| {
            req.extensions_mut().insert(authority.clone());
            Ok(())
        });
        Ok(service)
    }
}

impl IntoFuture for ControlService {
    type Future = FutureResult<Service, regex::Error>;
    type Item = Service;
    type Error = regex::Error;

    fn into_future(self) -> Self::Future {
        self.build().into()
    }
}
