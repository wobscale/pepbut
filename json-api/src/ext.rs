use futures::{Future, Stream};
use hyper::body::Payload;
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Request, StatusCode};
use serde::de::DeserializeOwned;
use serde_json;
use serde_urlencoded;

use super::{Error, HttpResult};

pub trait RequestExt: Sized {
    fn deserialize<T: DeserializeOwned>(self) -> HttpResult<Request<T>>;
}

impl RequestExt for Request<Body> {
    fn deserialize<T: DeserializeOwned>(self) -> HttpResult<Request<T>> {
        let (parts, body) = self.into_parts();
        if body.content_length().is_none() {
            return Err(Error::code(StatusCode::LENGTH_REQUIRED));
        }
        if body.content_length() == Some(0) {
            return Err(Error::new(
                StatusCode::BAD_REQUEST,
                "a request body is required",
            ));
        }
        let chunk = body.concat2().wait()?;
        let body = match parts.headers.get(CONTENT_TYPE).map(|t| t.as_bytes()) {
            Some(b"application/json") => serde_json::from_slice(&chunk)?,
            Some(b"application/x-www-form-urlencoded") => serde_urlencoded::from_bytes(&chunk)?,
            Some(t) => {
                return Err(
                    format!("content-type {} not accepted", String::from_utf8_lossy(t)).into(),
                );
            }
            None => return Err("missing content-type".into()),
        };
        Ok(Request::from_parts(parts, body))
    }
}
