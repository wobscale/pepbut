use futures::{Future, Stream};
use hyper::body::Payload;
use hyper::header::CONTENT_TYPE;
use hyper::{Body, Request, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{self, Value};
use serde_urlencoded;

pub trait RequestExt: Sized {
    fn deserialize<T: DeserializeOwned>(self) -> Result<Request<T>, Response<Option<Value>>>;
}

impl RequestExt for Request<Body> {
    fn deserialize<T: DeserializeOwned>(self) -> Result<Request<T>, Response<Option<Value>>> {
        let (parts, body) = self.into_parts();
        if body.content_length().is_none() {
            return Err(code!(StatusCode::LENGTH_REQUIRED));
        }
        if body.content_length() == Some(0) {
            return Err(err!(StatusCode::BAD_REQUEST, "a request body is required"));
        }
        let chunk = req_try!(body.concat2().wait());
        let body = match parts.headers.get(CONTENT_TYPE).map(|t| t.as_bytes()) {
            Some(b"application/json") => req_try!(serde_json::from_slice(&chunk)),
            Some(b"application/x-www-form-urlencoded") => {
                req_try!(serde_urlencoded::from_bytes(&chunk))
            }
            Some(t) => {
                return Err(err!(
                    StatusCode::BAD_REQUEST,
                    format!("content-type {} not accepted", String::from_utf8_lossy(t))
                ))
            }
            None => return Err(err!(StatusCode::BAD_REQUEST, "missing content-type")),
        };
        Ok(Request::from_parts(parts, body))
    }
}
