extern crate futures;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate serde_json;

mod never;

use futures::future::{self, FutureResult};
use futures::{Future, IntoFuture, Stream};
use hyper::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Method, Request, Response, StatusCode};
use regex::{Regex, RegexSet};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;

use never::Never;

/// This method assumes that `route` starts with a `/`.
fn pattern_to_regex(route: &str) -> String {
    let mut re = String::from("^");
    for thunk in route.split('/').skip(1) {
        re += &if thunk.starts_with(':') {
            format!("/(?P<{}>[^/]+)", thunk.get(1..).unwrap_or(""))
        } else {
            format!("/{}", thunk)
        };
    }
    re + "/?"
}

fn finish_response(res: Response<Option<Value>>) -> Response<Body> {
    let mut res = res;
    if res.body().is_some() {
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    res.map(|value| match value {
        Some(value) => Body::from(format!("{:#}\n", value)),
        None => Body::empty(),
    })
}

macro_rules! req_try {
    ($e:expr, $code:expr) => {{
        match $e {
            Ok(v) => v,
            Err(e) => return err!($code, &format!("{}", e)),
        }
    }};

    ($e:expr) => {{
        use hyper::StatusCode;
        req_try!($e, StatusCode::INTERNAL_SERVER_ERROR)
    }};
}

macro_rules! err {
    ($code:expr, $err:expr) => {{
        use hyper::{header::HeaderValue, Response};
        let mut response = Response::default();
        *response.status_mut() = $code;
        if let Ok(v) = HeaderValue::from_str($err) {
            response.headers_mut().insert("X-Pepbut-Error", v);
        }
        response
    }};
}

macro_rules! code {
    ($code:expr) => {{
        use hyper::Response;
        let mut response = Response::default();
        *response.status_mut() = $code;
        response
    }};
}

pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: Request<Option<Value>>) -> Response<Option<Value>>;
}

impl<F> Handler for F
where
    F: Send + Sync + 'static + Fn(Request<Option<Value>>) -> Response<Option<Value>>,
{
    fn handle(&self, req: Request<Option<Value>>) -> Response<Option<Value>> {
        (*self)(req)
    }
}

pub trait BeforeMiddleware: Send + Sync + 'static {
    fn before(&self, req: &mut Request<Option<Value>>) -> Result<(), Response<Option<Value>>>;
}

impl<F> BeforeMiddleware for F
where
    F: Send
        + Sync
        + 'static
        + Fn(&mut Request<Option<Value>>) -> Result<(), Response<Option<Value>>>,
{
    fn before(&self, req: &mut Request<Option<Value>>) -> Result<(), Response<Option<Value>>> {
        (*self)(req)
    }
}

struct Route {
    pattern: String,
    // If there are no URL parameters for this route, this is None
    regex: Option<Regex>,
    capture_names: Vec<String>,
    handlers: HashMap<Method, Box<Handler>>,
}

impl PartialEq for Route {
    fn eq(&self, other: &Route) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for Route {}

impl PartialOrd for Route {
    fn partial_cmp(&self, other: &Route) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Route {
    fn cmp(&self, other: &Route) -> Ordering {
        let mut lhs = self.pattern.chars();
        let mut rhs = other.pattern.chars();
        loop {
            match (lhs.next(), rhs.next()) {
                (None, _) => return Ordering::Less,
                (_, None) => return Ordering::Greater,
                (Some(':'), Some(':')) => (),
                (Some(':'), Some(_)) => return Ordering::Greater,
                (Some(_), Some(':')) => return Ordering::Less,
                (Some(lb), Some(rb)) => match lb.cmp(&rb) {
                    Ordering::Equal => (),
                    non_eq => return non_eq,
                },
            }
        }
    }
}

#[derive(Debug)]
pub struct PatternMatches(pub HashMap<String, Option<String>>);

pub struct Service {
    regexes: RegexSet,
    routes: Vec<Route>,
    before: Vec<Box<BeforeMiddleware>>,
}

impl Service {
    pub fn builder() -> ServiceBuilder {
        ServiceBuilder(HashMap::new())
    }

    pub fn before<B: BeforeMiddleware>(&mut self, before: B) {
        self.before.push(Box::new(before))
    }

    fn handle_request(&mut self, req: Request<Body>) -> Response<Body> {
        if let Some(route) = self
            .regexes
            .matches(req.uri().path())
            .iter()
            .filter_map(|i| self.routes.get(i))
            .next()
        {
            if let Some(handler) = route.handlers.get(req.method()) {
                let (parts, body) = req.into_parts();
                let body = if let Some(value) = parts.headers.get(CONTENT_TYPE) {
                    if parts.headers.get(CONTENT_LENGTH).is_none() {
                        return code!(StatusCode::LENGTH_REQUIRED);
                    }
                    if value == "application/json" {
                        Some(req_try!(serde_json::from_slice(&req_try!(
                            body.concat2().wait()
                        ))))
                    } else {
                        return err!(StatusCode::BAD_REQUEST, "only application/json is accepted");
                    }
                } else {
                    None
                };
                let mut req = Request::from_parts(parts, body);
                if let Some(ref re) = route.regex {
                    if let Some(captures) = re.captures(&req.uri().path().to_owned()) {
                        let mut matches = HashMap::new();
                        for name in &route.capture_names {
                            matches.insert(
                                name.to_owned(),
                                captures.name(name).map(|m| m.as_str().to_owned()),
                            );
                        }
                        req.extensions_mut().insert(PatternMatches(matches));
                    }
                }
                for f in &self.before {
                    if let Err(res) = f.before(&mut req) {
                        return finish_response(res);
                    }
                }
                finish_response((**handler).handle(req))
            } else {
                code!(StatusCode::METHOD_NOT_ALLOWED)
            }
        } else {
            code!(StatusCode::NOT_FOUND)
        }
    }
}

impl hyper::service::Service for Service {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = Never;
    type Future = FutureResult<Response<Body>, Never>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        future::ok(self.handle_request(req))
    }
}

impl IntoFuture for Service {
    type Future = FutureResult<Service, Never>;
    type Item = Service;
    type Error = Never;

    fn into_future(self) -> FutureResult<Service, Never> {
        future::ok(self)
    }
}

pub struct ServiceBuilder(HashMap<String, HashMap<Method, Box<Handler>>>);

impl ServiceBuilder {
    pub fn finalize(self) -> Result<Service, regex::Error> {
        let mut routes: Vec<_> = self
            .0
            .into_iter()
            .map(|(k, v)| {
                Ok(Route {
                    pattern: k.to_owned(),
                    regex: None,
                    capture_names: vec![],
                    handlers: v,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        routes.sort_unstable();

        lazy_static! {
            static ref RE_CAPTURE_NAMES: Regex = Regex::new("/:([^/]+)").unwrap();
        }

        let mut regexes = Vec::new();
        for route in &mut routes {
            let re = pattern_to_regex(&route.pattern);
            if route.pattern.contains("/:") {
                route.regex = Some(Regex::new(&re)?);
                for capture in RE_CAPTURE_NAMES.captures_iter(&route.pattern) {
                    if let Some(s) = capture.get(1) {
                        route.capture_names.push(s.as_str().to_owned());
                    }
                }
            }
            regexes.push(re);
        }

        Ok(Service {
            regexes: RegexSet::new(regexes)?,
            routes,
            before: Vec::new(),
        })
    }

    pub fn route<P: AsRef<str>, H: Handler>(
        mut self,
        pattern: P,
        method: Method,
        handler: H,
    ) -> ServiceBuilder {
        {
            let map = self
                .0
                .entry(pattern.as_ref().to_owned())
                .or_insert_with(HashMap::new);
            if map.contains_key(&method) {
                panic!("duplicate route added: {} {}", method, pattern.as_ref());
            }
            map.insert(method, Box::new(handler));
        }
        self
    }

    pub fn get<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::GET, handler)
    }

    pub fn post<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::POST, handler)
    }

    pub fn put<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::PUT, handler)
    }

    pub fn delete<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::DELETE, handler)
    }

    pub fn head<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::HEAD, handler)
    }

    pub fn options<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::OPTIONS, handler)
    }

    pub fn connect<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::CONNECT, handler)
    }

    pub fn patch<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::PATCH, handler)
    }

    pub fn trace<P: AsRef<str>, H: Handler>(self, pattern: P, handler: H) -> ServiceBuilder {
        self.route(pattern, Method::TRACE, handler)
    }
}

#[cfg(test)]
mod tests {
    use hyper::Response;
    use regex::Regex;

    use super::{pattern_to_regex, Service};

    #[test]
    fn pattern_to_regex_works() {
        Regex::new(&pattern_to_regex("/foo/:id/baz/:blah")).unwrap();
    }

    #[test]
    fn create_service() {
        Service::builder()
            .get("/hello", |_| Response::default())
            .put("/hello", |_| Response::default())
            .get("/hello/:id", |_| Response::default())
            .get("/hello/goodbye", |_| Response::default())
            .get("/hello/hello", |_| Response::default())
            .finalize()
            .unwrap();
    }
}
