// pepbut supports rust 1.26 and later; the uninhabited type (!) is not supported in that version.
#![cfg_attr(feature = "cargo-clippy", allow(empty_enum))]

use std::error::Error;
use std::fmt::{self, Display};

#[derive(Debug)]
pub enum Never {}

impl Error for Never {
    fn description(&self) -> &str {
        match *self {}
    }
}

impl Display for Never {
    fn fmt(&self, _fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {}
    }
}
