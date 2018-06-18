extern crate clap;
extern crate failure;
extern crate pepbut;

use clap::{App, Arg};
use pepbut::text_zone;
use std::fs::{self, File};

fn main() -> Result<(), failure::Error> {
    let matches = App::new("pepbut-zone-convert")
        .arg(Arg::with_name("INPUT").help("input file").required(true))
        .arg(Arg::with_name("OUTPUT").help("output file").required(true))
        .get_matches();

    text_zone::read(&fs::read_to_string(matches.value_of("INPUT").unwrap())?)?
        .write_to(&mut File::create(matches.value_of("OUTPUT").unwrap())?)?;
    Ok(())
}
