// SPDX-License-Identifier: AGPL-3.0-only

extern crate clap;
#[macro_use]
extern crate failure;
extern crate pepbut_nsd;
extern crate serde_json;
extern crate tabwriter;

use clap::{App, Arg, SubCommand};
use failure::ResultExt;
use pepbut_nsd::ctl::Request;
use serde_json::Value;
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use tabwriter::TabWriter;

static DEFAULT_SOCKET_PATH: &str = "/run/pepbut/nsd.sock";

fn main() -> Result<(), failure::Error> {
    let matches = App::new("pepbut-nsctl")
        .arg(
            Arg::with_name("socket_path")
                .short("s")
                .long("socket")
                .value_name("SOCKET_PATH")
                .help(&format!(
                    "Unix control socket to listen on (default {})",
                    DEFAULT_SOCKET_PATH
                ))
                .takes_value(true),
        )
        .subcommand(SubCommand::with_name("list-zones").about("List loaded zones"))
        .get_matches();
    if matches.subcommand_name().is_none() {
        eprintln!("error: a subcommand is required\n");
        eprintln!("{}", matches.usage());
        std::process::exit(1);
    }

    let ctl_socket_path = matches
        .value_of("socket_path")
        .unwrap_or(DEFAULT_SOCKET_PATH);
    let ctl_socket = UnixStream::connect(ctl_socket_path).with_context(|e| {
        format!(
            "Failed to connect to Unix socket at {}: {}",
            ctl_socket_path, e
        )
    })?;

    let request = match matches.subcommand() {
        ("list-zones", _) => Request::ListZones,
        _ => unreachable!(),
    };

    serde_json::to_writer(&ctl_socket, &request).context("Unable to write request to socket")?;
    ctl_socket
        .shutdown(Shutdown::Write)
        .context("Unable to shutdown write half of socket")?;
    let response =
        serde_json::from_reader(ctl_socket).context("Unable to read response from socket")?;

    match (request, response) {
        (Request::ListZones, Value::Object(v)) => {
            let mut tw = TabWriter::new(io::stdout());
            for (zone, serial) in v {
                writeln!(tw, "{}\t{}", zone, serial)?;
            }
            tw.flush()?;
        }
        _ => bail!("Unexpected response type for request"),
    }

    Ok(())
}
