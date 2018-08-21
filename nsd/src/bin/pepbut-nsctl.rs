// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(feature = "cargo-clippy", warn(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(use_self, stutter))]

extern crate clap;
#[macro_use]
extern crate failure;
extern crate pepbut_nsd;
extern crate serde_json;
extern crate tabwriter;

use clap::{App, Arg, SubCommand};
use failure::ResultExt;
use pepbut_nsd::ctl::Request;
use std::collections::HashMap;
use std::fs;
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
        .subcommand(
            SubCommand::with_name("load-zone")
                .about("Load zone from a file")
                .arg(
                    Arg::with_name("path")
                        .value_name("FILE")
                        .help("Zone file to load")
                        .takes_value(true)
                        .required(true),
                ),
        )
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
        ("load-zone", Some(matches)) => Request::LoadZone {
            path: fs::canonicalize(matches.value_of("path").expect("unreachable").to_owned())
                .context("could not canonicalize path")?,
        },
        _ => unreachable!(),
    };

    serde_json::to_writer(&ctl_socket, &request).context("Unable to write request to socket")?;
    ctl_socket
        .shutdown(Shutdown::Write)
        .context("Unable to shutdown write half of socket")?;

    macro_rules! response {
        () => {
            serde_json::from_reader(ctl_socket).context("Unable to read response from socket")
        };
    }

    match request {
        Request::ListZones => {
            let response: HashMap<String, u32> = response!()?;
            let mut tw = TabWriter::new(io::stdout());
            for (zone, serial) in response {
                writeln!(tw, "{}\t{}", zone, serial)?;
            }
            tw.flush()?;
        }
        Request::LoadZone { .. } => {
            let response: Result<(String, u32), String> = response!()?;
            if let Err(err) = response {
                bail!(err);
            }
        }
    }

    Ok(())
}
