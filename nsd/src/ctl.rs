// SPDX-License-Identifier: AGPL-3.0-only

use erased_serde;
use failure;
use pepbut::authority::Authority;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "kebab-case")]
pub enum Request {
    ListZones,
    LoadZone { path: PathBuf },
}

pub fn handle_request(request: Request, authority: &Arc<RwLock<Authority>>) -> impl Serialize {
    debug!("control socket request: {:?}", request);
    let b: Box<erased_serde::Serialize + Send> = match request {
        Request::ListZones => Box::new(list_zones(authority)),
        Request::LoadZone { path } => {
            Box::new(load_zone(authority, path).map_err(|err| format!("{}", err)))
        }
    };
    b
}

fn list_zones(authority: &Arc<RwLock<Authority>>) -> HashMap<String, u32> {
    authority
        .read()
        .unwrap_or_else(|_| fatal!("authority is poisoned"))
        .zones
        .iter()
        .map(|(name, zone)| (name.to_string(), zone.serial))
        .collect()
}

fn load_zone(
    authority: &Arc<RwLock<Authority>>,
    path: PathBuf,
) -> Result<(String, u32), failure::Error> {
    authority
        .write()
        .unwrap_or_else(|_| fatal!("authority is poisoned"))
        .load_zonefile(path)
        .map(|(name, serial)| (name.to_string(), serial))
}
