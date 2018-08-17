use pepbut::authority::Authority;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "kebab-case")]
pub enum Request {
    ListZones,
}

pub fn handle_request(request: Request, authority: &Arc<RwLock<Authority>>) -> impl Serialize {
    match request {
        Request::ListZones => list_zones(authority),
    }
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
