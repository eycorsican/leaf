mod tcp;
mod udp;

use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;

use crate::{
    app::dispatcher::Dispatcher,
    app::nat_manager::NatManager,
    config::{Inbound, SocksInboundSettings},
    Runner,
};

pub use super::NAME;

pub fn new(
    inbound: &Inbound,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> Result<Runner> {
    let listen = inbound.listen.clone();
    let port = inbound.port.to_owned() as u16;

    let settings = protobuf::parse_from_bytes::<SocksInboundSettings>(&inbound.settings).unwrap();
    let mut bind = settings.bind;

    let mut runners: Vec<Runner> = Vec::new();

    if !bind.is_empty() {
        if let Ok(r) = udp::new(listen.clone(), port, nat_manager) {
            runners.push(r);
        }
    } else {
        bind = "0.0.0.0".to_string();
    }

    if let Ok(r) = tcp::new(listen, port, bind, dispatcher.clone()) {
        runners.push(r);
    }

    if runners.len() > 0 {
        return Ok(Box::pin(async move {
            futures::future::join_all(runners).await;
        }));
    } else {
        return Err(anyhow!("no runners"));
    }
}
