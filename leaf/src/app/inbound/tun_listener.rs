use std::sync::Arc;

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::NatManager;
use crate::config::Inbound;
use crate::proxy::tun;
use crate::Runner;

use super::InboundListener;

pub struct TUNInboundListener {
    pub inbound: Inbound,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
}

impl InboundListener for TUNInboundListener {
    fn listen(&self) -> Vec<Runner> {
        let mut runners: Vec<Runner> = Vec::new();
        if let Ok(r) = tun::inbound::new(
            self.inbound.clone(),
            self.dispatcher.clone(),
            self.nat_manager.clone(),
        ) {
            runners.push(Box::pin(r));
        }
        runners
    }
}
