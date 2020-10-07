use std::net::SocketAddr;
use std::{io, sync::Arc};

use async_trait::async_trait;
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    proxy::{ProxyHandler, ProxyStream, ProxyTcpHandler},
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn ProxyHandler>>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let mut rng = StdRng::from_entropy();
        let i: usize = rng.gen_range(0, self.actors.len());
        self.actors[i].handle(sess, None).await
    }
}
