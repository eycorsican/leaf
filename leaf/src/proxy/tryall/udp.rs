use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::select_ok;

use crate::{
    proxy::{ProxyDatagram, ProxyHandler, ProxyStream, ProxyUdpHandler, UdpTransportType},
    session::Session,
};

pub struct Handler {
    pub actors: Vec<Arc<dyn ProxyHandler>>,
    pub delay_base: u32,
}

#[async_trait]
impl ProxyUdpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn udp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    fn udp_transport_type(&self) -> UdpTransportType {
        UdpTransportType::Unknown
    }

    async fn connect<'a>(
        &'a self,
        sess: &'a Session,
        _datagram: Option<Box<dyn ProxyDatagram>>,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyDatagram>> {
        let mut tasks = Vec::new();
        for (i, a) in self.actors.iter().enumerate() {
            let t = async move {
                if self.delay_base > 0 {
                    tokio::time::delay_for(std::time::Duration::from_millis(
                        (self.delay_base * i as u32) as u64,
                    ))
                    .await;
                }
                a.connect(sess, None, None).await
            };
            tasks.push(Box::pin(t));
        }
        match select_ok(tasks.into_iter()).await {
            Ok(v) => Ok(v.0),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("all outbound attempts failed, last error: {}", e),
            )),
        }
    }
}
