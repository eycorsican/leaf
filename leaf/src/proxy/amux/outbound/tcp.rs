use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::sync::Mutex;

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundHandler, ProxyStream, SimpleProxyStream, TcpConnector,
        TcpOutboundHandler,
    },
    session::{Session, SocksAddr},
};

use super::MuxConnector;
use super::MuxSession;
use super::MuxStream;

pub struct MuxManager {
    pub address: String,
    pub port: u16,
    pub actors: Vec<Arc<dyn OutboundHandler>>,
    pub max_accepts: usize,
    pub concurrency: usize,
    pub bind_addr: SocketAddr,
    pub dns_client: Arc<DnsClient>,
    pub connectors: Arc<Mutex<Vec<MuxConnector>>>,
    pub monitor_task: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl MuxManager {
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<Arc<dyn OutboundHandler>>,
        max_accepts: usize,
        concurrency: usize,
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        let connectors: Arc<Mutex<Vec<MuxConnector>>> = Arc::new(Mutex::new(Vec::new()));
        let connectors2 = connectors.clone();
        // A task to monitor and remove completed connectors.
        // TODO passive detection
        let monitor_task = Box::pin(async move {
            loop {
                connectors2.lock().await.retain(|c| !c.is_done());
                log::trace!("active connectors {}", connectors2.lock().await.len());
                use std::time::Duration;
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
        MuxManager {
            address,
            port,
            actors,
            max_accepts,
            concurrency,
            bind_addr,
            dns_client,
            connectors,
            monitor_task: Mutex::new(Some(monitor_task)),
        }
    }

    pub async fn new_stream(&self, sess: &Session) -> io::Result<MuxStream> {
        if self.monitor_task.lock().await.is_some() {
            if let Some(task) = self.monitor_task.lock().await.take() {
                tokio::spawn(task);
            }
        }

        for c in self.connectors.lock().await.iter_mut() {
            if let Some(s) = c.new_stream().await {
                return Ok(s);
            }
        }
        let mut conn = self
            .dial_tcp_stream(
                self.dns_client.clone(),
                &self.bind_addr,
                &self.address,
                &self.port,
            )
            .await?;
        let mut sess = sess.clone();
        if let Ok(addr) = SocksAddr::try_from(format!("{}:{}", &self.address, &self.port)) {
            sess.destination = addr;
        }
        for (_, a) in self.actors.iter().enumerate() {
            conn = a.handle_tcp(&sess, Some(conn)).await?;
        }
        let mut connector = MuxSession::connector(conn, self.max_accepts, self.concurrency);
        let s = match connector.new_stream().await {
            Some(s) => s,
            None => return Err(io::Error::new(io::ErrorKind::Other, "new stream failed")),
        };
        self.connectors.lock().await.push(connector);
        Ok(s)
    }
}

impl TcpConnector for MuxManager {}

pub struct Handler {
    manager: MuxManager,
}

impl Handler {
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<Arc<dyn OutboundHandler>>,
        max_accepts: usize,
        concurrency: usize,
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        Handler {
            manager: MuxManager::new(
                address,
                port,
                actors,
                max_accepts,
                concurrency,
                bind_addr,
                dns_client,
            ),
        }
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::NoConnect)
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        Ok(Box::new(SimpleProxyStream(
            self.manager.new_stream(sess).await?,
        )))
    }
}
