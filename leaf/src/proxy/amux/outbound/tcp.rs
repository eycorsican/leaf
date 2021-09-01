use std::convert::TryFrom;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use tokio::sync::Mutex;

use crate::{
    app::SyncDnsClient,
    proxy::*,
    session::{Session, SocksAddr},
};

use super::MuxConnector;
use super::MuxSession;
use super::MuxStream;

pub struct MuxManager {
    pub address: String,
    pub port: u16,
    pub actors: Vec<AnyOutboundHandler>,
    pub max_accepts: usize,
    pub concurrency: usize,
    pub dns_client: SyncDnsClient,
    // TODO Verify whether the run loops in connectors are aborted after
    // a config reload.
    pub connectors: Arc<Mutex<Vec<MuxConnector>>>,
    pub monitor_task: Mutex<Option<BoxFuture<'static, ()>>>,
}

impl MuxManager {
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<AnyOutboundHandler>,
        max_accepts: usize,
        concurrency: usize,
        dns_client: SyncDnsClient,
    ) -> (Self, Vec<AbortHandle>) {
        let mut abort_handles = Vec::new();
        let connectors: Arc<Mutex<Vec<MuxConnector>>> = Arc::new(Mutex::new(Vec::new()));
        let connectors2 = connectors.clone();
        // A task to monitor and remove completed connectors.
        // TODO passive detection
        let fut = async move {
            loop {
                connectors2.lock().await.retain(|c| !c.is_done());
                log::trace!("active connectors {}", connectors2.lock().await.len());
                tokio::time::sleep(Duration::from_secs(120)).await;
            }
        };
        let (abortable, abort_handle) = abortable(fut);
        abort_handles.push(abort_handle);
        let monitor_task: BoxFuture<'static, ()> = Box::pin(abortable.map(|_| ()));
        (
            MuxManager {
                address,
                port,
                actors,
                max_accepts,
                concurrency,
                dns_client,
                connectors,
                monitor_task: Mutex::new(Some(monitor_task)),
            },
            abort_handles,
        )
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
            .new_tcp_stream(self.dns_client.clone(), &self.address, &self.port)
            .await?;
        let mut sess = sess.clone();
        if let Ok(addr) = SocksAddr::try_from((&self.address, self.port)) {
            sess.destination = addr;
        }
        for (_, a) in self.actors.iter().enumerate() {
            conn = TcpOutboundHandler::handle(a.as_ref(), &sess, Some(conn)).await?;
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
        actors: Vec<AnyOutboundHandler>,
        max_accepts: usize,
        concurrency: usize,
        dns_client: SyncDnsClient,
    ) -> (Self, Vec<AbortHandle>) {
        let (manager, abort_handles) =
            MuxManager::new(address, port, actors, max_accepts, concurrency, dns_client);
        (Handler { manager }, abort_handles)
    }
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::NoConnect)
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        Ok(Box::new(self.manager.new_stream(sess).await?))
    }
}
