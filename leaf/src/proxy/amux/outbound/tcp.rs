use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::TryFutureExt;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::{mpsc, oneshot};

use crate::{
    app::dns_client::DnsClient,
    proxy::{
        OutboundConnect, OutboundHandler, ProxyStream, SimpleProxyStream, TcpConnector,
        TcpOutboundHandler,
    },
    session::{Session, SocksAddr},
};

use super::MuxClientConnection;
use super::MuxStream;

pub struct MuxManager {
    pub connections: Arc<TokioMutex<Vec<MuxClientConnection>>>,
    pub new_stream_req_tx: Sender<(Session, oneshot::Sender<MuxStream>)>,
    pub new_stream_req_task: TokioMutex<Option<BoxFuture<'static, ()>>>,
}

impl MuxManager {
    pub fn new(
        address: String,
        port: u16,
        actors: Vec<Arc<dyn OutboundHandler>>,
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        let (new_stream_req_tx, mut new_stream_req_rx) =
            mpsc::channel::<(Session, oneshot::Sender<MuxStream>)>(64);
        let connections: Arc<TokioMutex<Vec<MuxClientConnection>>> =
            Arc::new(TokioMutex::new(Vec::new()));
        let connections2 = connections.clone();
        let new_stream_req_task = Box::pin(async move {
            'req_recv: while let Some((mut sess, new_stream_send_tx)) =
                new_stream_req_rx.recv().await
            {
                for _ in 0..4 {
                    let mut connections = connections2.lock().await;
                    let mut to_remove = Vec::new();
                    for (i, conn) in connections.iter().enumerate() {
                        if conn.should_remove().await {
                            to_remove.push(i);
                        }
                    }
                    for i in to_remove.into_iter() {
                        connections.remove(i);
                    }
                    // TODO more efficient way?
                    for conn in connections.iter_mut() {
                        if let Ok(s) = conn.new_stream().await {
                            if let Err(_) = new_stream_send_tx.send(s) {
                                log::warn!("send new mux stream failed");
                            }
                            continue 'req_recv;
                        }
                    }
                    drop(connections);

                    let mut conn = match crate::proxy::dial_tcp_stream(
                        dns_client.clone(),
                        &bind_addr,
                        &address,
                        &port,
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(e) => {
                            log::warn!("dial tcp failed: {}", e);
                            continue 'req_recv;
                        }
                    };

                    if let Ok(addr) = SocksAddr::try_from(format!("{}:{}", &address, &port)) {
                        sess.destination = addr;
                    }
                    for (_, a) in actors.iter().enumerate() {
                        match a.handle_tcp(&sess, Some(conn)).await {
                            Ok(c) => {
                                conn = c;
                            }
                            Err(e) => {
                                log::warn!("handle tcp failed: {}", e);
                                continue 'req_recv;
                            }
                        }
                    }
                    let mux_conn = MuxClientConnection::new(conn);

                    connections2.lock().await.push(mux_conn);
                }
            }
        });
        MuxManager {
            connections,
            new_stream_req_tx,
            new_stream_req_task: TokioMutex::new(Some(new_stream_req_task)),
        }
    }

    pub async fn new_stream(&self, sess: &Session) -> io::Result<MuxStream> {
        if self.new_stream_req_task.lock().await.is_some() {
            if let Some(task) = self.new_stream_req_task.lock().await.take() {
                tokio::spawn(task);
            }
        }

        let (new_stream_send_tx, new_stream_send_rx) = oneshot::channel();
        let mut tx = (&self.new_stream_req_tx).clone();
        if let Err(_) = tx.send((sess.clone(), new_stream_send_tx)).await {
            log::warn!("send new stream req failed");
        }
        new_stream_send_rx
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("new stream failed: {}", e)))
            .await
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
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        Handler {
            manager: MuxManager::new(address, port, actors, bind_addr, dns_client),
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
