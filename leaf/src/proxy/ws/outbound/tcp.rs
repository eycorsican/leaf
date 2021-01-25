use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::client_async_with_config;
use tungstenite::protocol::WebSocketConfig;
use url::Url;

use crate::{
    app::dns_client::DnsClient,
    proxy::{OutboundConnect, ProxyStream, SimpleProxyStream, TcpOutboundHandler},
    session::Session,
};

use super::stream;

pub struct Handler {
    pub path: String,
    // FIXME headers
    pub dns_client: Arc<DnsClient>,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        None
    }

    async fn handle_tcp<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        if let Some(stream) = stream {
            let mut url = Url::parse(&format!("ws://{}", sess.destination.to_string())).unwrap();
            url = url.join(self.path.as_str()).unwrap();
            let ws_config = WebSocketConfig {
                max_send_queue: Some(1),
                max_message_size: Some(64 << 20),
                max_frame_size: Some(16 << 20),
            };
            let (socket, _) = client_async_with_config(&url, stream, Some(ws_config))
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("connect ws {} failed: {}", &url, e),
                    )
                })
                .await?;
            let ws_stream = stream::WebSocketToStream::new(socket);
            Ok(Box::new(SimpleProxyStream(ws_stream)))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
