use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::client_async_with_config;
use tungstenite::protocol::WebSocketConfig;
use url::Url;

use crate::{
    proxy::{ProxyStream, ProxyTcpHandler, SimpleStream},
    session::Session,
};

use super::stream;

pub struct Handler {
    pub path: String,
    // FIXME headers
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        let mut url = Url::parse(&format!("ws://{}", sess.destination.to_string())).unwrap();
        url = url.join(self.path.as_str()).unwrap();
        match stream {
            Some(stream) => {
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
                let ws_stream = stream::Adapter::new(socket);
                Ok(Box::new(SimpleStream(ws_stream)))
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid tls input")),
        }
    }
}
