use std::collections::HashMap;
use std::io;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::client_async_with_config;
use tungstenite::protocol::WebSocketConfig;
use url::Url;

use crate::{proxy::*, session::Session};

pub struct Handler {
    pub path: String,
    pub headers: HashMap<String, String>,
}

struct Request<'a> {
    pub uri: &'a str,
    pub headers: &'a HashMap<String, String>,
}

impl<'a> tungstenite::client::IntoClientRequest for Request<'a> {
    fn into_client_request(
        self,
    ) -> tungstenite::error::Result<tungstenite::handshake::client::Request> {
        let mut builder = ::http::Request::builder()
            .method("GET")
            .uri(self.uri)
            .header("User-Agent", &*crate::option::HTTP_USER_AGENT);
        for (k, v) in self.headers.iter() {
            if k != "Host" {
                builder = builder.header(k, v);
            }
        }
        Ok(builder.body(())?)
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        if let Some(stream) = stream {
            let host = if let Some(host) = self.headers.get("Host") {
                host.to_owned()
            } else {
                sess.destination.host()
            };
            let mut url = Url::parse(&format!("ws://{}", host)).unwrap();
            url = url.join(self.path.as_str()).unwrap();
            let req = Request {
                uri: &url.to_string(),
                headers: &self.headers,
            };
            let ws_config = WebSocketConfig {
                max_send_queue: Some(4),
                max_message_size: Some(64 << 20),
                max_frame_size: Some(16 << 20),
                accept_unmasked_frames: false,
            };
            let (socket, _) = client_async_with_config(req, stream, Some(ws_config))
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("connect ws {} failed: {}", &url, e),
                    )
                })
                .await?;
            let ws_stream = super::ws_stream::WebSocketToStream::new(socket);
            Ok(Box::new(ws_stream))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid input"))
        }
    }
}
