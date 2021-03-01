use std::io;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::accept_hdr_async;
use tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};

use crate::{
    proxy::{InboundTransport, ProxyStream, SimpleProxyStream, TcpInboundHandler},
    session::Session,
};

use super::stream;

struct SimpleCallback {
    path: String,
}

impl Callback for SimpleCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if request.uri().path() != self.path {
            return Err(http::response::Response::builder()
                .status(http::StatusCode::NOT_FOUND)
                .body(None)
                .unwrap());
        }
        Ok(response)
    }
}

pub struct Handler {
    path: String,
}

impl Handler {
    pub fn new(path: String) -> Self {
        Handler { path }
    }
}

#[async_trait]
impl TcpInboundHandler for Handler {
    async fn handle_tcp<'a>(
        &'a self,
        sess: Session,
        stream: Box<dyn ProxyStream>,
    ) -> std::io::Result<InboundTransport> {
        let cb = SimpleCallback {
            path: self.path.clone(), // TODO optimize the copy
        };
        let socket = accept_hdr_async(stream, cb)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("accept ws failed: {}", e)))
            .await?;
        let ws_stream = stream::WebSocketToStream::new(socket);
        Ok(InboundTransport::Stream(
            Box::new(SimpleProxyStream(ws_stream)),
            sess,
        ))
    }
}
