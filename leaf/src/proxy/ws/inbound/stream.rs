use std::io::{self, ErrorKind};

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio_tungstenite::accept_hdr_async;
use tungstenite::handshake::server::{Callback, ErrorResponse, Request, Response};

use crate::{proxy::*, session::Session};

struct SimpleCallback<'a> {
    sess: &'a mut Session,
    path: &'a str,
}

impl<'a> SimpleCallback<'a> {
    pub fn new(sess: &'a mut Session, path: &'a str) -> Self {
        Self { sess, path }
    }
}

impl<'a> Callback for SimpleCallback<'a> {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if request.uri().path() != self.path {
            return Err(::http::response::Response::builder()
                .status(::http::StatusCode::NOT_FOUND)
                .body(None)
                .unwrap());
        }
        if let Some(Ok(forwarded)) = request
            .headers()
            .get(&*crate::option::HTTP_FORWARDED_HEADER)
            .map(|x| x.to_str())
        {
            if let Some(f) = forwarded
                .split(',')
                .map(str::trim)
                .map(|x| x.parse::<IpAddr>())
                .take_while(|x| x.is_ok())
                .map(|x| x.unwrap())
                .last()
            {
                self.sess.forwarded_source.replace(f);
            }
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
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        Ok(InboundTransport::Stream(
            Box::new(super::ws_stream::WebSocketToStream::new(
                accept_hdr_async(stream, SimpleCallback::new(&mut sess, &self.path))
                    .map_err(|e| {
                        io::Error::new(ErrorKind::Other, format!("accept ws failed: {}", e))
                    })
                    .await?,
            )),
            sess,
        ))
    }
}
