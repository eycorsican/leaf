use std::convert::TryFrom;
use std::{net::IpAddr, pin::Pin, sync::Arc, task::Poll};

use anyhow::Result;
use futures::future::{self, Future};
use hyper::{server::conn::Http, service::Service, Body, Request, Response};
use log::*;
use tokio::{net::TcpListener, stream::StreamExt};

use crate::{
    app::dispatcher::Dispatcher,
    config::Inbound,
    session::{Session, SocksAddr},
    Runner,
};

struct ProxyService {
    uri: String,
}

impl ProxyService {
    pub fn new() -> Self {
        ProxyService {
            uri: "".to_string(),
        }
    }

    pub fn get_uri(&self) -> &String {
        &self.uri
    }
}

impl Service<Request<Body>> for ProxyService {
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;
    type Response = Response<Body>;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        self.uri = req.uri().to_string();
        Box::pin(future::ready(Ok(Response::builder()
            .status(200)
            .body(hyper::Body::empty())
            .unwrap())))
    }

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

pub fn new(inbound: Inbound, dispatcher: Arc<Dispatcher>) -> Result<Runner> {
    let t = async move {
        let mut listener =
            TcpListener::bind(format!("{}:{}", inbound.listen, inbound.port).as_str())
                .await
                .unwrap();
        info!(
            "http inbound listening tcp {}:{}",
            inbound.listen, inbound.port
        );
        while let Some(stream) = listener.next().await {
            if let Ok(stream) = stream {
                let dispatcher = dispatcher.clone();
                tokio::spawn(async move {
                    let source = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            warn!("invalid peer addr {}", e);
                            return;
                        }
                    };
                    let http = Http::new();
                    let proxy_service = ProxyService::new();
                    let conn = http
                        .serve_connection(stream, proxy_service)
                        .without_shutdown();
                    let parts = match conn.await {
                        Ok(v) => v,
                        Err(err) => {
                            debug!("accept conn failed: {}", err);
                            return;
                        }
                    };

                    let uri = parts.service.get_uri();
                    let host_port: Vec<&str> = uri.split(':').collect();
                    if host_port.len() != 2 {
                        debug!("invalid target {:?}", uri);
                        return;
                    }

                    let destination = if let Ok(port) = host_port[1].parse::<u16>() {
                        if let Ok(ip) = host_port[0].parse::<IpAddr>() {
                            SocksAddr::from((ip, port))
                        } else {
                            match SocksAddr::try_from((host_port[0], port)) {
                                Ok(v) => v,
                                Err(err) => {
                                    debug!("invalid target {:?}: {}", uri, err);
                                    return;
                                }
                            }
                        }
                    } else {
                        debug!("invalid target {:?}", uri);
                        return;
                    };

                    let sess = Session {
                        source: Some(source),
                        destination,
                    };

                    // dispatch err logging was handled in dispatcher
                    let _ = dispatcher.dispatch_tcp(&sess, parts.io).await;
                });
            }
        }
    };

    Ok(Box::pin(t))
}
