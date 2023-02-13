use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::{
    task::{Context, Poll},
    Future,
};

use crate::{proxy::*, session::Session};

use super::QuicProxyStream;

struct Incoming {
    inner: quinn::Incoming,
    connectings: Vec<quinn::Connecting>,
    new_conns: Vec<quinn::NewConnection>,
    incoming_closed: bool,
}

impl Incoming {
    pub fn new(inner: quinn::Incoming) -> Self {
        Incoming {
            inner,
            connectings: Vec::new(),
            new_conns: Vec::new(),
            incoming_closed: false,
        }
    }
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // FIXME don't iterate and poll all

        if !self.incoming_closed {
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(connecting)) => {
                    self.connectings.push(connecting);
                }
                Poll::Ready(None) => {
                    self.incoming_closed = true;
                }
                Poll::Pending => (),
            }
        }

        let mut new_conns = Vec::new();
        let mut completed = Vec::new();
        for (idx, connecting) in self.connectings.iter_mut().enumerate() {
            match Pin::new(connecting).poll(cx) {
                Poll::Ready(Ok(new_conn)) => {
                    new_conns.push(new_conn);
                    completed.push(idx);
                }
                Poll::Ready(Err(e)) => {
                    log::debug!("quic connect failed: {}", e);
                    completed.push(idx);
                }
                Poll::Pending => (),
            }
        }
        if !new_conns.is_empty() {
            self.new_conns.append(&mut new_conns);
        }

        #[allow(unused_must_use)]
        for idx in completed.iter().rev() {
            self.connectings.swap_remove(*idx);
        }

        let mut stream: Option<Self::Item> = None;
        let mut completed = Vec::new();
        for (idx, new_conn) in self.new_conns.iter_mut().enumerate() {
            match Pin::new(&mut new_conn.bi_streams).poll_next(cx) {
                Poll::Ready(Some(Ok((send, recv)))) => {
                    let mut sess = Session {
                        source: new_conn.connection.remote_address(),
                        ..Default::default()
                    };
                    // TODO Check whether the index suitable for this purpose.
                    sess.stream_id = Some(send.id().index());
                    stream.replace(AnyBaseInboundTransport::Stream(
                        Box::new(QuicProxyStream { recv, send }),
                        sess,
                    ));
                    break;
                }
                Poll::Ready(Some(Err(e))) => {
                    log::debug!("new quic bidirectional stream failed: {}", e);
                    completed.push(idx);
                }
                Poll::Ready(None) => {
                    // FIXME what?
                    log::warn!("quic bidirectional stream exhausted");
                    completed.push(idx);
                }
                Poll::Pending => (),
            }
        }
        for idx in completed.iter().rev() {
            self.new_conns.remove(*idx);
        }

        if let Some(stream) = stream.take() {
            Poll::Ready(Some(stream))
        } else if self.incoming_closed && self.connectings.is_empty() && self.new_conns.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

fn quic_err<E>(error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}

pub struct Handler {
    server_config: quinn::ServerConfig,
}

impl Handler {
    pub fn new(certificate: String, certificate_key: String, alpns: Vec<String>) -> Result<Self> {
        let (cert, key) =
            fs::read(&certificate).and_then(|x| Ok((x, fs::read(&certificate_key)?)))?;

        let cert = match Path::new(&certificate).extension().map(|ext| ext.to_str()) {
            Some(Some(ext)) if ext == "der" => {
                vec![rustls::Certificate(cert)]
            }
            _ => rustls_pemfile::certs(&mut &*cert)?
                .into_iter()
                .map(rustls::Certificate)
                .collect(),
        };

        let key = match Path::new(&certificate_key)
            .extension()
            .map(|ext| ext.to_str())
        {
            Some(Some(ext)) if ext == "der" => rustls::PrivateKey(key),
            _ => {
                let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)?;
                match pkcs8.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)?;
                        match rsa.into_iter().next() {
                            Some(x) => rustls::PrivateKey(x),
                            None => {
                                let rsa = rustls_pemfile::ec_private_keys(&mut &*key)?;
                                match rsa.into_iter().next() {
                                    Some(x) => rustls::PrivateKey(x),
                                    None => {
                                        return Err(anyhow!("no private keys found",));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        let mut crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert, key)?;

        for alpn in alpns {
            crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
            .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
                300_000,
            )))); // ms
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport = Arc::new(transport_config);

        Ok(Self { server_config })
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let (_, incoming) = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(self.server_config.clone()),
            socket.into_std()?,
        )
        .map_err(quic_err)?;
        Ok(InboundTransport::Incoming(Box::new(Incoming::new(
            incoming,
        ))))
    }
}
