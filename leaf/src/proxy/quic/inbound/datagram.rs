use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use quinn::{RecvStream, SendStream};
use rustls_pemfile_old::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, trace, warn};

use crate::{proxy::*, session::Session};

use super::QuicProxyStream;

struct Incoming {
    stream_rx: Receiver<(SocketAddr, (SendStream, RecvStream))>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stream_rx.poll_recv(cx) {
            Poll::Ready(Some((source, (send, recv)))) => {
                let mut sess = Session {
                    source,
                    ..Default::default()
                };
                sess.stream_id = Some(send.id().index());
                Poll::Ready(Some(AnyBaseInboundTransport::Stream(
                    Box::new(QuicProxyStream { recv, send }),
                    sess,
                )))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
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
            _ => certs(&mut &*cert)?
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
                let pkcs8 = pkcs8_private_keys(&mut &*key)?;
                match pkcs8.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        let rsa = rsa_private_keys(&mut &*key)?;
                        match rsa.into_iter().next() {
                            Some(x) => rustls::PrivateKey(x),
                            None => {
                                let rsa = ec_private_keys(&mut &*key)?;
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
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(transport_config));

        Ok(Self { server_config })
    }
}

async fn handle_conn(
    stream_tx: Sender<(SocketAddr, (SendStream, RecvStream))>,
    remote_addr: &SocketAddr,
    conn: quinn::Connecting,
) -> Result<()> {
    let (conn, _) = conn
        .into_0rtt()
        .map_err(|_| anyhow!("convert 0rtt failed"))?;
    trace!("QUIC handling connection from {}", remote_addr);
    loop {
        let s = conn.accept_bi().await?;
        trace!("QUIC accepted stream from {}", remote_addr);
        if stream_tx.capacity() == 0 {
            warn!("QUIC accept channel full");
        }
        let _ = stream_tx.send((remote_addr.clone(), s)).await;
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let (stream_tx, stream_rx) = channel(*crate::option::QUIC_ACCEPT_CHANNEL_SIZE);
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(self.server_config.clone()),
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(quic_err)?;
        tokio::spawn(async move {
            while let Some(connecting) = endpoint.accept().await {
                let stream_tx_c = stream_tx.clone();
                tokio::spawn(async move {
                    let remote_addr = connecting.remote_address();
                    if let Err(e) = handle_conn(stream_tx_c, &remote_addr, connecting).await {
                        debug!("handle QUIC connection from {} failed: {}", &remote_addr, e);
                    }
                });
            }
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming { stream_rx })))
    }
}
