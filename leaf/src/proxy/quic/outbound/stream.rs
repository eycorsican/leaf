use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::TryFutureExt;
use rustls::OwnedTrustAnchor;
use rustls_pemfile_old::certs;
use tokio::sync::RwLock;
use tracing::{debug, trace};

use crate::{app::SyncDnsClient, proxy::*, session::Session};

use super::QuicProxyStream;

struct Manager {
    address: String,
    port: u16,
    server_name: Option<String>,
    dns_client: SyncDnsClient,
    client_config: quinn::ClientConfig,
    connections: RwLock<Vec<quinn::Connection>>,
}

impl Manager {
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        certificate: Option<String>,
        dns_client: SyncDnsClient,
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(cert_path) = certificate.as_ref() {
            match fs::read(cert_path) {
                Ok(cert) => {
                    match Path::new(&cert_path).extension().map(|ext| ext.to_str()) {
                        Some(Some(ext)) if ext == "der" => {
                            roots.add(&rustls::Certificate(cert)).unwrap(); // FIXME
                        }
                        _ => {
                            let certs: Vec<rustls::Certificate> = certs(&mut &*cert)
                                .unwrap()
                                .into_iter()
                                .map(rustls::Certificate)
                                .collect();
                            for cert in certs {
                                roots.add(&cert).unwrap();
                            }
                        }
                    }
                }
                Err(e) => {
                    panic!("read certificate {} failed: {}", cert_path, e);
                }
            }
        } else {
            roots.add_trust_anchors(webpki_roots_old::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));
        }

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        for alpn in alpns {
            client_crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(64));
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            300_000,
        ))));
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        client_config.transport_config(Arc::new(transport_config));

        Manager {
            address,
            port,
            server_name,
            dns_client,
            client_config,
            connections: RwLock::new(Vec::new()),
        }
    }
}

impl Manager {
    pub async fn new_stream(
        &self,
    ) -> Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
        let start = std::time::Instant::now();
        for conn in self.connections.read().await.iter() {
            match conn.open_bi().await {
                Ok((send, recv)) => {
                    trace!(
                        "opened QUIC stream on existing connection (rtt {} ms) in {} ms",
                        conn.rtt().as_millis(),
                        start.elapsed().as_millis(),
                    );
                    return Ok(QuicProxyStream { recv, send });
                }
                Err(e) => {
                    debug!("open QUIC stream failed: {}", e);
                }
            }
        }

        // FIXME A better indicator.
        let socket = self
            .new_udp_socket(&*crate::option::UNSPECIFIED_BIND_ADDR)
            .await?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.client_config.clone());
        let ips = {
            self.dns_client
                .read()
                .await
                .direct_lookup(&self.address)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("lookup {} failed: {}", &self.address, e),
                    )
                })
                .await?
        };
        if ips.is_empty() {
            return Err(anyhow!("could not resolve to any address",));
        }
        let connect_addr = SocketAddr::new(ips[0], self.port);
        let server_name = self.server_name.as_ref().unwrap_or(&self.address);
        let conn = endpoint.connect(connect_addr, server_name)?.await?;
        let (send, recv) = conn.open_bi().await?;

        self.connections.write().await.push(conn);

        trace!("opened QUIC stream on new connection",);

        Ok(QuicProxyStream { recv, send })
    }
}

impl UdpConnector for Manager {}

pub struct Handler {
    manager: Manager,
}

impl Handler {
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        certificate: Option<String>,
        dns_client: SyncDnsClient,
    ) -> Self {
        Self {
            manager: Manager::new(address, port, server_name, alpns, certificate, dns_client),
        }
    }

    pub async fn new_stream(
        &self,
    ) -> io::Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
        self.manager.new_stream().await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("new QUIC stream failed: {}", e),
            )
        })
    }
}

impl UdpConnector for Handler {}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        Ok(Box::new(self.new_stream().await?))
    }
}
