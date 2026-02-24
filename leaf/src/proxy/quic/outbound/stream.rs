use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::TryFutureExt;
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
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
            if cert_path.contains("-----BEGIN") {
                let mut reader = io::BufReader::new(cert_path.as_bytes());
                for cert in certs(&mut reader) {
                    roots.add(cert.unwrap()).unwrap();
                }
            } else {
                match fs::read(cert_path) {
                    Ok(cert) => {
                        match Path::new(&cert_path).extension().map(|ext| ext.to_str()) {
                            Some(Some("der")) => {
                                roots.add(CertificateDer::from(cert)).unwrap(); // FIXME
                            }
                            _ => {
                                let mut reader = io::BufReader::new(&*cert);
                                for cert in certs(&mut reader) {
                                    roots.add(cert.unwrap()).unwrap();
                                }
                            }
                        }
                    }
                    Err(e) => {
                        panic!("read certificate {} failed: {}", cert_path, e);
                    }
                }
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        #[cfg(feature = "rustls-tls-aws-lc")]
        let provider = rustls::crypto::aws_lc_rs::default_provider().into();
        #[cfg(not(feature = "rustls-tls-aws-lc"))]
        let provider = rustls::crypto::ring::default_provider().into();

        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        for alpn in alpns {
            client_crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
        ));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(64));
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            300_000,
        ))));
        transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
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
        let dial_timeout = Duration::from_secs(*crate::option::OUTBOUND_DIAL_TIMEOUT);
        let start = std::time::Instant::now();
        {
            let mut conns = self.connections.write().await;
            let idx = 0usize;
            while idx < conns.len() {
                let conn = &conns[idx];
                match timeout(dial_timeout, conn.open_bi()).await {
                    Ok(Ok((send, recv))) => {
                        trace!(
                            "opened QUIC stream on existing connection (rtt {} ms) in {} ms",
                            conn.rtt().as_millis(),
                            start.elapsed().as_millis(),
                        );
                        return Ok(QuicProxyStream { recv, send });
                    }
                    Ok(Err(e)) => {
                        debug!("open QUIC stream failed: {}", e);
                        conns.swap_remove(idx);
                    }
                    Err(_) => {
                        debug!("open QUIC stream timed out");
                        conns.swap_remove(idx);
                    }
                }
            }
        }

        // FIXME A better indicator.
        let socket = self
            .new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR)
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
                .map_err(|e| io::Error::other(format!("lookup {} failed: {}", &self.address, e)))
                .await?
        };
        if ips.is_empty() {
            return Err(anyhow!("could not resolve to any address",));
        }
        let server_name = self.server_name.as_ref().unwrap_or(&self.address);
        let mut last_err: Option<anyhow::Error> = None;
        for ip in ips {
            let connect_addr = SocketAddr::new(ip, self.port);
            let connecting = match endpoint.connect(connect_addr, server_name) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            let conn = match timeout(dial_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow!("connect QUIC timed out"));
                    continue;
                }
            };
            let (send, recv) = match timeout(dial_timeout, conn.open_bi()).await {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow!("open QUIC stream timed out"));
                    continue;
                }
            };

            let mut conns = self.connections.write().await;
            conns.push(conn);
            conns.truncate(4);

            trace!("opened QUIC stream on new connection",);

            return Ok(QuicProxyStream { recv, send });
        }

        Err(last_err.unwrap_or_else(|| anyhow!("connect QUIC failed")))
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
        self.manager
            .new_stream()
            .await
            .map_err(|e| io::Error::other(format!("new QUIC stream failed: {}", e)))
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
        tracing::trace!("handling outbound stream session: {:?}", _sess);
        Ok(Box::new(self.new_stream().await?))
    }
}
