use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use futures::TryFutureExt;
use rustls::OwnedTrustAnchor;
use tokio::sync::Mutex;

use crate::{app::SyncDnsClient, proxy::*, session::Session};

use super::QuicProxyStream;

fn quic_err<E>(error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}

struct Connection {
    pub new_conn: quinn::NewConnection,
    pub total_accepted: usize,
    pub completed: bool,
}

struct Manager {
    address: String,
    port: u16,
    server_name: Option<String>,
    dns_client: SyncDnsClient,
    client_config: quinn::ClientConfig,
    connections: Mutex<Vec<Connection>>,
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
                            let certs: Vec<rustls::Certificate> =
                                rustls_pemfile::certs(&mut &*cert)
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
            roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
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
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            300_000,
        )))); // ms
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        client_config.transport = Arc::new(transport_config);

        Manager {
            address,
            port,
            server_name,
            dns_client,
            client_config,
            connections: Mutex::new(Vec::new()),
        }
    }
}

impl Manager {
    pub async fn new_stream(
        &self,
    ) -> io::Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
        self.connections.lock().await.retain(|c| !c.completed);

        for conn in self.connections.lock().await.iter_mut() {
            if conn.total_accepted < 128 {
                // FIXME I think awaiting here is fine, it should return immediately, not sure.
                match conn.new_conn.connection.open_bi().await {
                    Ok((send, recv)) => {
                        conn.total_accepted += 1;
                        log::trace!(
                            "opened quic stream on connection with rtt {}ms, total_accepted {}",
                            conn.new_conn.connection.rtt().as_millis(),
                            conn.total_accepted,
                        );
                        return Ok(QuicProxyStream { recv, send });
                    }
                    Err(e) => {
                        conn.completed = true;
                        log::debug!("open quic bidirectional stream failed: {}", e);
                    }
                }
            } else {
                conn.completed = true;
            }
        }

        // FIXME A better indicator.
        let socket = self
            .new_udp_socket(&*crate::option::UNSPECIFIED_BIND_ADDR)
            .await?;
        let (mut endpoint, _) =
            quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket.into_std()?)
                .map_err(quic_err)?;
        endpoint.set_default_client_config(self.client_config.clone());

        let ips = {
            self.dns_client
                .read()
                .await
                .lookup(&self.address)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("lookup {} failed: {}", &self.address, e),
                    )
                })
                .await?
        };
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            ));
        }
        let connect_addr = SocketAddr::new(ips[0], self.port);

        let server_name = if let Some(name) = self.server_name.as_ref() {
            name
        } else {
            &self.address
        };

        let new_conn = endpoint
            .connect(connect_addr, server_name)
            .map_err(quic_err)?
            .await
            .map_err(quic_err)?;

        let (send, recv) = new_conn.connection.open_bi().await.map_err(quic_err)?;

        self.connections.lock().await.push(Connection {
            new_conn,
            total_accepted: 1,
            completed: false,
        });

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
        self.manager.new_stream().await
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
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        Ok(Box::new(self.new_stream().await?))
    }
}
