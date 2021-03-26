use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::sync::Mutex;

use crate::{
    app::dns_client::DnsClient,
    proxy::{OutboundConnect, ProxyStream, TcpOutboundHandler, UdpConnector},
    session::Session,
};

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
    bind_addr: SocketAddr,
    dns_client: Arc<DnsClient>,
    client_config: quinn::ClientConfig,
    connections: Mutex<Vec<Connection>>,
}

impl Manager {
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        certificate: Option<String>,
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        let mut client_config = quinn::ClientConfig::default();

        let mut crypto_config = rustls::ClientConfig::with_ciphersuites(&QUIC_CIPHER_SUITES);
        crypto_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        crypto_config.enable_early_data = true;
        crypto_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        client_config.crypto = Arc::new(crypto_config);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_idle_timeout(Some(std::time::Duration::from_secs(300)))
            .map_err(quic_err)
            .unwrap();
        client_config.transport = Arc::new(transport_config); // TODO share

        if let Some(cert_path) = certificate.as_ref() {
            match fs::read(cert_path) {
                Ok(cert) => {
                    let cert = match Path::new(cert_path).extension().map(|ext| ext.to_str()) {
                        Some(Some(ext)) if ext == "der" => quinn::Certificate::from_der(&cert)
                            .map_err(quic_err)
                            .unwrap(),
                        _ => {
                            if let Some(c) = quinn::CertificateChain::from_pem(&cert)
                                .map_err(quic_err)
                                .unwrap()
                                .iter()
                                .next()
                            {
                                quinn::Certificate::from(c.clone())
                            } else {
                                panic!("no certificate found in chain");
                            }
                        }
                    };
                    client_config
                        .add_certificate_authority(cert)
                        .map_err(quic_err)
                        .unwrap();
                }
                Err(e) => {
                    panic!("read certificate {} failed: {}", cert_path, e);
                }
            }
        }

        Manager {
            address,
            port,
            server_name,
            bind_addr,
            dns_client,
            client_config,
            connections: Mutex::new(Vec::new()),
        }
    }
}

static QUIC_CIPHER_SUITES: [&rustls::SupportedCipherSuite; 3] = [
    &rustls::ciphersuite::TLS13_AES_256_GCM_SHA384,
    &rustls::ciphersuite::TLS13_AES_128_GCM_SHA256,
    &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
];

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

        let mut endpoint = quinn::Endpoint::builder();
        endpoint.default_client_config(self.client_config.clone());
        let socket = self.create_udp_socket(&self.bind_addr).await?;
        let (endpoint, _) = endpoint.with_socket(socket.into_std()?).map_err(quic_err)?;

        let ips = self
            .dns_client
            .lookup_with_bind(self.address.to_owned(), &self.bind_addr)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("lookup {} failed: {}", &self.address, e),
                )
            })
            .await?;
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
            .connect(&connect_addr, server_name)
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
        certificate: Option<String>,
        bind_addr: SocketAddr,
        dns_client: Arc<DnsClient>,
    ) -> Self {
        Self {
            manager: Manager::new(
                address,
                port,
                server_name,
                certificate,
                bind_addr,
                dns_client,
            ),
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
impl TcpOutboundHandler for Handler {
    fn name(&self) -> &str {
        super::NAME
    }

    fn tcp_connect_addr(&self) -> Option<OutboundConnect> {
        Some(OutboundConnect::NoConnect)
    }

    async fn handle_tcp<'a>(
        &'a self,
        _sess: &'a Session,
        _stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        Ok(Box::new(self.new_stream().await?))
    }
}
