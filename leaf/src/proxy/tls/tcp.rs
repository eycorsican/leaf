use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::TryFutureExt;
use log::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    client::TlsStream, rustls, rustls::ClientConfig, webpki::DNSNameRef, TlsConnector,
};

use crate::{
    proxy::{ProxyStream, ProxyTcpHandler, SimpleStream},
    session::Session,
};

struct InsecureVerifier;

impl rustls::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: DNSNameRef<'_>,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

async fn wrap_tls<S>(
    stream: S,
    domain: &str,
    alpns: Vec<String>,
    insecure: bool,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut config = ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    for alpn in alpns {
        config.alpn_protocols.push(alpn.as_bytes().to_vec());
    }

    if insecure {
        let mut dangerous_config = config.dangerous();
        dangerous_config.set_certificate_verifier(Arc::new(InsecureVerifier));
    }

    let config = TlsConnector::from(Arc::new(config));
    let dnsname = DNSNameRef::try_from_ascii_str(domain)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("invalid domain: {}", e)))?;
    let tls_stream = config
        .connect(dnsname, stream)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Interrupted,
                format!("tls connect failed: {}", e),
            )
        })
        .await?;
    // FIXME check negotiated alpn
    Ok(tls_stream)
}

pub struct Handler {
    pub server_name: String,
    pub alpns: Vec<String>,
}

#[async_trait]
impl ProxyTcpHandler for Handler {
    fn name(&self) -> &str {
        return super::NAME;
    }

    fn tcp_connect_addr(&self) -> Option<(String, u16, SocketAddr)> {
        None
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Box<dyn ProxyStream>>,
    ) -> io::Result<Box<dyn ProxyStream>> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        trace!("wrapping tls with name {}", &name);
        match stream {
            Some(stream) => {
                let tls_stream = wrap_tls(stream, &name, self.alpns.clone(), false).await?;
                return Ok(Box::new(SimpleStream(tls_stream)));
            }
            None => Err(io::Error::new(io::ErrorKind::Other, "invalid tls input")),
        }
    }
}
