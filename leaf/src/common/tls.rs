use std::io;

use futures::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

pub use wrapper::wrap_tls;

#[cfg(any(target_os = "ios", target_os = "macos"))]
// #[cfg(any(target_os = "ios"))]
pub(crate) mod wrapper {
    use super::*;

    use std::sync::Arc;

    use tokio_rustls::{client::TlsStream, rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

    pub async fn wrap_tls<S>(stream: S, domain: &str) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // TODO global config?
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

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
        Ok(tls_stream)
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
// #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub(crate) mod wrapper {
    use super::*;

    use native_tls::TlsConnector as NativeTlsConnector;
    use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream};

    pub async fn wrap_tls<S>(stream: S, domain: &str) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let native_connector = NativeTlsConnector::new().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("new tls connector failed: {}", e),
            )
        })?;
        let connector = TokioTlsConnector::from(native_connector);
        let tls_stream = connector
            .connect(domain, stream)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls connect failed: {}", e)))
            .await?;
        Ok(tls_stream)
    }
}
