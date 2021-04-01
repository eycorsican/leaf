use anyhow::{anyhow, Result};
use futures::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::{ProxyStream, SimpleProxyStream};

#[cfg(feature = "rustls-tls")]
pub mod wrapper {
    use std::sync::Arc;

    use tokio_rustls::{rustls::ClientConfig, webpki::DNSNameRef, TlsConnector};

    use super::*;

    // struct InsecureVerifier;

    // impl rustls::ServerCertVerifier for InsecureVerifier {
    //     fn verify_server_cert(
    //         &self,
    //         _roots: &rustls::RootCertStore,
    //         _presented_certs: &[rustls::Certificate],
    //         _dns_name: DNSNameRef<'_>,
    //         _ocsp_response: &[u8],
    //     ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
    //         Ok(rustls::ServerCertVerified::assertion())
    //     }
    // }

    pub async fn wrap_tls<S>(
        stream: S,
        domain: &str,
        alpns: Vec<String>,
        // insecure: bool,
    ) -> Result<Box<dyn ProxyStream>>
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Sync + Send,
    {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        for alpn in alpns {
            config.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        // if insecure {
        //     let mut dangerous_config = config.dangerous();
        //     dangerous_config.set_certificate_verifier(Arc::new(InsecureVerifier));
        // }

        let config = TlsConnector::from(Arc::new(config));
        let dnsname = DNSNameRef::try_from_ascii_str(domain)
            .map_err(|e| anyhow!(format!("invalid domain: {}", e)))?;
        let tls_stream = config
            .connect(dnsname, stream)
            .map_err(|e| anyhow!(format!("tls connect failed: {}", e)))
            .await?;
        // FIXME check negotiated alpn
        Ok(Box::new(SimpleProxyStream(tls_stream)))
    }
}

#[cfg(feature = "openssl-tls")]
pub mod wrapper {
    use std::pin::Pin;
    use std::sync::Once;

    use openssl::ssl::{Ssl, SslConnector, SslMethod};
    use tokio_openssl::SslStream;

    use super::*;

    pub async fn wrap_tls<S>(
        stream: S,
        domain: &str,
        alpns: Vec<String>,
        // insecure: bool,
    ) -> Result<Box<dyn ProxyStream>>
    where
        S: 'static + AsyncRead + AsyncWrite + Unpin + Sync + Send,
    {
        {
            static ONCE: Once = Once::new();
            ONCE.call_once(openssl_probe::init_ssl_cert_env_vars);
        }

        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| anyhow!(format!("create tls builder failed: {}", e)))?;

        if alpns.len() > 0 {
            let wire = alpns
                .into_iter()
                .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                .collect::<Vec<Vec<u8>>>()
                .concat();
            builder
                .set_alpn_protos(&wire)
                .map_err(|e| anyhow!(format!("set alpn failed: {}", e)))?;
        }

        let connector = builder.build();
        let mut ssl =
            Ssl::new(connector.context()).map_err(|_| anyhow!(format!("new tls stream failed")))?;
        ssl.set_hostname(domain)
            .map_err(|_| anyhow!(format!("set tls hostname failed")))?;
        let mut stream =
            SslStream::new(ssl, stream).map_err(|_| anyhow!(format!("new tls stream failed")))?;
        Pin::new(&mut stream)
            .connect()
            .map_err(|e| {
                log::trace!("connect tls stream failed: {}", e);
                anyhow!(format!("connect tls stream failed"))
            })
            .await?;
        Ok(Box::new(SimpleProxyStream(stream)))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_alpns_list_to_wire() {
        let mut alpns = Vec::new();
        alpns.push("h2".to_string());
        alpns.push("http/1.1".to_string());
        let expected = b"\x02h2\x08http/1.1";
        let wire = alpns
            .into_iter()
            .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
            .collect::<Vec<Vec<u8>>>()
            .concat();
        assert_eq!(wire, expected);
    }
}
