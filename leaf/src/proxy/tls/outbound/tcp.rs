use std::fs::File;
use std::io;
use std::io::BufReader;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryFutureExt;
use log::*;

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc,
    tokio_rustls::{
        rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName},
        webpki, TlsConnector,
    },
};

#[cfg(feature = "openssl-tls")]
use {
    openssl::ssl::{Ssl, SslConnector, SslMethod},
    std::pin::Pin,
    std::sync::Once,
    tokio_openssl::SslStream,
};

use crate::{proxy::*, session::Session};

pub struct Handler {
    server_name: String,
    #[cfg(feature = "rustls-tls")]
    tls_config: Arc<ClientConfig>,
    #[cfg(feature = "openssl-tls")]
    ssl_connector: SslConnector,
}

impl Handler {
    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        certificate: Option<String>,
    ) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            let mut root_cert_store = RootCertStore::empty();
            if let Some(cert) = certificate {
                let mut pem = BufReader::new(File::open(cert)?);
                let certs = rustls_pemfile::certs(&mut pem)?;
                let trust_anchors = certs.iter().map(|cert| {
                    let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap(); // FIXME
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                });
                root_cert_store.add_server_trust_anchors(trust_anchors);
            } else {
                root_cert_store.add_server_trust_anchors(
                    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }),
                );
            }

            let mut config = ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();

            for alpn in alpns {
                config.alpn_protocols.push(alpn.as_bytes().to_vec());
            }
            Ok(Handler {
                server_name,
                tls_config: Arc::new(config),
            })
        }
        #[cfg(feature = "openssl-tls")]
        {
            {
                static ONCE: Once = Once::new();
                ONCE.call_once(openssl_probe::init_ssl_cert_env_vars);
            }
            let mut builder =
                SslConnector::builder(SslMethod::tls()).expect("create ssl connector failed");
            if alpns.len() > 0 {
                let wire = alpns
                    .into_iter()
                    .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                builder.set_alpn_protos(&wire).expect("set alpn failed");
            }
            let ssl_connector = builder.build();
            Ok(Handler {
                server_name,
                ssl_connector,
            })
        }
    }
}

fn tls_err<E>(_error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, "tls error")
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        trace!("wrapping tls with name {}", &name);
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            {
                let connector = TlsConnector::from(self.tls_config.clone());
                let domain = ServerName::try_from(name.as_str())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))?;
                let tls_stream = connector.connect(domain, stream).map_err(tls_err).await?;
                // FIXME check negotiated alpn
                Ok(Box::new(tls_stream))
            }
            #[cfg(feature = "openssl-tls")]
            {
                let mut ssl = Ssl::new(self.ssl_connector.context()).map_err(tls_err)?;
                ssl.set_hostname(&name).map_err(tls_err)?;
                let mut stream = SslStream::new(ssl, stream).map_err(tls_err)?;
                Pin::new(&mut stream)
                    .connect()
                    .map_err(|e| {
                        log::trace!("connect tls stream failed: {}", e);
                        tls_err(e)
                    })
                    .await?;
                Ok(Box::new(stream))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid tls input"))
        }
    }
}
