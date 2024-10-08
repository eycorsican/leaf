use std::fs::File;
use std::io;
use std::io::BufReader;

use anyhow::Result;
use async_trait::async_trait;
use futures::TryFutureExt;
use tracing::trace;

#[cfg(feature = "rustls-tls")]
use {
    std::sync::Arc,
    tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
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

#[cfg(feature = "rustls-tls")]
mod dangerous {
    use tokio_rustls::rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };

    #[derive(Debug)]
    pub(super) struct NotVerified;

    impl ServerCertVerifier for NotVerified {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> core::result::Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // Non-exhaustive, new variants can be added in the future.
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

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
        insecure: bool,
    ) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            let mut roots = RootCertStore::empty();
            if let Some(cert) = certificate {
                let mut pem = BufReader::new(File::open(cert)?);
                for cert in rustls_pemfile::certs(&mut pem) {
                    roots.add(cert?)?;
                }
            } else {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            if insecure {
                let mut dangerous_config = config.dangerous();
                dangerous_config.set_certificate_verifier(Arc::new(dangerous::NotVerified));
            }
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
            if !alpns.is_empty() {
                let wire = alpns
                    .into_iter()
                    .map(|a| [&[a.len() as u8], a.as_bytes()].concat())
                    .collect::<Vec<Vec<u8>>>()
                    .concat();
                builder.set_alpn_protos(&wire).expect("set alpn failed");
            }
            if insecure {
                builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            }
            let ssl_connector = builder.build();
            Ok(Handler {
                server_name,
                ssl_connector,
            })
        }
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        // TODO optimize, dont need copy
        let name = if !&self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        if let Some(stream) = stream {
            #[cfg(feature = "rustls-tls")]
            {
                trace!("handling TLS {} with rustls", &name);
                let connector = TlsConnector::from(self.tls_config.clone());
                let domain = ServerName::try_from(name.as_str()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid tls server name {}: {}", &name, e),
                    )
                })?;
                let tls_stream = connector
                    .connect(domain.to_owned(), stream)
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect tls failed: {}", e),
                        )
                    })
                    .await?;
                // FIXME check negotiated alpn
                Ok(Box::new(tls_stream))
            }
            #[cfg(feature = "openssl-tls")]
            {
                trace!("handling TLS {} with openssl", &name);
                let mut ssl = Ssl::new(self.ssl_connector.context()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl failed: {}", e),
                    )
                })?;
                ssl.set_hostname(&name).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("set tls name failed: {}", e),
                    )
                })?;
                let mut stream = SslStream::new(ssl, stream).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("new ssl stream failed: {}", e),
                    )
                })?;
                Pin::new(&mut stream)
                    .connect()
                    .map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("connect ssl stream failed: {}", e),
                        )
                    })
                    .await?;
                Ok(Box::new(stream))
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "invalid tls input"))
        }
    }
}
