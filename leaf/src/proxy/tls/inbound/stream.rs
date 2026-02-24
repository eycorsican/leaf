use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use anyhow::Result;

#[cfg(feature = "rustls-tls")]
use {
    rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys},
    tokio_rustls::rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    tokio_rustls::TlsAcceptor,
};

use crate::{proxy::*, session::Session};

pub struct Handler {
    #[cfg(feature = "rustls-tls")]
    acceptor: TlsAcceptor,
}

#[cfg(feature = "rustls-tls")]
fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    certs(&mut reader).collect()
}

#[cfg(feature = "rustls-tls")]
fn load_keys(path: &Path) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys = Vec::new();
    for key in pkcs8_private_keys(&mut reader) {
        keys.push(PrivateKeyDer::Pkcs8(key?));
    }
    let mut reader = BufReader::new(File::open(path)?);
    for key in rsa_private_keys(&mut reader) {
        keys.push(PrivateKeyDer::Pkcs1(key?));
    }
    let mut reader = BufReader::new(File::open(path)?);
    for key in ec_private_keys(&mut reader) {
        keys.push(PrivateKeyDer::Sec1(key?));
    }
    Ok(keys)
}

impl Handler {
    pub fn new(certificate: String, certificate_key: String) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            let certs = load_certs(Path::new(&certificate)).map_err(|e| {
                anyhow::anyhow!("load certificates from {} failed: {}", certificate, e)
            })?;
            let mut keys = load_keys(Path::new(&certificate_key))
                .map_err(|e| anyhow::anyhow!("load keys from {} failed: {}", certificate_key, e))?;
            #[cfg(feature = "rustls-tls-aws-lc")]
            let provider = rustls::crypto::aws_lc_rs::default_provider().into();
            #[cfg(not(feature = "rustls-tls-aws-lc"))]
            let provider = rustls::crypto::ring::default_provider().into();

            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
                .with_no_client_auth()
                .with_single_cert(certs, keys.remove(0))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            Ok(Self { acceptor })
        }
        #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
        unimplemented!();
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        Err(anyhow::anyhow!("no tls feature enabled"))
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream session: {:?}", sess);
        #[cfg(feature = "rustls-tls")]
        {
            Ok(InboundTransport::Stream(
                Box::new(self.acceptor.accept(stream).await?),
                sess,
            ))
        }

        #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
        unimplemented!();
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        Err(io::Error::new(
            io::ErrorKind::Other,
            "no tls feature enabled",
        ))
    }
}
