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
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

#[cfg(feature = "rustls-tls")]
fn load_keys(path: &Path) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let mut keys = pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .into_iter()
        .filter_map(|x| x.ok())
        .map(Into::into)
        .collect::<Vec<_>>();
    let mut keys2 = rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .into_iter()
        .filter_map(|x| x.ok())
        .map(Into::into)
        .collect::<Vec<_>>();
    let mut keys3 = ec_private_keys(&mut BufReader::new(File::open(path)?))
        .into_iter()
        .filter_map(|x| x.ok())
        .map(Into::into)
        .collect::<Vec<_>>();
    keys.append(&mut keys3);
    keys.append(&mut keys2);
    Ok(keys)
}

impl Handler {
    pub fn new(certificate: String, certificate_key: String) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            let certs = load_certs(Path::new(&certificate))?;
            let mut keys = load_keys(Path::new(&certificate_key))?;
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, keys.remove(0))
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            Ok(Self { acceptor })
        }
        #[cfg(feature = "openssl-tls")]
        unimplemented!();
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        #[cfg(feature = "rustls-tls")]
        {
            Ok(InboundTransport::Stream(
                Box::new(self.acceptor.accept(stream).await?),
                sess,
            ))
        }

        #[cfg(feature = "openssl-tls")]
        unimplemented!();
    }
}
