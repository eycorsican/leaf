#[cfg(feature = "rustls-tls")]
use {std::fs::File, std::io, std::io::BufReader, std::path::Path};

use anyhow::Result;

#[cfg(feature = "rustls-tls")]
use {
    rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys},
    tokio_rustls::TlsAcceptor,
    tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};

use crate::{proxy::*, session::Session};

pub struct Handler {
    #[cfg(feature = "rustls-tls")]
    acceptor: TlsAcceptor,
}

#[cfg(feature = "rustls-tls")]
fn load_certs(certificate: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    if certificate.contains("-----BEGIN") {
        let mut reader = BufReader::new(io::Cursor::new(certificate.as_bytes()));
        certs(&mut reader).collect()
    } else {
        let mut reader = BufReader::new(File::open(Path::new(certificate))?);
        certs(&mut reader).collect()
    }
}

#[cfg(feature = "rustls-tls")]
fn load_keys(certificate_key: &str) -> io::Result<Vec<PrivateKeyDer<'static>>> {
    let mut keys = Vec::new();
    if certificate_key.contains("-----BEGIN") {
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in pkcs8_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs8(key?));
        }
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in rsa_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Pkcs1(key?));
        }
        let mut reader = BufReader::new(io::Cursor::new(certificate_key.as_bytes()));
        for key in ec_private_keys(&mut reader) {
            keys.push(PrivateKeyDer::Sec1(key?));
        }
    } else {
        let path = Path::new(certificate_key);
        let mut reader = BufReader::new(File::open(path)?);
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
    }
    Ok(keys)
}

impl Handler {
    pub fn new(
        certificate: String,
        certificate_key: String,
        ech_config: Option<String>,
        ech_key: Option<String>,
    ) -> Result<Self> {
        #[cfg(feature = "rustls-tls")]
        {
            let ech = load_ech(ech_config.as_deref(), ech_key.as_deref())?;
            if ech.is_some() {
                tracing::error!(
                    "tls inbound ech is configured but inbound ech is not supported by current rustls implementation"
                );
                return Err(anyhow::anyhow!(
                    "tls inbound ech is not supported yet; remove echConfig and echKey"
                ));
            }
            let certs = load_certs(&certificate).map_err(|e| {
                anyhow::anyhow!("load certificates from {} failed: {}", certificate, e)
            })?;
            let mut keys = load_keys(&certificate_key)
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
        {
            let _ = (certificate, certificate_key, ech_config, ech_key);
            unimplemented!();
        }
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        {
            let _ = (certificate, certificate_key, ech_config, ech_key);
            Err(anyhow::anyhow!("no tls feature enabled"))
        }
    }
}

#[cfg(feature = "rustls-tls")]
fn load_ech(
    ech_config: Option<&str>,
    ech_key: Option<&str>,
) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    match (ech_config, ech_key) {
        (None, None) => Ok(None),
        (Some(config), Some(key)) => {
            let config = decode_ech_blob(config)?;
            let key = decode_ech_blob(key)?;
            if config.is_empty() || key.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid ech config or key",
                ));
            }
            Ok(Some((config, key)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ech config and key must be set together",
        )),
    }
}

#[cfg(feature = "rustls-tls")]
fn decode_ech_blob(input: &str) -> io::Result<Vec<u8>> {
    let value = input.trim();
    if value.starts_with("-----BEGIN") {
        let mut encoded = String::new();
        for line in value.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("-----BEGIN") || line.starts_with("-----END") {
                continue;
            }
            encoded.push_str(line);
        }
        if encoded.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ech pem",
            ));
        }
        return decode_base64(&encoded);
    }
    decode_base64(value)
}

#[cfg(feature = "rustls-tls")]
fn decode_base64(data: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    fn decode_chunk(chunk: &[u8; 4], output: &mut Vec<u8>) -> io::Result<()> {
        if chunk[0] == 64 || chunk[1] == 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            ));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        match (chunk[2], chunk[3]) {
            (64, 64) => Ok(()),
            (64, _) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 padding",
            )),
            (c2, 64) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                Ok(())
            }
            (c2, c3) => {
                output.push(((chunk[1] & 0x0f) << 4) | (c2 >> 2));
                output.push(((c2 & 0x03) << 6) | c3);
                Ok(())
            }
        }
    }

    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    let mut chunk = [0_u8; 4];
    let mut chunk_len = 0_usize;
    let mut seen_padding = false;

    for byte in data.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            seen_padding = true;
            chunk[chunk_len] = 64;
            chunk_len += 1;
        } else if let Some(decoded) = value(byte) {
            if seen_padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid base64 padding",
                ));
            }
            chunk[chunk_len] = decoded;
            chunk_len += 1;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid base64 character",
            ));
        }

        if chunk_len == 4 {
            decode_chunk(&chunk, &mut output)?;
            chunk = [0_u8; 4];
            chunk_len = 0;
        }
    }

    match chunk_len {
        0 => Ok(output),
        2 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            Ok(output)
        }
        3 => {
            output.push((chunk[0] << 2) | (chunk[1] >> 4));
            output.push(((chunk[1] & 0x0f) << 4) | (chunk[2] >> 2));
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid base64 length",
        )),
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        #[cfg(feature = "rustls-tls")]
        {
            Ok(InboundTransport::Stream(
                Box::new(self.acceptor.accept(stream).await?),
                sess,
            ))
        }

        #[cfg(all(not(feature = "rustls-tls"), feature = "openssl-tls"))]
        {
            let _ = (sess, stream);
            unimplemented!();
        }
        #[cfg(all(not(feature = "rustls-tls"), not(feature = "openssl-tls")))]
        {
            let _ = (sess, stream);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "no tls feature enabled",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_base64, decode_ech_blob, load_ech};

    #[test]
    fn test_decode_base64_standard_and_urlsafe() {
        assert_eq!(decode_base64("AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_base64("AQI=").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("AQI").unwrap(), vec![1, 2]);
        assert_eq!(decode_base64("-_8=").unwrap(), vec![251, 255]);
    }

    #[test]
    fn test_decode_base64_invalid_input() {
        assert!(decode_base64("A").is_err());
        assert!(decode_base64("AA=A").is_err());
        assert!(decode_base64("AA$A").is_err());
    }

    #[test]
    fn test_decode_ech_blob_pem() {
        let value = "-----BEGIN ECH-----\nAQID\n-----END ECH-----";
        assert_eq!(decode_ech_blob(value).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_load_ech_pair() {
        assert!(load_ech(None, None).unwrap().is_none());
        assert!(load_ech(Some("AQID"), Some("AQID")).unwrap().is_some());
        assert!(load_ech(Some("AQID"), None).is_err());
    }

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn test_new_with_ech_rejected() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let result = super::Handler::new(
            cert_pem,
            key_pem,
            Some("AQID".to_string()),
            Some("BAUG".to_string()),
        );
        assert!(result.is_err());
    }
}
