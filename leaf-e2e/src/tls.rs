//! A throwaway certificate authority for the TLS topologies.
//!
//! Generated per process rather than checked in, so nothing expires and no case
//! depends on a file next to the binary. The client side trusts it by turning
//! verification off, which is what every TLS engine here is configured to do:
//! these cases are about record handling and the ABI, not about trust chains.
//! Certificate *rejection* is its own case, and says so.

use std::sync::OnceLock;

use anyhow::{Context, Result};

/// The name every TLS topology uses, on both sides.
pub const SERVER_NAME: &str = "localhost";

pub struct SelfSigned {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

/// The process-wide certificate. Generating one costs a keypair, and a case may
/// build several nodes.
pub fn self_signed() -> Result<&'static SelfSigned> {
    static CERT: OnceLock<SelfSigned> = OnceLock::new();
    if let Some(cert) = CERT.get() {
        return Ok(cert);
    }
    let generated = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
        .context("generating a self-signed certificate")?;
    let cert = SelfSigned {
        certificate_pem: generated.cert.pem(),
        private_key_pem: generated.key_pair.serialize_pem(),
    };
    Ok(CERT.get_or_init(|| cert))
}
