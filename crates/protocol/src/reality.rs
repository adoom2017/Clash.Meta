//! Independently maintained REALITY authentication over standard rustls TLS 1.3.
//! The local rustls patch exposes a pre-transcript session-id hook; all protocol
//! semantics and cryptography orchestration live here, not in a TLS fork.
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, NamedGroup, SignatureScheme,
    client::{
        SessionIdCustomizer,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Sha256, Sha512};
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Debug)]
struct X25519;
static GROUP: X25519 = X25519;
struct Exchange {
    secret: StaticSecret,
    public: PublicKey,
}
impl Exchange {
    fn shared(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| Error::General("invalid X25519 key length".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(Error::General("non-contributory X25519 key".into()));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }
}
impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Ok(Box::new(Exchange { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}
impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.shared(peer)
    }
    fn additional_peer_secret(&self, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.shared(peer)
    }
    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct Authentication {
    public: [u8; 32],
    short_id: [u8; 8],
    auth_key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}
impl std::fmt::Debug for Authentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RealityAuthentication")
    }
}
impl SessionIdCustomizer for Authentication {
    fn customize(&self, hello: &[u8], kx: &dyn ActiveKeyExchange) -> Result<[u8; 32], Error> {
        let mut saved = self
            .auth_key
            .lock()
            .map_err(|_| Error::General("REALITY authentication state poisoned".into()))?;
        if saved.is_some() {
            return Err(Error::General(
                "REALITY config is single-use; create a new config for each connection".into(),
            ));
        }
        if hello.len() < 71
            || hello[0] != 1
            || hello[38] != 32
            || hello[39..71].iter().any(|b| *b != 0)
        {
            return Err(Error::General("unexpected ClientHello layout".into()));
        }
        let shared = kx.additional_peer_secret(&self.public)?;
        let mut key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<Sha256>::new(Some(&hello[6..26]), shared.secret_bytes())
            .expand(b"REALITY", key.as_mut())
            .map_err(|_| Error::General("REALITY key derivation failed".into()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::General("system time before epoch".into()))?
            .as_secs();
        let mut plaintext = [0; 16];
        plaintext[..3].copy_from_slice(&[1, 8, 2]);
        plaintext[4..8].copy_from_slice(&(now as u32).to_be_bytes());
        plaintext[8..].copy_from_slice(&self.short_id);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|_| Error::General("REALITY cipher setup failed".into()))?;
        let session = cipher
            .encrypt(
                (&hello[26..38]).into(),
                Payload {
                    msg: &plaintext,
                    aad: hello,
                },
            )
            .map_err(|_| Error::General("REALITY authentication failed".into()))?;
        *saved = Some(key);
        session
            .try_into()
            .map_err(|_| Error::General("REALITY session size error".into()))
    }
}
impl ServerCertVerifier for Authentication {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        use x509_parser::prelude::FromDer;
        let (rest, cert) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
            .map_err(|_| Error::General("invalid REALITY certificate".into()))?;
        if !rest.is_empty() || cert.public_key().subject_public_key.data.len() != 32 {
            return Err(Error::General(
                "invalid REALITY certificate encoding".into(),
            ));
        }
        if cert.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112" {
            return Err(Error::General(
                "REALITY peer certificate is not Ed25519".into(),
            ));
        }
        let key = self.auth_key.lock().unwrap();
        let key = key
            .as_ref()
            .ok_or_else(|| Error::General("REALITY handshake key missing".into()))?;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key.as_ref())
            .map_err(|_| Error::General("REALITY HMAC error".into()))?;
        mac.update(cert.public_key().subject_public_key.data.as_ref());
        mac.verify_slice(cert.signature_value.data.as_ref())
            .map_err(|_| Error::General("REALITY server authentication rejected".into()))?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("REALITY requires TLS 1.3".into()))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Create authentication state for exactly one connection. Reusing the returned
/// config is rejected because its certificate verifier is bound to that hello.
pub fn config(options: &meta_config::Reality, alpn: &[String]) -> Result<ClientConfig> {
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&options.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid REALITY public key"))?;
    ensure!(
        options.short_id.len() <= 16 && options.short_id.len().is_multiple_of(2),
        "invalid REALITY short id"
    );
    let mut short_id = [0; 8];
    for (index, chunk) in options.short_id.as_bytes().chunks(2).enumerate() {
        short_id[index] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    let auth = Arc::new(Authentication {
        public,
        short_id,
        auth_key: Mutex::new(None),
    });
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![&GROUP];
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(auth.clone())
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.session_id_customizer = Some(auth);
    config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_rejects_reused_state_and_low_order_public_keys() {
        let secret = StaticSecret::from([9; 32]);
        let public = PublicKey::from(&secret);
        let options = meta_config::Reality {
            public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
            short_id: String::new(),
        };
        let config = Arc::new(config(&options, &[]).unwrap());
        let name = ServerName::try_from("localhost").unwrap();
        assert!(rustls::ClientConnection::new(config.clone(), name.clone()).is_ok());
        assert!(rustls::ClientConnection::new(config, name.clone()).is_err());
        let options = meta_config::Reality {
            public_key: URL_SAFE_NO_PAD.encode([0; 32]),
            short_id: String::new(),
        };
        assert!(
            rustls::ClientConnection::new(Arc::new(super::config(&options, &[]).unwrap()), name)
                .is_err()
        );
    }
    #[test]
    fn certificate_authentication_checks_hmac_and_key_type() {
        let auth = Authentication {
            public: [0; 32],
            short_id: [0; 8],
            auth_key: Mutex::new(Some(Zeroizing::new([11; 32]))),
        };
        let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&signing_key)
            .unwrap();
        let mut bytes = cert.der().to_vec();
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&[11; 32]).unwrap();
        mac.update(signing_key.public_key_raw());
        let start = bytes.len() - 64;
        bytes[start..].copy_from_slice(&mac.finalize().into_bytes());
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(100));
        assert!(
            auth.verify_server_cert(&CertificateDer::from(bytes.clone()), &[], &name, &[], now)
                .is_ok()
        );
        bytes[start] ^= 1;
        assert!(
            auth.verify_server_cert(&CertificateDer::from(bytes), &[], &name, &[], now)
                .is_err()
        );
        assert!(
            auth.verify_server_cert(cert.der(), &[], &name, &[], now)
                .is_err()
        );
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(
            auth.verify_server_cert(cert.cert.der(), &[], &name, &[], now)
                .is_err()
        );
    }
    #[test]
    fn session_auth_is_bound_to_transcript() {
        use aes_gcm::aead::Aead;
        let server = StaticSecret::from([7; 32]);
        let public = PublicKey::from(&server);
        let options = meta_config::Reality {
            public_key: URL_SAFE_NO_PAD.encode(public.as_bytes()),
            short_id: "01020304".into(),
        };
        let mut client = rustls::ClientConnection::new(
            Arc::new(config(&options, &[]).unwrap()),
            ServerName::try_from("example.org").unwrap(),
        )
        .unwrap();
        let mut wire = vec![];
        client.write_tls(&mut wire).unwrap();
        let hello = &wire[5..];
        assert_eq!(hello[38], 32);
        let mut cursor = 71;
        let cipher_len = u16::from_be_bytes(hello[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2 + cipher_len;
        cursor += 1 + hello[cursor] as usize;
        cursor += 2;
        let mut peer = None;
        while cursor + 4 <= hello.len() {
            let kind = u16::from_be_bytes(hello[cursor..cursor + 2].try_into().unwrap());
            let len =
                u16::from_be_bytes(hello[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            if kind == 51 {
                peer = Some(<[u8; 32]>::try_from(&hello[cursor + 6..cursor + 38]).unwrap());
            }
            cursor += len;
        }
        let shared = server.diffie_hellman(&PublicKey::from(peer.unwrap()));
        let mut key = [0; 32];
        hkdf::Hkdf::<Sha256>::new(Some(&hello[6..26]), shared.as_bytes())
            .expand(b"REALITY", &mut key)
            .unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut aad = hello.to_vec();
        aad[39..71].fill(0);
        let plain = cipher
            .decrypt(
                (&hello[26..38]).into(),
                Payload {
                    msg: &hello[39..71],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&plain[..3], &[1, 8, 2]);
        assert_eq!(&plain[8..12], &[1, 2, 3, 4]);
        aad[6] ^= 1;
        assert!(
            cipher
                .decrypt(
                    (&hello[26..38]).into(),
                    Payload {
                        msg: &hello[39..71],
                        aad: &aad
                    }
                )
                .is_err()
        );
    }
}
