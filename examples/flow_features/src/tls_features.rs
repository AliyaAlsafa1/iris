use iris_datatypes::TlsHandshake;
use serde::Serialize;
use crate::hash_utils::hash_str;

#[derive(Clone, Debug, Serialize)]
pub struct TlsFeatures {
    // --- ClientHello ---
    pub has_client_hello:             u8,   // 1 if a ClientHello was observed
    pub client_version:               u16,  // legacy record version from ClientHello
    pub client_num_supported_groups:  u16,  // number of named groups in supported_groups extension
    pub client_num_sig_algs:          u16,  // number of signature algorithms advertised
    pub client_num_alpn_protocols:    u16,  // number of ALPN protocols advertised
    pub client_num_key_shares:        u16,  // number of key share entries (TLS 1.3)
    pub client_num_supported_vers:    u16,  // number of supported_versions entries (TLS 1.3)
    pub client_has_sni:               u8,   // 1 if SNI extension is present
    pub client_sni_hash:              u64,  // bucketed hash of SNI hostname, 0 if absent
    pub client_sni_len:               u16,  // byte length of the SNI hostname, 0 if absent
    pub client_has_session_id:        u8,   // 1 if session_id is non-empty (session resumption hint)
    pub client_session_id_len:        u8,   // length of session_id in bytes (0–32)
    pub client_has_compression:       u8,   // 1 if any non-null compression method is offered
    pub client_has_alpn:              u8,   // 1 if ALPN extension is present
    pub client_has_key_share:         u8,   // 1 if key_share extension is present (TLS 1.3)
    pub client_has_supported_vers:    u8,   // 1 if supported_versions extension is present (TLS 1.3)

    // --- ServerHello ---
    pub has_server_hello:             u8,   // 1 if a ServerHello was observed
    pub server_version:               u16,  // legacy record version from ServerHello
    pub server_cipher_suite:          u16,  // chosen cipher suite ID
    pub server_compression_alg:       u8,   // chosen compression method (0 = null)
    pub server_has_alpn:              u8,   // 1 if server sent ALPN extension
    pub server_has_key_share:         u8,   // 1 if server sent key_share extension (TLS 1.3)
    pub server_has_selected_vers:     u8,   // 1 if server sent supported_versions extension (TLS 1.3)

    // --- Certificates ---
    pub num_server_certs:             u16,  // number of certificates in the server certificate chain
    pub num_client_certs:             u16,  // number of certificates in the client certificate chain
    pub server_cert0_len:             u32,  // raw byte length of the leaf server certificate, 0 if absent
    pub server_cert1_len:             u32,  // raw byte length of the first intermediate cert, 0 if absent

    // --- Key exchange ---
    pub has_server_kex:               u8,   // 1 if ServerKeyExchange was observed (TLS 1.2-)
    pub has_client_kex:               u8,   // 1 if ClientKeyExchange was observed (TLS 1.2-)
    pub kex_type:                     u8,   // 0=none/unknown 1=ECDH 2=DH 3=RSA
}

impl TlsFeatures {
    pub fn from_tls(tls: &TlsHandshake) -> Option<Self> {
        if tls.client_hello.is_none() && tls.server_hello.is_none() {
            return None;
        }

        // --- ClientHello fields ---
        let (
            has_client_hello,
            client_version,
            client_num_supported_groups,
            client_num_sig_algs,
            client_num_alpn_protocols,
            client_num_key_shares,
            client_num_supported_vers,
            client_has_sni,
            client_sni_hash,
            client_sni_len,
            client_has_session_id,
            client_session_id_len,
            client_has_compression,
            client_has_alpn,
            client_has_key_share,
            client_has_supported_vers,
        ) = if let Some(ch) = &tls.client_hello {
            let sni = ch.server_name.clone().unwrap_or_default();
            let sni_len = sni.len() as u16;
            let sni_hash = if sni.is_empty() { 0 } else { hash_str(&sni) };
            (
                1u8,
                ch.version.0,
                ch.supported_groups.len() as u16,
                ch.signature_algs.len() as u16,
                ch.alpn_protocols.len() as u16,
                ch.key_shares.len() as u16,
                ch.supported_versions.len() as u16,
                ch.server_name.is_some() as u8,
                sni_hash,
                sni_len,
                (!ch.session_id.is_empty()) as u8,
                ch.session_id.len() as u8,
                ch.compression_algs.iter().any(|c| c.0 != 0) as u8,
                (!ch.alpn_protocols.is_empty()) as u8,
                (!ch.key_shares.is_empty()) as u8,
                (!ch.supported_versions.is_empty()) as u8,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        };

        // --- ServerHello fields ---
        let (
            has_server_hello,
            server_version,
            server_cipher_suite,
            server_compression_alg,
            server_has_alpn,
            server_has_key_share,
            server_has_selected_vers,
        ) = if let Some(sh) = &tls.server_hello {
            (
                1u8,
                sh.version.0,
                sh.cipher_suite.0,
                sh.compression_alg.0,
                sh.alpn_protocol.is_some() as u8,
                sh.key_share.is_some() as u8,
                sh.selected_version.is_some() as u8,
            )
        } else {
            (0, 0, 0, 0, 0, 0, 0)
        };

        // --- Certificate fields ---
        let num_server_certs = tls.server_certificates.len() as u16;
        let num_client_certs = tls.client_certificates.len() as u16;
        let server_cert0_len = tls.server_certificates.first().map(|c| c.raw.len() as u32).unwrap_or(0);
        let server_cert1_len = tls.server_certificates.get(1).map(|c| c.raw.len() as u32).unwrap_or(0);

        // --- Key exchange fields ---
        use iris_core::protocols::stream::tls::{ClientKeyExchange, ServerKeyExchange};
        let has_server_kex = tls.server_key_exchange.is_some() as u8;
        let has_client_kex = tls.client_key_exchange.is_some() as u8;
        let kex_type: u8 = match &tls.server_key_exchange {
            Some(ServerKeyExchange::Ecdh(_)) => 1,
            Some(ServerKeyExchange::Dh(_))   => 2,
            Some(ServerKeyExchange::Rsa(_))  => 3,
            _ => match &tls.client_key_exchange {
                Some(ClientKeyExchange::Ecdh(_)) => 1,
                Some(ClientKeyExchange::Dh(_))   => 2,
                Some(ClientKeyExchange::Rsa(_))  => 3,
                _ => 0,
            },
        };

        Some(Self {
            has_client_hello,
            client_version,
            client_num_supported_groups,
            client_num_sig_algs,
            client_num_alpn_protocols,
            client_num_key_shares,
            client_num_supported_vers,
            client_has_sni,
            client_sni_hash,
            client_sni_len,
            client_has_session_id,
            client_session_id_len,
            client_has_compression,
            client_has_alpn,
            client_has_key_share,
            client_has_supported_vers,
            has_server_hello,
            server_version,
            server_cipher_suite,
            server_compression_alg,
            server_has_alpn,
            server_has_key_share,
            server_has_selected_vers,
            num_server_certs,
            num_client_certs,
            server_cert0_len,
            server_cert1_len,
            has_server_kex,
            has_client_kex,
            kex_type,
        })
    }
}