use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384, Sha512};

use crate::parse::DecodedJwt;

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyResult {
    Valid,
    Invalid,
    /// `alg` is something this tool doesn't verify (RS256/ES256/none/...) —
    /// distinct from `Invalid` on purpose: telling someone their RS256
    /// token is "invalid" when it was simply never checked would be a
    /// straightforwardly false claim about a real security property.
    UnsupportedAlg(String),
}

pub fn verify_signature(decoded: &DecodedJwt, key: &[u8]) -> VerifyResult {
    let alg = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input = decoded.signing_input.as_bytes();

    match alg {
        "HS256" => verify_with_hmac::<Hmac<Sha256>>(input, key, &decoded.signature),
        "HS384" => verify_with_hmac::<Hmac<Sha384>>(input, key, &decoded.signature),
        "HS512" => verify_with_hmac::<Hmac<Sha512>>(input, key, &decoded.signature),
        "RS256" => verify_with_ring(&ring::signature::RSA_PKCS1_2048_8192_SHA256, input, key, &decoded.signature),
        "RS384" => verify_with_ring(&ring::signature::RSA_PKCS1_2048_8192_SHA384, input, key, &decoded.signature),
        "RS512" => verify_with_ring(&ring::signature::RSA_PKCS1_2048_8192_SHA512, input, key, &decoded.signature),
        "PS256" => verify_with_ring(&ring::signature::RSA_PSS_2048_8192_SHA256, input, key, &decoded.signature),
        "PS384" => verify_with_ring(&ring::signature::RSA_PSS_2048_8192_SHA384, input, key, &decoded.signature),
        "PS512" => verify_with_ring(&ring::signature::RSA_PSS_2048_8192_SHA512, input, key, &decoded.signature),
        "ES256" => verify_with_ring(&ring::signature::ECDSA_P256_SHA256_FIXED, input, key, &decoded.signature),
        "ES384" => verify_with_ring(&ring::signature::ECDSA_P384_SHA384_FIXED, input, key, &decoded.signature),
        "none" | "None" | "NONE" => {
            VerifyResult::UnsupportedAlg("none — this is the alg:none forgery attack, not a real algorithm; never treat this as verified".to_string())
        }
        other => VerifyResult::UnsupportedAlg(other.to_string()),
    }
}

fn verify_with_hmac<M: Mac + hmac::digest::KeyInit>(
    input: &[u8],
    secret: &[u8],
    signature: &[u8],
) -> VerifyResult {
    let Ok(mut mac) = <M as hmac::digest::KeyInit>::new_from_slice(secret) else {
        return VerifyResult::Invalid;
    };
    mac.update(input);
    match mac.verify_slice(signature) {
        Ok(()) => VerifyResult::Valid,
        Err(_) => VerifyResult::Invalid,
    }
}

fn decode_pem(key: &[u8]) -> Vec<u8> {
    if let Ok(key_str) = std::str::from_utf8(key) {
        if key_str.contains("-----BEGIN PUBLIC KEY-----") || key_str.contains("-----BEGIN CERTIFICATE-----") {
            let b64 = key_str
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>();
            if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
                return der;
            }
        }
    }
    key.to_vec()
}

fn verify_with_ring(
    alg: &'static dyn ring::signature::VerificationAlgorithm,
    input: &[u8],
    key: &[u8],
    signature: &[u8],
) -> VerifyResult {
    let der = decode_pem(key);
    let pub_key = ring::signature::UnparsedPublicKey::new(alg, der);
    match pub_key.verify(input, signature) {
        Ok(()) => VerifyResult::Valid,
        Err(_) => VerifyResult::Invalid,
    }
}

pub fn sign_hmac_hs256(signing_input: &str, secret: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::decode;

    const SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn correct_secret_verifies_the_canonical_jwt_io_example() {
        let decoded = decode(SAMPLE).unwrap();
        let result = verify_signature(&decoded, b"your-256-bit-secret");
        assert_eq!(result, VerifyResult::Valid);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let decoded = decode(SAMPLE).unwrap();
        let result = verify_signature(&decoded, b"the-wrong-secret");
        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn tampered_payload_is_rejected_even_with_the_right_secret() {
        let tampered = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZWQiLCJuYW1lIjoiTWFsbG9yeSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let decoded = decode(tampered).unwrap();
        let result = verify_signature(&decoded, b"your-256-bit-secret");
        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn unsupported_algorithm_is_reported_distinctly_not_as_invalid() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#);
        let token = format!("{header}.{payload}.fakesig");
        let decoded = decode(&token).unwrap();
        let result = verify_signature(&decoded, b"anything");
        assert_eq!(result, VerifyResult::UnsupportedAlg("EdDSA".to_string()));
    }

    #[test]
    fn alg_none_forgery_is_never_treated_as_valid() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"admin"}"#);
        let token = format!("{header}.{payload}.");
        let decoded = decode(&token).unwrap();
        let result = verify_signature(&decoded, b"whatever-secret-doesnt-matter");
        assert!(matches!(result, VerifyResult::UnsupportedAlg(_)));
        assert_ne!(result, VerifyResult::Valid);
    }

    #[test]
    fn sign_then_verify_round_trips_with_a_freshly_generated_token() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"me"}"#);
        let signing_input = format!("{header}.{payload}");
        let sig = sign_hmac_hs256(&signing_input, b"my-test-secret");
        let token = format!("{signing_input}.{sig}");

        let decoded = decode(&token).unwrap();
        assert_eq!(
            verify_signature(&decoded, b"my-test-secret"),
            VerifyResult::Valid
        );
        assert_eq!(verify_signature(&decoded, b"wrong"), VerifyResult::Invalid);
    }
}
