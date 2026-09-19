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

/// Verifies an HMAC-family (`HS256`/`HS384`/`HS512`) signature against
/// `secret`. Recomputes the HMAC over `decoded.signing_input` exactly as
/// received (see `DecodedJwt`'s doc comment) and compares it to the
/// token's actual signature bytes using each `hmac` crate's own
/// constant-time `verify_slice` — never a manual `==` on the digests,
/// which would reintroduce exactly the timing side-channel HMAC
/// verification exists to avoid.
pub fn verify_hmac(decoded: &DecodedJwt, secret: &[u8]) -> VerifyResult {
    let alg = decoded
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input = decoded.signing_input.as_bytes();

    match alg {
        "HS256" => verify_with::<Hmac<Sha256>>(input, secret, &decoded.signature),
        "HS384" => verify_with::<Hmac<Sha384>>(input, secret, &decoded.signature),
        "HS512" => verify_with::<Hmac<Sha512>>(input, secret, &decoded.signature),
        // The classic JWT forgery: an attacker sets `alg: none` and strips
        // the signature entirely, betting that a lax verifier treats an
        // absent check as a passing one. Flagged with its own message
        // (still `UnsupportedAlg`, still never `Valid` — just a clearer
        // reason why) rather than folded into the generic RS256-style
        // "not implemented yet" case, since this one is an attack, not a
        // missing feature.
        "none" | "None" | "NONE" => {
            VerifyResult::UnsupportedAlg("none — this is the alg:none forgery attack, not a real algorithm; never treat this as verified".to_string())
        }
        other => VerifyResult::UnsupportedAlg(other.to_string()),
    }
}

fn verify_with<M: Mac + hmac::digest::KeyInit>(
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

/// The base64url-encoded signature a correct HMAC verification would
/// accept — exposed for tests and for `main.rs`'s `--sign` convenience
/// mode (recreating a token with a known secret, useful for testing your
/// own backend's verification code against a known-good token).
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
        let result = verify_hmac(&decoded, b"your-256-bit-secret");
        assert_eq!(result, VerifyResult::Valid);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let decoded = decode(SAMPLE).unwrap();
        let result = verify_hmac(&decoded, b"the-wrong-secret");
        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn tampered_payload_is_rejected_even_with_the_right_secret() {
        // Same header/signature, but a payload edited after signing —
        // exactly what a forged token looks like.
        let tampered = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZWQiLCJuYW1lIjoiTWFsbG9yeSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let decoded = decode(tampered).unwrap();
        let result = verify_hmac(&decoded, b"your-256-bit-secret");
        assert_eq!(result, VerifyResult::Invalid);
    }

    #[test]
    fn unsupported_algorithm_is_reported_distinctly_not_as_invalid() {
        // A real RS256 header, this tool doesn't attempt RSA verification.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"x"}"#);
        let token = format!("{header}.{payload}.fakesig");
        let decoded = decode(&token).unwrap();
        let result = verify_hmac(&decoded, b"anything");
        assert_eq!(result, VerifyResult::UnsupportedAlg("RS256".to_string()));
    }

    #[test]
    fn alg_none_forgery_is_never_treated_as_valid() {
        // The classic attack: a forged token with alg:none and an empty
        // signature — must never come back Valid, regardless of secret.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"admin"}"#);
        let token = format!("{header}.{payload}.");
        let decoded = decode(&token).unwrap();
        let result = verify_hmac(&decoded, b"whatever-secret-doesnt-matter");
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
            verify_hmac(&decoded, b"my-test-secret"),
            VerifyResult::Valid
        );
        assert_eq!(verify_hmac(&decoded, b"wrong"), VerifyResult::Invalid);
    }
}
