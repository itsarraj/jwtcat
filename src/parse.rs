use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedJwt {
    pub header: Value,
    pub payload: Value,
    /// The exact bytes `signing_input` (`header.payload`, still base64url —
    /// what the signature actually covers) — needed by `verify.rs` to
    /// recompute the HMAC without re-encoding and risking a mismatch from
    /// non-canonical JSON round-tripping.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

/// Splits and decodes a JWT's three segments. Deliberately does **not**
/// verify anything — that's `verify.rs`'s job — so a malformed or
/// unsigned token can still be inspected, which is the whole point of a
/// tool for looking at tokens you didn't issue yourself.
pub fn decode(token: &str) -> Result<DecodedJwt, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "expected 3 dot-separated segments (header.payload.signature), got {}",
            parts.len()
        ));
    }
    let [header_b64, payload_b64, signature_b64] = [parts[0], parts[1], parts[2]];

    let header = decode_json_segment(header_b64, "header")?;
    let payload = decode_json_segment(payload_b64, "payload")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| format!("signature segment isn't valid base64url: {e}"))?;

    Ok(DecodedJwt {
        header,
        payload,
        signing_input: format!("{header_b64}.{payload_b64}"),
        signature,
    })
}

fn decode_json_segment(segment: &str, name: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("{name} segment isn't valid base64url: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{name} segment isn't valid JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real, working HS256 token — `{"alg":"HS256","typ":"JWT"}` /
    /// `{"sub":"1234567890","name":"John Doe","iat":1516239022}`, signed
    /// with the secret `"your-256-bit-secret"`. This exact token is the
    /// canonical jwt.io example, chosen so anyone can independently
    /// cross-check these tests against jwt.io itself.
    const SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn decodes_header_and_payload_of_a_real_token() {
        let decoded = decode(SAMPLE).unwrap();
        assert_eq!(decoded.header["alg"], "HS256");
        assert_eq!(decoded.header["typ"], "JWT");
        assert_eq!(decoded.payload["sub"], "1234567890");
        assert_eq!(decoded.payload["name"], "John Doe");
        assert_eq!(decoded.payload["iat"], 1516239022);
    }

    #[test]
    fn signing_input_is_exactly_the_first_two_segments_rejoined() {
        let decoded = decode(SAMPLE).unwrap();
        assert_eq!(
            decoded.signing_input,
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        );
    }

    #[test]
    fn wrong_number_of_segments_is_a_clear_error() {
        assert!(decode("not.a.jwt.at.all").is_err());
        assert!(decode("onlyonepart").is_err());
    }

    #[test]
    fn invalid_base64_in_a_segment_is_a_clean_error_not_a_panic() {
        let result = decode("not-valid-base64!!!.eyJhIjoxfQ.sig");
        assert!(result.is_err());
    }

    #[test]
    fn valid_base64_that_isnt_json_is_a_clean_error() {
        // "aGVsbG8" base64url-decodes to the plain string "hello", not JSON.
        let result = decode("aGVsbG8.eyJhIjoxfQ.sig");
        assert!(result.is_err());
    }
}
