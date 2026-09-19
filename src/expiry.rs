use std::time::{Duration, SystemTime};

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum TimeStatus {
    /// No `exp`/`nbf` claims present at all — many tokens legitimately
    /// don't have one (a long-lived API key encoded as a JWT, say), so
    /// this is reported as its own state, not silently treated as "valid".
    NoTimeClaims,
    Expired {
        seconds_ago: i64,
    },
    NotYetValid {
        seconds_until: i64,
    },
    Valid,
}

/// Reads `exp`/`nbf` (both standard, both optional per RFC 7519) out of a
/// decoded payload and classifies the token's time-validity as of `now` —
/// pure, `now` passed in rather than read internally, so every boundary
/// case is exactly reproducible in a test.
pub fn check_time_validity(payload: &Value, now: SystemTime) -> TimeStatus {
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let exp = payload.get("exp").and_then(|v| v.as_i64());
    let nbf = payload.get("nbf").and_then(|v| v.as_i64());

    if exp.is_none() && nbf.is_none() {
        return TimeStatus::NoTimeClaims;
    }

    if let Some(nbf) = nbf {
        if now_secs < nbf {
            return TimeStatus::NotYetValid {
                seconds_until: nbf - now_secs,
            };
        }
    }

    if let Some(exp) = exp {
        if now_secs >= exp {
            return TimeStatus::Expired {
                seconds_ago: now_secs - exp,
            };
        }
    }

    TimeStatus::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn no_time_claims_at_all_is_its_own_state() {
        let payload = json!({"sub": "user1"});
        assert_eq!(
            check_time_validity(&payload, at(1000)),
            TimeStatus::NoTimeClaims
        );
    }

    #[test]
    fn expired_token_reports_how_long_ago() {
        let payload = json!({"exp": 1000});
        let status = check_time_validity(&payload, at(1500));
        assert_eq!(status, TimeStatus::Expired { seconds_ago: 500 });
    }

    #[test]
    fn exactly_at_expiry_counts_as_expired() {
        // exp is "valid up to and not including" per RFC 7519 §4.1.4.
        let payload = json!({"exp": 1000});
        assert_eq!(
            check_time_validity(&payload, at(1000)),
            TimeStatus::Expired { seconds_ago: 0 }
        );
    }

    #[test]
    fn not_yet_valid_token_reports_how_long_until() {
        let payload = json!({"nbf": 2000});
        let status = check_time_validity(&payload, at(1500));
        assert_eq!(status, TimeStatus::NotYetValid { seconds_until: 500 });
    }

    #[test]
    fn currently_valid_token_between_nbf_and_exp() {
        let payload = json!({"nbf": 1000, "exp": 2000});
        assert_eq!(check_time_validity(&payload, at(1500)), TimeStatus::Valid);
    }
}
