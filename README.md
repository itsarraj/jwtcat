# jwtcat

Decode and verify a JWT locally — never paste a real token into jwt.io
again. Debugging auth almost always means looking at a *real* token from
a *real* session, and jwt.io is a website you're sending that token to.
This is a static binary that does the same decode/verify locally.

## Usage

```bash
jwtcat decode "$TOKEN"                       # header + payload + time-validity, no secret needed
jwtcat verify "$TOKEN" --secret "my-secret"  # + HMAC signature check
jwtcat sign '{"sub":"user1","exp":1900000000}' --secret "my-secret"  # mint a test token
```

Exit codes from `verify`: `0` genuinely valid, `1` bad signature, `2` an
algorithm this tool doesn't verify (RS/ES/PS — see Scope), `3` correctly
signed but expired or not-yet-valid. **Not just signature-valid or
invalid** — a script chaining on this exit code would otherwise treat a
correctly-signed-but-expired token as fully valid, exactly the mistake a
`verify` command exists to prevent.

## Scope: HMAC (HS256/384/512) only in v1

RS256/ES256/PS256 (RSA/ECDSA-signed, the common case for OAuth/OIDC
tokens from Auth0, Google, etc.) are **decoded** but not
**cryptographically verified** — that needs the issuer's public key, a
real v2, not attempted here. `verify` reports this honestly
(`signature: NOT CHECKED`, not a false "invalid"), never silently
pretends to have checked something it didn't.

## Status: built and verified against jwt.io's own canonical example token

- **15 unit tests** (`cargo test --lib`): decode round-trips a real
  token; malformed segment counts, invalid base64, and valid-base64-but-
  not-JSON all produce clean errors, not panics; HMAC verification —
  correct secret accepted, wrong secret rejected, **a payload tampered
  with after signing rejected even against the right secret** (the actual
  security property this exists to check), an RS256 header correctly
  reported as `UnsupportedAlg` rather than a false `Invalid`; every
  exp/nbf boundary case (exactly at expiry counts as expired per RFC 7519
  §4.1.4, not-yet-valid, no time claims at all as its own state, not
  silently "valid").
- **CLI verified against a real, independently-checkable token**: used
  the exact example from jwt.io's own homepage (`{"alg":"HS256"}` /
  `{"sub":"1234567890","name":"John Doe",...}`, secret
  `your-256-bit-secret`) — decoded correctly, verified `VALID` with the
  right secret, `INVALID` with the wrong one, both matching what jwt.io
  itself reports for the same token (independently checkable by anyone,
  not just asserted here).
- **A real gap caught and fixed during this same verification pass, not
  after**: the first version of `verify` only checked the signature —
  `jwtcat sign '{"sub":"me","exp":1000000000}' --secret X` (an
  already-expired token) then `jwtcat verify` on it printed
  `signature: VALID` and **exited 0**, which is a genuinely dangerous
  false positive for anything scripting on the exit code. Fixed to also
  check time-validity and exit `3` for an expired-but-correctly-signed
  token; reverified with the same expired token (now exits 3) and the
  original still-valid jwt.io example (still exits 0, confirming the fix
  didn't break the honest-valid case).

**`alg: none` handled explicitly, not just incidentally**: the classic
JWT forgery (attacker sets `alg: none`, strips the signature, bets the
verifier skips the check) gets its own distinct `UnsupportedAlg` message
naming it as an attack rather than falling through to the generic
"not implemented yet" wording an RS256 token gets — same refusal-to-verify
behavior either way, but this one is called out on purpose. Covered by
its own test (`alg_none_forgery_is_never_treated_as_valid`).

**Not done / deliberately deferred**: RS256/ES256/PS256 verification
(see Scope) — the real gap that remains.
