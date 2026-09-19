use std::time::SystemTime;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use jwtcat::expiry::{check_time_validity, TimeStatus};
use jwtcat::parse::decode;
use jwtcat::verify::{sign_hmac_hs256, verify_hmac, VerifyResult};

#[derive(Parser)]
#[command(
    name = "jwtcat",
    about = "Decode and verify a JWT locally — never paste a real token into jwt.io"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode a token's header and payload. No signature check.
    Decode { token: String },
    /// Decode and verify an HS256/HS384/HS512 signature.
    Verify {
        token: String,
        #[arg(long)]
        secret: String,
    },
    /// Sign a payload as a fresh HS256 token — useful for testing your own
    /// backend's verification against a token you know is valid.
    Sign {
        /// Raw JSON object, e.g. '{"sub":"user1","exp":1900000000}'.
        payload: String,
        #[arg(long)]
        secret: String,
    },
}

fn print_decoded(header: &serde_json::Value, payload: &serde_json::Value) {
    println!(
        "header:\n{}\n",
        serde_json::to_string_pretty(header).unwrap()
    );
    println!(
        "payload:\n{}\n",
        serde_json::to_string_pretty(payload).unwrap()
    );
    match check_time_validity(payload, SystemTime::now()) {
        TimeStatus::NoTimeClaims => println!("time: no exp/nbf claims present"),
        TimeStatus::Valid => println!("time: currently valid"),
        TimeStatus::Expired { seconds_ago } => println!("time: EXPIRED {seconds_ago}s ago"),
        TimeStatus::NotYetValid { seconds_until } => {
            println!("time: NOT YET VALID for another {seconds_until}s")
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Decode { token } => {
            let decoded = decode(&token).map_err(|e| anyhow::anyhow!(e))?;
            print_decoded(&decoded.header, &decoded.payload);
        }
        Command::Verify { token, secret } => {
            let decoded = decode(&token).map_err(|e| anyhow::anyhow!(e))?;
            print_decoded(&decoded.header, &decoded.payload);
            // A "verified" token must be both correctly signed AND
            // currently time-valid — checking only the signature would
            // let a script chaining on this command's exit code treat a
            // correctly-signed-but-expired token as fully valid, which is
            // exactly the mistake a "verify" command exists to prevent.
            let time_status = check_time_validity(&decoded.payload, SystemTime::now());
            match verify_hmac(&decoded, secret.as_bytes()) {
                VerifyResult::Valid => {
                    println!("signature: VALID");
                    match time_status {
                        TimeStatus::Expired { .. } | TimeStatus::NotYetValid { .. } => {
                            std::process::exit(3);
                        }
                        TimeStatus::Valid | TimeStatus::NoTimeClaims => {}
                    }
                }
                VerifyResult::Invalid => {
                    println!("signature: INVALID");
                    std::process::exit(1);
                }
                VerifyResult::UnsupportedAlg(alg) => {
                    println!("signature: NOT CHECKED — '{alg}' isn't HMAC (jwtcat only verifies HS256/HS384/HS512; RS/ES/PS algorithms need the issuer's public key, not implemented in this v1)");
                    std::process::exit(2);
                }
            }
        }
        Command::Sign { payload, secret } => {
            serde_json::from_str::<serde_json::Value>(&payload)
                .map_err(|e| anyhow::anyhow!("payload isn't valid JSON: {e}"))?;
            let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
            let signing_input = format!("{header}.{payload_b64}");
            let sig = sign_hmac_hs256(&signing_input, secret.as_bytes());
            println!("{signing_input}.{sig}");
        }
    }
    Ok(())
}
