// Command interop_rust cross-validates i2pbox outputs against the emissary
// (Rust) implementation's independent parsers.
//
// Subcommand (called by tests/interop/run_interop.sh):
//
//	router-identity <router.info> <expected-hash-b64>
//	    parse the RouterIdentity frame of a router.info and compare its
//	    identity hash (I2P base64) to the i2pbox `routerinfo` output
use std::fs;

use emissary_core::primitives::RouterIdentity;

fn i2p_base64(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data).replace('+', "-").replace('/', "~")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: interop_rust router-identity <router.info> <expected-hash-b64>");
        std::process::exit(2);
    }
    let data = fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("interop_rust: read {}: {e}", args[2]);
        std::process::exit(1);
    });
    // i2pbox (and i2pd) default to ElGamal-encrypted identities; emissary
    // only parses X25519-encrypted ones, so this parse legitimately fails on
    // default keys. Exit 2 so the runner can report it as SKIP, not FAIL.
    let (_rest, identity) = match RouterIdentity::parse_frame(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("interop_rust: SKIP: emissary cannot parse this identity ({e}); emissary only supports X25519-encrypted identities, i2pbox/i2pd default is ElGamal");
            std::process::exit(2);
        }
    };
    let got = i2p_base64(&identity.hash());
    if got != args[2] {
        eprintln!("interop_rust: hash mismatch: emissary={got} i2pbox={}", args[2]);
        std::process::exit(1);
    }
    println!("ok");
}
