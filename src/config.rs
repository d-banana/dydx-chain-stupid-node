use ed25519_consensus::SigningKey;
use rand_core::OsRng;

#[derive(Clone)]
pub struct Config{
        pub signing_key: SigningKey
}

impl Default for Config {
        fn default() -> Self {
                Config {
                        signing_key: SigningKey::new(OsRng)
                }
        }
}