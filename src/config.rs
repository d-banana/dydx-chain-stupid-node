use ed25519_consensus::SigningKey;
use rand_core::OsRng;
use crate::peer::PeerVersion;

#[derive(Clone)]
pub struct Config{
        pub signing_key: SigningKey,
        pub version: PeerVersion
}

impl Config{
        pub fn new(
                version: PeerVersion,
        ) -> Self{
                Config{
                        signing_key: SigningKey::new(OsRng),
                        version
                }
        }
}

impl Default for Config {
        fn default() -> Self {
                Config {
                        signing_key: SigningKey::new(OsRng),
                        version: PeerVersion::default()
                }
        }
}