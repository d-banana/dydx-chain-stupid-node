use crate::proto_rust::peer_info_message::PeerInfo;
use crate::result::*;

#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct Version {
        pub p2p: u64,
        pub block: u64,
        pub app: u64,
        pub tendermint: String,
        pub network: String,
}

impl Version {
        pub fn is_compatible(&self, version: &Version) -> Result<()>{
                match self == version {
                        true => Ok(()),
                        false => Err(Error::PeerVersionIncompatible(
                                self.clone(),
                                version.clone()
                        ))
                }
        }
}

impl From<&PeerInfo> for Version {
        fn from(peer: &PeerInfo) -> Self {
                let protocol_version = peer.protocol_version.get_or_default();
                Version {
                        p2p: protocol_version.p2p,
                        block: protocol_version.block,
                        app: protocol_version.app,
                        tendermint: peer.tendermint_version.clone(),
                        network: peer.network.clone(),
                }
        }
}