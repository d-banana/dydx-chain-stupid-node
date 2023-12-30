use std::{io};
use crate::connection::ConnectionState;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
        // TCP Stream
        TcpStreamConnectFailed(io::Error),
        TcpStreamReadFailed(io::Error),
        TcpStreamCloneFailed(io::Error),
        TcpStreamWriteFailed(io::Error),
        ConnectionStateUpdateImpossible(ConnectionState, ConnectionState),

        // Message empty
        MessageEmpty,
        MessageChunkTooBig,

        // ED25519
        ParseVerificationKeyFailed(Vec<u8>, ed25519_consensus::Error),

        // Missing state
        LocalEphemeralKeyMissing,
        RemoteEphemeralKeyMissing,
        SharedSecretMissing,
        EncryptionKeyMissing,

        // Message Malformed
        HandshakeMessageMalformed(Vec<u8>),

        //Proto
        ProtoWriteFailed(protobuf::Error),

        //Encryption
        EncryptFailed(chacha20poly1305::aead::Error),
        NounceTooBig,

}