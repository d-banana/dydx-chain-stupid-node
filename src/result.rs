use std::{io};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
        // TCP Stream
        TcpStreamConnectFailed(io::Error),
        TcpStreamCloneFailed(io::Error),

        // Buffer stream
        StreamReadFailed(io::Error),
        StreamWriteFailed(io::Error),

        // Message empty
        MessageChunkTooBig,

        // Missing state
        RemoteVerificationMissing,
        SharedSecretMissing,
        EncryptionKeyMissing,

        // Authentication
        MessageVerificationBadSize(Vec<u8>),
        VerificationKeyIncorrect(ed25519_consensus::Error),

        //Proto
        ProtoBuildFailed,
        ProtoWriteFailed(protobuf::Error),


        //Encryption
        EncryptFailed(chacha20poly1305::aead::Error),
        NounceTooBig,

}