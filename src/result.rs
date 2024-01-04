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

        // Authentication
        MessageEphemeralPublicBadSize(Vec<u8>),
        RemoteVerificationKeyMissing,
        RemoteAddressDoesntMatch(Vec<u8>, Vec<u8>),
        SignedAuthenticationMessageMalformed,
        RemotePeerSignatureVerificationFailed(ed25519_consensus::Error),

        //Proto
        ProtoWriteFailed(protobuf::Error),
        ProtoReadFailed(protobuf::Error),


        //Encryption
        EncryptFailed(chacha20poly1305::aead::Error),
        DecryptFailed(chacha20poly1305::aead::Error),
        NounceTooBig,

}