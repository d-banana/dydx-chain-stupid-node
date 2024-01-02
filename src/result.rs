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

        //Proto
        ProtoWriteFailed(protobuf::Error),


        //Encryption
        EncryptFailed(chacha20poly1305::aead::Error),
        NounceTooBig,

}