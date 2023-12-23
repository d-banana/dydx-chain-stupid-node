use std::{io, result};

pub type Result<T> = result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
        // TCP Stream
        TcpStreamConnectFailed(io::Error),
        TcpStreamReadFailed(io::Error),
        TcpStreamCloneFailed(io::Error),

        // Packet empty
        PacketEmpty,

        // Packet Malformed
        HandshakePacketMalformed(Vec<u8>)

}