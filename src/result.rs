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

        // Packet empty
        PacketEmpty,

        // Packet Malformed
        HandshakePacketMalformed(Vec<u8>),

        //Proto
        ProtoWriteFailed(protobuf::Error),

}