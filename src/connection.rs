pub mod setup;

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::{thread};
use std::time::Duration;
use curve25519_dalek::MontgomeryPoint;
use crate::connection::setup::*;
use crate::connection::setup::send_local_public_ephemeral::EphemeralED25519KeyPair;
use crate::result::{Error, Result};

#[macro_export]
macro_rules! read_message {
        ($self: expr, $size: expr) => {
                {
                       let mut buffer = [0u8;$size];
                        $self.reader
                                .read_exact(&mut buffer)
                                .map_err(Error::TcpStreamReadFailed)?;
                        buffer
                }
        }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState{
        Initialize,
        EphemeralSent,
        EphemeralReceived,
        EphemeralShared,
}

#[derive(Debug)]
pub struct Connection<R: Read, W: Write> {
        reader: BufReader<R>,
        writer: BufWriter<W>,
        pub state: ConnectionState,
        pub local_ephemeral_ed25519: Option<EphemeralED25519KeyPair>,
        pub remote_public_ephemeral_ed25519: Option<MontgomeryPoint>
}
impl Connection<TcpStream, TcpStream> {
        pub fn try_new(ip: [u8; 4], port: u16) -> Result<Self>{
                let tcp_stream = TcpStream::connect(SocketAddr::new(ip.into(), port))
                        .map_err(Error::TcpStreamConnectFailed)?;
                let reader = BufReader::new(tcp_stream
                        .try_clone()
                        .map_err(Error::TcpStreamCloneFailed)?);
                let writer = BufWriter::new(tcp_stream
                        .try_clone()
                        .map_err(Error::TcpStreamCloneFailed)?);

                Ok(Connection {
                        reader,
                        writer,
                        state: ConnectionState::Initialize,
                        local_ephemeral_ed25519: None,
                        remote_public_ephemeral_ed25519: None,

                })
        }

        pub fn run(mut self) -> Result<()> {
                thread::spawn(move || -> Result<()> {
                        loop {
                                match self.state {
                                        ConnectionState::Initialize => send_local_public_ephemeral::write_process(&mut self)?,
                                        ConnectionState::EphemeralSent => receive_remote_public_ephemeral::read_process(&mut self)?,
                                        ConnectionState::EphemeralReceived => {
                                                println!("{:?}", self);
                                                thread::sleep(Duration::from_secs(1))
                                        }
                                        ConnectionState::EphemeralShared => {}
                                }
                        }

                        Ok(())
                });

                Ok(())
        }
}