pub mod setup;

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::{thread};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;
use x25519_dalek::SharedSecret;
use crate::connection::setup::{
        receive_remote_verification_key_ephemeral,
        send_local_verification_key_ephemeral,
        make_encryption_keys
};
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
        EncryptionKeysMade,
        AuthenticationDone,
}

#[derive(Debug)]
pub struct EphemeralKeyPair{
        pub signing: SigningKey,
        pub verification: VerificationKey,
}

impl Default for EphemeralKeyPair {
        fn default() -> Self{
                let signing = SigningKey::new(OsRng);
                let verification = signing.verification_key();
                EphemeralKeyPair{
                        signing,
                        verification,
                }
        }
}

pub struct Connection<R: Read, W: Write> {
        reader: BufReader<R>,
        writer: BufWriter<W>,
        pub state: ConnectionState,
        pub local_ephemeral: Option<EphemeralKeyPair>,
        pub remote_verification_key_ephemeral: Option<VerificationKey>,
        pub reader_encryption_key: Option<ChaCha20Poly1305>,
        pub writer_encryption_key: Option<ChaCha20Poly1305>,
        pub diffie_hellman_shared_secret: Option<SharedSecret>,
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
                        local_ephemeral: None,
                        remote_verification_key_ephemeral: None,
                        reader_encryption_key: None,
                        writer_encryption_key: None,
                        diffie_hellman_shared_secret: None,

                })
        }

        pub fn run(mut self) -> Result<()> {
                thread::spawn(move || -> Result<()> {
                        loop {
                                match self.state {
                                        ConnectionState::Initialize => send_local_verification_key_ephemeral::write_process(&mut self)?,
                                        ConnectionState::EphemeralSent => receive_remote_verification_key_ephemeral::read_process(&mut self)?,
                                        ConnectionState::EphemeralReceived => make_encryption_keys::process(&mut self)?,
                                        ConnectionState::EncryptionKeysMade => {}
                                        _ => {}
                                }
                        }

                        Ok(())
                });

                Ok(())
        }
}