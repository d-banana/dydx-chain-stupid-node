pub mod setup;

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::{thread};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305};
use ed25519_consensus::{SigningKey, VerificationKey};
use rand_core::OsRng;
use x25519_dalek::SharedSecret;
use crate::connection::setup::{
        receive_remote_verification_key_ephemeral,
        send_local_verification_key_ephemeral,
        make_encryption_keys
};
use crate::result::{Error, Result};

const POLY1305_AUTHENTICATION_TAG_BYTE_SIZE: usize = 16;
const MESSAGE_CHUNK_BYTE_SIZE: usize = 1_024;
const MESSAGE_CHUNK_LEN_BYTE_SIZE: usize = 4;
const NOUNCE_BYTE_SIZE: usize = 12;
const NOUNCE_MAX: u128 = 2u128.pow(96) - 1;

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

#[derive(Debug, Clone)]
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
        pub write_nounce: u128,
        pub read_nounce: u128,
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
                        write_nounce: 0,
                        read_nounce: 0,

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

        pub fn write_encrypted(&mut self, message_raw: &[u8]) -> Result<()> {

                let message_raw_len = message_raw.len();

                for start in (0..message_raw_len).step_by(MESSAGE_CHUNK_BYTE_SIZE){
                        let end = message_raw_len.min(start + MESSAGE_CHUNK_BYTE_SIZE);

                        let message_encrypted_chunk = self.encrypt_message_chunk(
                                &message_raw[start..end])?;

                        // TODO send


                }

                Ok(())
        }

        fn encrypt_message_chunk(&mut self, message_raw_chunk: &[u8]) -> Result<[u8;MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE + POLY1305_AUTHENTICATION_TAG_BYTE_SIZE]>{
                let mut message_encrypted_chunk = [
                        0u8;
                        MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE + POLY1305_AUTHENTICATION_TAG_BYTE_SIZE
                ];

                let message_len_bytes = message_raw_chunk
                        .len()
                        .to_le_bytes();

                message_encrypted_chunk
                        [..MESSAGE_CHUNK_LEN_BYTE_SIZE]
                        .copy_from_slice(&message_len_bytes[..MESSAGE_CHUNK_LEN_BYTE_SIZE]);
                message_encrypted_chunk
                        .get_mut(MESSAGE_CHUNK_LEN_BYTE_SIZE..MESSAGE_CHUNK_LEN_BYTE_SIZE + message_raw_chunk.len())
                        .ok_or(Error::MessageChunkTooBig)?
                        .copy_from_slice(message_raw_chunk);

                let tag = self.writer_encryption_key
                        .as_ref()
                        .ok_or(Error::EncryptionKeyMissing)?
                        .encrypt_in_place_detached(
                                self.write_nounce
                                        .to_le_bytes()
                                        [..NOUNCE_BYTE_SIZE]
                                        .into(),
                                b"",
                                &mut message_encrypted_chunk[..MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE]
                        )
                        .map_err(Error::EncryptFailed)?;

                self.write_nounce += 1;
                if self.write_nounce >= NOUNCE_MAX {
                        return Err(Error::NounceTooBig);
                }

                message_encrypted_chunk
                        [MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE..]
                        .copy_from_slice(tag.as_slice());

                Ok(message_encrypted_chunk)
        }

}