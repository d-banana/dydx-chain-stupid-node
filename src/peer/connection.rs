use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305};
use crate::result::{Error, Result};

const POLY1305_AUTHENTICATION_TAG_BYTE_SIZE: usize = 16;
const MESSAGE_CHUNK_BYTE_SIZE: usize = 1_024;
const MESSAGE_CHUNK_LEN_BYTE_SIZE: usize = 4;
pub const MESSAGE_CHUNK_TOTAL_SIZE: usize = MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE + POLY1305_AUTHENTICATION_TAG_BYTE_SIZE;
const NONCE_BYTE_SIZE: usize = 12;
const NONCE_MAX: u128 = 2u128.pow(96) - 1;

pub enum Connection {
        Tcp(ConnectionTcp),
        Fake(ConnectionFake)
}

pub struct ConnectionTcp {
        pub reader: BufReader<TcpStream>,
        pub writer: BufWriter<TcpStream>,
}

#[derive(Default)]
pub struct ConnectionFake {
        pub local_to_read: Vec<u8>,
        pub remote_to_read: Vec<u8>,
}

impl Connection {
        pub fn write_all(&mut self, message: &[u8]) -> Result<()>{
                println!("Write: {:?}", message);
                match self {
                        Connection::Tcp(tcp) => {
                                tcp.writer
                                        .write_all(message)
                                        .map_err(Error::StreamWriteFailed)?;
                                tcp.writer
                                        .flush()
                                        .map_err(Error::StreamWriteFailed)
                        },
                        Connection::Fake(fake) => fake.write_all(message),
                }
        }

        pub fn read_exact(&mut self, message: &mut [u8]) -> Result<()> {
                match self {
                        Connection::Tcp(tcp) =>tcp.reader
                                .read_exact(message)
                                .map_err(Error::StreamReadFailed),
                        Connection::Fake(fake) => fake.read_exact(message),
                }?;

                println!("Read: {:?}", message);

                Ok(())
        }

        pub fn write_all_encrypted(&mut self, message_raw: &[u8], encryption_key: &ChaCha20Poly1305, nonce: &mut u128) -> Result<()> {
                let message_raw_len = message_raw.len();

                for start in (0..message_raw_len).step_by(MESSAGE_CHUNK_BYTE_SIZE){
                        let end = message_raw_len.min(start + MESSAGE_CHUNK_BYTE_SIZE);

                        let message_encrypted_chunk = encrypt_message_chunk(
                                &message_raw[start..end],
                                encryption_key,
                                nonce
                        )?;

                        self.write_all(&message_encrypted_chunk)?;


                }

                Ok(())
        }

        pub fn read_next_message_encrypted(&mut self, encryption_key: &ChaCha20Poly1305, nonce: &mut u128) -> Result<Vec<u8>> {
                let mut message_raw = Vec::new();

                let mut message_raw_chunk_len = MESSAGE_CHUNK_BYTE_SIZE;

                while message_raw_chunk_len == MESSAGE_CHUNK_BYTE_SIZE {
                        let mut message_encrypted_chunk = [0u8; MESSAGE_CHUNK_TOTAL_SIZE];
                        self.read_exact(&mut message_encrypted_chunk)?;

                        let (message_raw_chunk_len_new, message_raw_chunk) = decrypt_message_chunk(
                                &message_encrypted_chunk,
                                encryption_key,
                                nonce
                        )?;

                        message_raw_chunk_len = message_raw_chunk_len_new as usize;
                        message_raw.extend_from_slice(
                                message_raw_chunk
                                        .get(..message_raw_chunk_len)
                                        .expect("Fix size")
                        );
                }

                Ok(message_raw)
        }

        pub fn connection_fake_mut(&mut self) -> &mut ConnectionFake{
                match self {
                        Connection::Fake(fake) => fake,
                        _ => panic!("Try to get fake from non-fake connection"),
                }
        }

        pub fn connection_fake(&self) -> &ConnectionFake{
                match self {
                        Connection::Fake(fake) => fake,
                        _ => panic!("Try to get fake from non-fake connection"),
                }
        }

        pub fn connection_tcp_mut(&mut self) -> &mut ConnectionTcp{
                match self {
                        Connection::Tcp(tcp) => tcp,
                        _ => panic!("Try to get tcp from non-tcp connection"),
                }
        }

        pub fn connection_tcp(&self) -> &ConnectionTcp{
                match self {
                        Connection::Tcp(tcp) => tcp,
                        _ => panic!("Try to get tcp from non-tcp connection"),
                }
        }

}

impl ConnectionTcp {
        pub fn try_new(ip: [u8; 4], port: u16) -> Result<Self> {
                let tcp_stream = TcpStream::connect(SocketAddr::new(ip.into(), port))
                        .map_err(Error::TcpStreamConnectFailed)?;
                let reader = BufReader::new(tcp_stream
                        .try_clone()
                        .map_err(Error::TcpStreamCloneFailed)?);
                let writer = BufWriter::new(tcp_stream
                        .try_clone()
                        .map_err(Error::TcpStreamCloneFailed)?);

                Ok(ConnectionTcp{
                        reader,
                        writer
                })
        }
}

impl ConnectionFake {
        pub fn write_all(&mut self, message: &[u8]) -> Result<()>{
                self.remote_to_read.extend_from_slice(message);
                Ok(())
        }
        pub fn read_exact(&mut self, message: &mut [u8]) -> Result<()>{
                if message.len() > self.local_to_read.len(){
                        return Err(Error::StreamReadFailed(io::ErrorKind::UnexpectedEof.into()))
                }
                message.copy_from_slice(
                        self.local_to_read
                                .get(..message.len())
                                .expect("Size checked")
                );

                self.local_to_read = self.local_to_read
                        .get(message.len()..)
                        .as_ref()
                        .expect("Size checked")
                        .to_vec();
                Ok(())
        }
}



fn encrypt_message_chunk(
        message_raw_chunk: &[u8],
        encryption_key: &ChaCha20Poly1305,
        nonce: &mut u128
) -> Result<[u8;MESSAGE_CHUNK_TOTAL_SIZE]>{
        let mut message_encrypted_chunk = [
                0u8;
                MESSAGE_CHUNK_TOTAL_SIZE
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

        let tag = encryption_key
                .encrypt_in_place_detached(
                        nonce.to_le_bytes()
                                [..NONCE_BYTE_SIZE]
                                .into(),
                        b"",
                        &mut message_encrypted_chunk[..MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE]
                )
                .map_err(Error::EncryptFailed)?;

        *nonce += 1;
        if *nonce >= NONCE_MAX {
                return Err(Error::NonceTooBig);
        }

        message_encrypted_chunk
                [MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE..]
                .copy_from_slice(tag.as_slice());

        Ok(message_encrypted_chunk)
}

fn decrypt_message_chunk(
        message_encrypted_chunk: &[u8; MESSAGE_CHUNK_TOTAL_SIZE],
        encryption_key: &ChaCha20Poly1305,
        nonce: &mut u128
) -> Result<(u32, [u8; MESSAGE_CHUNK_BYTE_SIZE])>{
        let (message_encrypted_chunk, tag) = message_encrypted_chunk
                .split_at(MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE);

        let mut message_raw_chunk = [0u8; MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE];
        message_raw_chunk.copy_from_slice(message_encrypted_chunk);

        encryption_key.decrypt_in_place_detached(
                nonce.to_le_bytes()
                        [..NONCE_BYTE_SIZE]
                        .into(),
                b"",
                &mut message_raw_chunk,
                tag.into()
        ).map_err(Error::DecryptFailed)?;

        *nonce += 1;
        if *nonce >= NONCE_MAX {
                return Err(Error::NonceTooBig);
        }

        Ok((
                u32::from_le_bytes(
                        message_raw_chunk
                                .get(..MESSAGE_CHUNK_LEN_BYTE_SIZE)
                                .expect("fix size")
                                .try_into()
                                .expect("fix size")
                ),
                message_raw_chunk.get(MESSAGE_CHUNK_LEN_BYTE_SIZE..)
                        .expect("fix size")
                        .try_into()
                        .expect("fix size")
        ))
}

#[cfg(test)]
mod tests {
        use super::*;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
        use crate::peer::encryption::Encryption;

        fn make_local_encryption_key() -> Encryption{
                Encryption {
                        reader_key: ChaCha20Poly1305::new(&[42u8; 32].into()),
                        writer_key: ChaCha20Poly1305::new(&[41u8; 32].into()),
                        write_nonce: 0,
                        read_nonce: 0,
                }
        }

        fn make_remote_encryption_key() -> Encryption{
                Encryption {
                        reader_key: ChaCha20Poly1305::new(&[41u8; 32].into()),
                        writer_key: ChaCha20Poly1305::new(&[42u8; 32].into()),
                        write_nonce: 0,
                        read_nonce: 0,
                }
        }

        #[test]
        pub fn encrypt_decrypt_message_success() {
                let mut local_encryption = make_local_encryption_key();
                let mut remote_encryption = make_remote_encryption_key();
                let message = b"THE MAGIC WORDS ARE SQUEAMISH OSSIFRAGE";

                let message_encrypted = encrypt_message_chunk(
                        message,
                        &local_encryption.writer_key,
                        &mut local_encryption.write_nonce
                ).expect("Failed to encrypt message chunk");

                let (message_len, message_decrypted) = decrypt_message_chunk(
                        &message_encrypted,
                        &remote_encryption.reader_key,
                        &mut remote_encryption.read_nonce
                ).expect("Failed to decrypt message chunk");

                assert_eq!(message, &message_decrypted[..message_len as usize]);
        }

        #[test]
        pub fn read_write_multiple_chunk_success(){
                let mut local_encryption = make_local_encryption_key();
                let mut remote_encryption = make_remote_encryption_key();

                let mut message = Vec::with_capacity(3_000);
                while message.len() < 3000 {
                        match message.len() {
                                i if i < MESSAGE_CHUNK_BYTE_SIZE => message.push(1u8),
                                i if i < MESSAGE_CHUNK_BYTE_SIZE * 2 => message.push(2u8),
                                i if i < 3_000 => message.push(3u8),
                                _ => break
                        }
                }

                let mut connection = Connection::Fake(ConnectionFake::default());

                connection.write_all_encrypted(
                        &message,
                        &local_encryption.writer_key,
                        &mut local_encryption.write_nonce
                ).expect("Failed to write all encrypted");

                connection.connection_fake_mut().local_to_read = connection
                        .connection_fake().remote_to_read.clone();

                let remote_message = connection
                        .read_next_message_encrypted(
                                &remote_encryption.reader_key,
                                &mut remote_encryption.read_nonce
                        ).expect("Failed to read next message encryted");

                assert_eq!(message, remote_message.as_slice());
        }
}