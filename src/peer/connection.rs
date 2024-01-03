use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Tag};
use crate::result::{Error, Result};

const POLY1305_AUTHENTICATION_TAG_BYTE_SIZE: usize = 16;
const MESSAGE_CHUNK_BYTE_SIZE: usize = 1_024;
const MESSAGE_CHUNK_LEN_BYTE_SIZE: usize = 4;
pub const MESSAGE_CHUNK_TOTAL_SIZE: usize = MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE + POLY1305_AUTHENTICATION_TAG_BYTE_SIZE;
const NOUNCE_BYTE_SIZE: usize = 12;
const NOUNCE_MAX: u128 = 2u128.pow(96) - 1;

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

        pub fn write_all_encrypted(&mut self, message_raw: &[u8], encryption_key: &ChaCha20Poly1305, nounce: &mut u128) -> Result<()> {
                let message_raw_len = message_raw.len();

                for start in (0..message_raw_len).step_by(MESSAGE_CHUNK_BYTE_SIZE){
                        let end = message_raw_len.min(start + MESSAGE_CHUNK_BYTE_SIZE);

                        let message_encrypted_chunk = encrypt_message_chunk(
                                &message_raw[start..end],
                                encryption_key,
                                nounce
                        )?;

                        self.write_all(&message_encrypted_chunk)?;


                }

                Ok(())
        }

        pub fn read_next_message_encrypted(&mut self, encryption_key: &ChaCha20Poly1305, nounce: &mut u128) -> Result<Vec<u8>> {
                let mut message_raw = Vec::new();

                let mut message_raw_chunk_len = MESSAGE_CHUNK_BYTE_SIZE;

                while message_raw_chunk_len == MESSAGE_CHUNK_BYTE_SIZE {
                        let mut message_encrypted_chunk = [0u8; MESSAGE_CHUNK_TOTAL_SIZE];
                        self.read_exact(&mut message_encrypted_chunk)?;

                        let (message_raw_chunk_len_new, message_raw_chunk) = decrypt_message_chunk(
                                &message_encrypted_chunk,
                                encryption_key,
                                nounce
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
        nounce: &mut u128
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
                        nounce.to_le_bytes()
                                [..NOUNCE_BYTE_SIZE]
                                .into(),
                        b"",
                        &mut message_encrypted_chunk[..MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE]
                )
                .map_err(Error::EncryptFailed)?;

        *nounce += 1;
        if *nounce >= NOUNCE_MAX {
                return Err(Error::NounceTooBig);
        }

        message_encrypted_chunk
                [MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE..]
                .copy_from_slice(tag.as_slice());

        Ok(message_encrypted_chunk)
}

fn decrypt_message_chunk(
        message_encrypted_chunk: &[u8; MESSAGE_CHUNK_TOTAL_SIZE],
        encryption_key: &ChaCha20Poly1305,
        nounce: &mut u128
) -> Result<(u32, [u8; MESSAGE_CHUNK_BYTE_SIZE])>{
        let (message_encrypted_chunk, tag) = message_encrypted_chunk
                .split_at(MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE);

        let mut message_raw_chunk = [0u8; MESSAGE_CHUNK_BYTE_SIZE + MESSAGE_CHUNK_LEN_BYTE_SIZE];
        message_raw_chunk.copy_from_slice(message_encrypted_chunk);

        encryption_key.decrypt_in_place_detached(
                nounce.to_le_bytes()
                        [..NOUNCE_BYTE_SIZE]
                        .into(),
                b"",
                &mut message_raw_chunk,
                tag.into()
        ).map_err(Error::DecryptFailed)?;

        *nounce += 1;
        if *nounce >= NOUNCE_MAX {
                return Err(Error::NounceTooBig);
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