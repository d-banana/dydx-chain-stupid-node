use curve25519_dalek::{MontgomeryPoint, Scalar};
use curve25519_dalek::constants::X25519_BASEPOINT;
use rand_core::OsRng;
use crate::result::{Result, Error};
use crate::connection::Connection;
use crate::read_message;
use std::io::{Read, Write};
use crate::connection::ConnectionState;
use protobuf::CodedOutputStream;
use std::io::{BufReader, BufWriter, Cursor};

const MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE: usize = 35;

pub mod receive_remote_public_ephemeral{
        use super::*;

        pub fn read_process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()>{
                let message_received = read_message!(connection, MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE);

                connection.remote_public_ephemeral_ed25519 = Some(parse_message_to_ephemeral_ed25519(&message_received)?);
                connection.state = ConnectionState::EphemeralReceived;

                Ok(())
        }

        fn parse_message_to_ephemeral_ed25519(message: &[u8; MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE]) -> Result<MontgomeryPoint>{
                let packet_size = message[0];

                let is_announced_packet_size_correct = packet_size as usize != MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE - 1;
                if is_announced_packet_size_correct {
                        return Err(Error::HandshakePacketMalformed(message.to_vec()));
                }

                Ok(MontgomeryPoint(
                        message.get(3..MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE)
                                .unwrap()
                                .try_into()
                                .expect("Fixed size array")
                ))
        }

        mod tests{
                use super::*;

                #[test]
                pub fn read_process_success() {
                        let mut fake_message = [1u8;MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE];
                        fake_message[0] = (MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE - 1) as u8;
                        fake_message[1] = 0x0a;
                        fake_message[2] = 0x20;
                        let mut remote = Cursor::new(fake_message.to_vec());

                        let mut connection = Connection{
                                reader: BufReader::new(&mut remote),
                                writer: BufWriter::new(Cursor::new(Vec::new())),
                                state: ConnectionState::Initialize,
                                local_ephemeral_ed25519: None,
                                remote_public_ephemeral_ed25519: None,
                        };

                        let result = read_process(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(connection.state, ConnectionState::EphemeralReceived);
                        assert!(connection.remote_public_ephemeral_ed25519.is_some());
                        assert_eq!(connection.remote_public_ephemeral_ed25519.unwrap(), MontgomeryPoint([1u8; 32]))
                }
        }
}

pub mod send_local_public_ephemeral{
        use super::*;

        #[derive(Debug)]
        pub struct EphemeralED25519KeyPair{
                private: Scalar,
                public: MontgomeryPoint,
        }

        impl Default for EphemeralED25519KeyPair {
                fn default() -> Self{
                        let private = Scalar::random(&mut OsRng);
                        EphemeralED25519KeyPair{
                                private,
                                public: X25519_BASEPOINT * private,
                        }
                }
        }

        pub fn write_process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()>{
                let local_ephemeral_ed25519 = EphemeralED25519KeyPair::default();
                let mut message = Vec::with_capacity(MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE);

                message.push((MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE - 1) as u8);
                CodedOutputStream::new(&mut message)
                        .write_bytes(1, local_ephemeral_ed25519.public.as_bytes())
                        .map_err(Error::ProtoWriteFailed)?;

                connection.writer
                        .write_all(&message)
                        .map_err(Error::TcpStreamWriteFailed)?;

                connection.local_ephemeral_ed25519 = Some(local_ephemeral_ed25519);
                connection.state = ConnectionState::EphemeralSent;

                Ok(())
        }

        mod tests{
                use super::*;

                #[test]
                pub fn write_process_success() {
                        let mut remote = Cursor::new(Vec::new());

                        let mut connection = Connection{
                                reader: BufReader::new(Cursor::new(Vec::new())),
                                writer: BufWriter::new(&mut remote),
                                state: ConnectionState::Initialize,
                                local_ephemeral_ed25519: None,
                                remote_public_ephemeral_ed25519: None,
                        };

                        let result = write_process(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(connection.state, ConnectionState::EphemeralSent);
                        assert!(connection.local_ephemeral_ed25519.is_some());

                        let message_sent = connection.writer
                                .into_inner()
                                .unwrap()
                                .get_ref();
                        assert_eq!(message_sent.len(), MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE);
                        assert_eq!(
                                *connection.local_ephemeral_ed25519
                                        .unwrap()
                                        .public
                                        .as_bytes(),
                                message_sent[3..MESSAGE_PUBLIC_EPHEMERAL_ED25519_SIZE]
                        );
                }
        }
}
