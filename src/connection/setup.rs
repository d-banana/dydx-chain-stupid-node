use ed25519_consensus::{VerificationKey};
use crate::result::{Result, Error};
use crate::connection::Connection;
use crate::read_message;
use std::io::{Read, Write};
use crate::connection::{ConnectionState, EphemeralKeyPair};
use protobuf::CodedOutputStream;
use std::io::{BufReader, BufWriter, Cursor};
use merlin::Transcript;
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::SharedSecret;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use crate::proto_rust;

const MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE: usize = 35;

pub mod receive_remote_verification_key_ephemeral{
        use super::*;

        pub fn read_process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()>{
                let message_received = read_message!(connection, MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE);

                connection.remote_verification_key_ephemeral = Some(parse_message_to_verification_key_ephemeral(&message_received)?);
                connection.state = ConnectionState::EphemeralReceived;

                Ok(())
        }

        fn parse_message_to_verification_key_ephemeral(message: &[u8; MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE]) -> Result<VerificationKey>{
                let message_size = message[0];

                let is_announced_message_size_correct = message_size as usize != MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE - 1;
                if is_announced_message_size_correct {
                        return Err(Error::HandshakeMessageMalformed(message.to_vec()));
                }

                message.get(3..MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE)
                        .expect("35 - 3 = 32")
                        .try_into()
                        .map_err(|e| Error::ParseVerificationKeyFailed(message.to_vec(), e))
        }

        mod tests{
                use super::*;

                #[test]
                pub fn read_process_success() {
                        let mut fake_message = [1u8;MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE];
                        fake_message[0] = (MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE - 1) as u8;
                        fake_message[1] = 0x0a;
                        fake_message[2] = 0x20;
                        let mut remote = Cursor::new(fake_message.to_vec());

                        let mut connection = Connection{
                                reader: BufReader::new(&mut remote),
                                writer: BufWriter::new(Cursor::new(Vec::new())),
                                state: ConnectionState::Initialize,
                                local_ephemeral: None,
                                remote_verification_key_ephemeral: None,
                                reader_encryption_key: None,
                                writer_encryption_key: None,
                                diffie_hellman_shared_secret: None,
                                write_nounce: 0,
                                read_nounce: 0,
                        };

                        let result = read_process(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(connection.state, ConnectionState::EphemeralReceived);
                        assert!(connection.remote_verification_key_ephemeral.is_some());
                        assert_eq!(connection.remote_verification_key_ephemeral.unwrap(), [1u8; 32].try_into().unwrap())
                }
        }
}

pub mod send_local_verification_key_ephemeral{
        use super::*;

        pub fn write_process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()>{
                let local_ephemeral = EphemeralKeyPair::default();
                let mut message = Vec::with_capacity(MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE);

                message.push((MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE - 1) as u8);
                CodedOutputStream::new(&mut message)
                        .write_bytes(1, local_ephemeral.verification.as_bytes())
                        .map_err(Error::ProtoWriteFailed)?;

                connection.writer
                        .write_all(&message)
                        .map_err(Error::TcpStreamWriteFailed)?;

                connection.local_ephemeral = Some(local_ephemeral);
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
                                local_ephemeral: None,
                                remote_verification_key_ephemeral: None,
                                reader_encryption_key: None,
                                writer_encryption_key: None,
                                diffie_hellman_shared_secret: None,
                                write_nounce: 0,
                                read_nounce: 0,
                        };

                        let result = write_process(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(connection.state, ConnectionState::EphemeralSent);
                        assert!(connection.local_ephemeral.is_some());

                        let message_sent = connection.writer
                                .into_inner()
                                .unwrap()
                                .get_ref();
                        assert_eq!(message_sent.len(), MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE);
                        assert_eq!(
                                *connection.local_ephemeral
                                        .unwrap()
                                        .verification
                                        .as_bytes(),
                                message_sent[3..MESSAGE_VERIFICATION_KEY_EPHEMERAL_SIZE]
                        );
                }
        }
}

pub mod make_encryption_keys {
        use super::*;

        pub fn process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()> {
                let local_ephemeral = connection.local_ephemeral
                        .as_ref()
                        .ok_or(Error::LocalEphemeralKeyMissing)?;
                let remote_ephemeral_verification_key = connection.remote_verification_key_ephemeral
                        .as_ref()
                        .ok_or(Error::RemoteEphemeralKeyMissing)?;

                let is_local_verification_key_smaller_than_remote =
                        &local_ephemeral.verification < remote_ephemeral_verification_key;

                let diffie_hellman_shared_secret = StaticSecret::from(
                        *local_ephemeral.signing.as_bytes())
                        .diffie_hellman(&PublicKey::from(*remote_ephemeral_verification_key.as_bytes()));

                let chacha_encryption_keys = ChaChaEncryptionKeys::new(
                        &diffie_hellman_shared_secret,
                        is_local_verification_key_smaller_than_remote
                );

                connection.reader_encryption_key = Some(chacha_encryption_keys.reader);
                connection.writer_encryption_key = Some(chacha_encryption_keys.writer);
                connection.diffie_hellman_shared_secret = Some(diffie_hellman_shared_secret);
                connection.state = ConnectionState::EncryptionKeysMade;

                Ok(())
        }

        struct ChaChaEncryptionKeys{
                reader: ChaCha20Poly1305,
                writer: ChaCha20Poly1305,
        }
        impl ChaChaEncryptionKeys{
                pub fn new(diffie_hellman_shared_secret: &SharedSecret,
                           is_local_verification_key_smaller_than_remote: bool
                ) -> Self {
                        let mut hkdf_sha256 = [0u8; 64];
                        Hkdf::<Sha256>::new(
                                None,
                                diffie_hellman_shared_secret.as_bytes())
                                .expand(b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN", &mut hkdf_sha256)
                                .expect("64 < x * 255");
                        let (reader,
                                writer): ([u8;32], [u8;32]) = match is_local_verification_key_smaller_than_remote {
                                true =>(
                                        hkdf_sha256
                                                .get(..32)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                        hkdf_sha256
                                                .get(32..64)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                ),
                                false => (
                                        hkdf_sha256
                                                .get(32..64)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                        hkdf_sha256
                                                .get(..32)
                                                .expect("size 96")
                                                .try_into()
                                                .expect("size = 32"),
                                )
                        };

                        ChaChaEncryptionKeys {
                                reader: ChaCha20Poly1305::new(&reader.into()),
                                writer: ChaCha20Poly1305::new(&writer.into()),
                        }
                }
        }

        mod tests {
                use super::*;

                #[test]
                pub fn process_success() {
                        let local_ephemeral = EphemeralKeyPair::default();
                        let remote_ephemeral = EphemeralKeyPair::default();
                        let mut connection = Connection{
                                reader: BufReader::new(Cursor::new(Vec::new())),
                                writer: BufWriter::new(Cursor::new(Vec::new())),
                                state: ConnectionState::Initialize,
                                local_ephemeral: Some(local_ephemeral.clone()),
                                remote_verification_key_ephemeral: Some(remote_ephemeral.clone().verification),
                                reader_encryption_key: None,
                                writer_encryption_key: None,
                                diffie_hellman_shared_secret: None,
                                write_nounce: 0,
                                read_nounce: 0,
                        };

                        assert!(process(&mut connection).is_ok());
                        assert!(connection.reader_encryption_key.is_some());
                        assert!(connection.writer_encryption_key.is_some());
                        assert!(connection.diffie_hellman_shared_secret.is_some());
                        assert_eq!(connection.state, ConnectionState::EncryptionKeysMade);
                }
        }
}

pub mod send_receive_authentication{
        use protobuf::Message;
        use super::*;
        pub fn read_write_process<R: Read, W: Write>(connection: &mut Connection<R, W>) -> Result<()> {
                let local_ephemeral = connection.local_ephemeral
                        .as_ref()
                        .ok_or(Error::LocalEphemeralKeyMissing)?;
                let remote_ephemeral_verification_key = connection.remote_verification_key_ephemeral
                        .as_ref()
                        .ok_or(Error::RemoteEphemeralKeyMissing)?;
                let diffie_hellman_shared_secret = connection.diffie_hellman_shared_secret
                        .as_ref()
                        .ok_or(Error::SharedSecretMissing)?;

                let is_local_verification_key_smaller_than_remote =
                        &local_ephemeral.verification < remote_ephemeral_verification_key;

                let mut transcript = make_transcript(
                        is_local_verification_key_smaller_than_remote,
                        &local_ephemeral.verification,
                        remote_ephemeral_verification_key,
                        diffie_hellman_shared_secret
                );

                let mut message_authentication_code = [0u8; 32];
                transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut message_authentication_code);
                let signed_message_authentication_code = local_ephemeral.signing.sign(&message_authentication_code);

                let mut authentication_signature_message =
                        proto_rust::authentication_signature_message::AuthenticationSignatureMessage::new();
                authentication_signature_message.signature = signed_message_authentication_code
                        .to_bytes()
                        .to_vec();
                authentication_signature_message
                        .verification_key
                        .as_mut()
                        .unwrap()
                        .set_ed25519(
                                local_ephemeral
                                        .verification
                                        .as_bytes()
                                        .to_vec()
                        );
                let message_to_send = authentication_signature_message
                        .write_length_delimited_to_bytes()
                        .unwrap();

                // TODO refactor code + send/receive + check

                Ok(())
        }
        fn make_transcript(
                is_local_verification_key_smaller_than_remote: bool,
                local_verification_key_ephemeral: &VerificationKey,
                remote_verification_key_ephemeral: &VerificationKey,
                diffie_hellman_shared_secret: &SharedSecret
        ) -> Transcript{
                let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

                let (smaller_verification_key,
                        bigger_verification_key) = match is_local_verification_key_smaller_than_remote {
                        true => (local_verification_key_ephemeral, remote_verification_key_ephemeral),
                        false => (remote_verification_key_ephemeral, local_verification_key_ephemeral)
                };

                transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", smaller_verification_key.as_bytes());
                transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", bigger_verification_key.as_bytes());
                transcript.append_message(b"DH_SECRET", diffie_hellman_shared_secret.as_bytes());

                transcript
        }

        mod tests {
                use super::*;
                // TODO add tests
        }
}