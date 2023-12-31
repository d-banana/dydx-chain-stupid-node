use ed25519_consensus::{VerificationKey, SigningKey};
use protobuf::CodedOutputStream;
use merlin::Transcript;
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use protobuf::Message;
use x25519_dalek::{SharedSecret};

use crate::result::{Result, Error};
use crate::proto_rust;
use crate::peer::{
        connection::*,
        encryption::*
};

const MESSAGE_VERIFICATION_SIZE: usize = 35;

pub mod write_local_verification {
        use super::*;

        pub fn write_local_verification(
                connection: &mut Connection,
                local_verification: &VerificationKey
        ) -> Result<()>{
                let mut message = Vec::with_capacity(MESSAGE_VERIFICATION_SIZE);

                message.push((MESSAGE_VERIFICATION_SIZE - 1) as u8);
                CodedOutputStream::new(&mut message)
                        .write_bytes(1, local_verification.as_bytes())
                        .map_err(Error::ProtoWriteFailed)?;

                connection.write_all(&message)?;

                Ok(())
        }

        #[cfg(test)]
        mod tests{
                use rand_core::OsRng;
                use super::*;

                #[test]
                pub fn write_local_verification_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());
                        let local_verification = &SigningKey::new(OsRng).verification_key();

                        let result = write_local_verification(
                                &mut connection,
                                &local_verification
                        );
                        assert!(result.is_ok());

                        let message_sent = &connection.connection_fake().remote_to_read;
                        assert_eq!(message_sent.len(), MESSAGE_VERIFICATION_SIZE);
                        assert_eq!(
                                message_sent[..3],
                                [(MESSAGE_VERIFICATION_SIZE - 1) as u8, 0x0a, 0x20]
                        );
                        assert_eq!(
                                *local_verification.as_bytes(),
                                message_sent[3..MESSAGE_VERIFICATION_SIZE]
                        );
                }
        }
}

pub mod read_remote_verification {
        use super::*;

        pub fn read_remote_verification(connection: &mut Connection) -> Result<VerificationKey>{
                let mut message = [0u8; MESSAGE_VERIFICATION_SIZE];
                connection.read_exact(&mut message)?;

                parse_message_to_verification(&message)
        }

        fn parse_message_to_verification(message: &[u8; MESSAGE_VERIFICATION_SIZE]) -> Result<VerificationKey>{
                let message_size = message[0];

                let is_announced_message_size_correct = message_size as usize != MESSAGE_VERIFICATION_SIZE - 1;
                if is_announced_message_size_correct {
                        return Err(Error::MessageVerificationBadSize(message.to_vec()));
                }

                message.get(3..MESSAGE_VERIFICATION_SIZE)
                        .expect("35 - 3 = 32")
                        .try_into()
                        .map_err(|_| Error::MessageVerificationBadSize(message.to_vec()))
        }

        #[cfg(test)]
        mod tests{
                use super::*;

                #[test]
                pub fn read_remote_verification_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());

                        let mut fake_message = [1u8; MESSAGE_VERIFICATION_SIZE];
                        fake_message[0] = (MESSAGE_VERIFICATION_SIZE - 1) as u8;
                        fake_message[1] = 0x0a;
                        fake_message[2] = 0x20;

                        connection.connection_fake_mut().local_to_read = Vec::from(fake_message);

                        let result = read_remote_verification(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(result.unwrap().as_bytes(), &([1u8; 32]));
                }
        }
}

pub mod make_encryption_keys {
        use super::*;

        pub fn make_encryption_keys(
                is_local_verification_smaller_than_remote: bool,
                shared_secret: &SharedSecret
        ) -> Result<Encryption> {
                let chacha_encryption_keys = ChaChaEncryptionKeys::new(
                        shared_secret,
                        is_local_verification_smaller_than_remote
                );

                Ok(Encryption{
                        reader_key: chacha_encryption_keys.reader,
                        writer_key: chacha_encryption_keys.writer,
                        write_nounce: 0,
                        read_nounce: 0,
                })
        }

        struct ChaChaEncryptionKeys{
                reader: ChaCha20Poly1305,
                writer: ChaCha20Poly1305,
        }
        impl ChaChaEncryptionKeys{
                pub fn new(shared_secret: &SharedSecret,
                           is_local_verification_smaller_than_remote: bool
                ) -> Self {
                        let mut hkdf_sha256 = [0u8; 64];
                        Hkdf::<Sha256>::new(
                                None,
                                shared_secret.as_bytes())
                                .expand(b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN", &mut hkdf_sha256)
                                .expect("64 < x * 255");
                        let (reader,
                                writer): ([u8;32], [u8;32]) = match is_local_verification_smaller_than_remote {
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

        #[cfg(test)]
        mod tests {
                use rand_core::OsRng;
                use x25519_dalek::{PublicKey, StaticSecret};
                use super::*;

                #[test]
                pub fn make_encryption_keys_success() {
                        assert!(
                                make_encryption_keys(
                                        true,
                                        &StaticSecret::random_from_rng(OsRng)
                                                .diffie_hellman(&PublicKey::from([8u8;32]))
                                ).is_ok()
                        );
                }
        }
}

pub mod read_write_authentication{
        use super::*;
        pub fn read_write_authentication(
                local_signing: &SigningKey,
                local_verification: &VerificationKey,
                remote_verification: &VerificationKey,
                shared_secret: &SharedSecret,
                connection: &mut Connection,
                encryption: &mut Encryption

        ) -> Result<()> {
                let authentication_code = &make_authentication_challenge_code(
                        local_verification,
                        remote_verification,
                        shared_secret
                );

                let signed_authentication_message = make_signed_authentication_message(
                        local_signing,
                        local_verification,
                        authentication_code
                )?;

                connection.write_all_encrypted(
                        signed_authentication_message.as_slice(),
                        &encryption.writer_key,
                        &mut encryption.write_nounce
                )?;

                // TODO receive + check

                Ok(())
        }

        fn make_authentication_challenge_code(
                local_verification: &VerificationKey,
                remote_verification: &VerificationKey,
                shared_secret: &SharedSecret
        ) -> [u8; 32]{
                let is_local_verification_smaller_than_remote =
                        local_verification < remote_verification;

                let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

                let (smaller_verification,
                        bigger_verification) = match is_local_verification_smaller_than_remote {
                        true => (local_verification, remote_verification),
                        false => (remote_verification, local_verification)
                };

                transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", smaller_verification.as_bytes());
                transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", bigger_verification.as_bytes());
                transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

                let mut message_authentication_code = [0u8; 32];
                transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut message_authentication_code);

                message_authentication_code
        }

        fn make_signed_authentication_message(
                local_signing: &SigningKey,
                local_verification: &VerificationKey,
                authentication_code: &[u8;32],
        ) -> Result<Vec<u8>>{
                let signed_authentication_code = local_signing.sign(authentication_code);

                let mut signed_authentication_message =
                        proto_rust::signed_authentication_message::SignedAuthenticationMessage::new();

                signed_authentication_message.signed_authentication = signed_authentication_code
                        .to_bytes()
                        .to_vec();

                let verification_key = signed_authentication_message
                        .verification_key
                        .as_mut()
                        .ok_or(Error::ProtoBuildFailed)?;

                verification_key.set_ed25519(
                        local_verification
                                .as_bytes()
                                .to_vec()
                );

                signed_authentication_message
                        .write_length_delimited_to_bytes()
                        .map_err(Error::ProtoWriteFailed)
        }

        #[cfg(test)]
        mod tests {
                use super::*;
                // TODO add tests
        }
}