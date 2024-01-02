use protobuf::CodedOutputStream;
use merlin::Transcript;
use hkdf::Hkdf;
use sha2::Sha256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use protobuf::Message;
use x25519_dalek::{SharedSecret, PublicKey as EphemeralPublic};
use ed25519_consensus::SigningKey;

use crate::result::{Result, Error};
use crate::proto_rust;
use crate::peer::{
        connection::*,
        encryption::*
};

const MESSAGE_EPHEMERAL_PUBLIC_SIZE: usize = 35;

pub mod write_local_ephemeral_public {
        use super::*;

        pub fn write_local_ephemeral_public(
                connection: &mut Connection,
                local_ephemeral_public: &EphemeralPublic
        ) -> Result<()>{
                let mut message = Vec::with_capacity(MESSAGE_EPHEMERAL_PUBLIC_SIZE);

                message.push((MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8);
                CodedOutputStream::new(&mut message)
                        .write_bytes(1, local_ephemeral_public.as_bytes())
                        .map_err(Error::ProtoWriteFailed)?;

                connection.write_all(&message)?;

                Ok(())
        }

        #[cfg(test)]
        mod tests{
                use rand_core::OsRng;
                use x25519_dalek::EphemeralSecret;
                use super::*;

                #[test]
                pub fn write_local_ephemeral_public_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());
                        let local_ephemeral_public = EphemeralPublic::from(
                                &EphemeralSecret::random_from_rng(OsRng));

                        let result = write_local_ephemeral_public(
                                &mut connection,
                                &local_ephemeral_public
                        );
                        assert!(result.is_ok());

                        let message_sent = &connection.connection_fake().remote_to_read;
                        assert_eq!(message_sent.len(), MESSAGE_EPHEMERAL_PUBLIC_SIZE);
                        assert_eq!(
                                message_sent[..3],
                                [(MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8, 0x0a, 0x20]
                        );
                        assert_eq!(
                                *local_ephemeral_public.as_bytes(),
                                message_sent[3..MESSAGE_EPHEMERAL_PUBLIC_SIZE]
                        );
                }
        }
}

pub mod read_remote_ephemeral_public {
        use super::*;

        pub fn read_remote_ephemeral_public(connection: &mut Connection) -> Result<EphemeralPublic>{
                let mut message = [0u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE];
                connection.read_exact(&mut message)?;

                parse_message_to_ephemeral_public(&message)
        }

        fn parse_message_to_ephemeral_public(message: &[u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE]) -> Result<EphemeralPublic>{
                let message_size = message[0];

                let is_announced_message_size_correct = message_size as usize == MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1;
                if !is_announced_message_size_correct {
                        return Err(Error::MessageEphemeralPublicBadSize(message.to_vec()));
                }

                let mut remote_ephemeral_public = [0u8;32];
                remote_ephemeral_public.copy_from_slice(
                        message.get(3..MESSAGE_EPHEMERAL_PUBLIC_SIZE)
                                .expect("35 - 3 = 32"));

                Ok(remote_ephemeral_public.into())
        }

        #[cfg(test)]
        mod tests{
                use super::*;

                #[test]
                pub fn read_remote_ephemeral_public_success() {
                        let mut connection = Connection::Fake(ConnectionFake::default());

                        let mut fake_message = [1u8; MESSAGE_EPHEMERAL_PUBLIC_SIZE];
                        fake_message[0] = (MESSAGE_EPHEMERAL_PUBLIC_SIZE - 1) as u8;
                        fake_message[1] = 0x0a;
                        fake_message[2] = 0x20;

                        connection.connection_fake_mut().local_to_read = Vec::from(fake_message);

                        let result = read_remote_ephemeral_public(&mut connection);
                        assert!(result.is_ok());

                        assert_eq!(result.unwrap().as_bytes(), &([1u8; 32]));
                }
        }
}

pub mod make_encryption_keys {
        use super::*;

        pub fn make_encryption_keys(
                is_local_ephemeral_public_smaller_than_remote: bool,
                shared_secret: &SharedSecret
        ) -> Result<Encryption> {
                let chacha_encryption_keys = ChaChaEncryptionKeys::new(
                        shared_secret,
                        is_local_ephemeral_public_smaller_than_remote
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
                           is_local_ephemeral_public_smaller_than_remote: bool
                ) -> Self {
                        let mut hkdf_sha256 = [0u8; 64];
                        Hkdf::<Sha256>::new(
                                None,
                                shared_secret.as_bytes())
                                .expand(b"TENDERMINT_SECRET_CONNECTION_KEY_AND_CHALLENGE_GEN", &mut hkdf_sha256)
                                .expect("64 < x * 255");
                        let (reader,
                                writer): ([u8;32], [u8;32]) = match is_local_ephemeral_public_smaller_than_remote {
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
                signing_key: &SigningKey,
                local_ephemeral_public: &EphemeralPublic,
                remote_ephemeral_public: &EphemeralPublic,
                shared_secret: &SharedSecret,
                connection: &mut Connection,
                encryption: &mut Encryption

        ) -> Result<()> {
                let authentication_code = make_authentication_challenge_code(
                        local_ephemeral_public,
                        remote_ephemeral_public,
                        shared_secret
                );

                let signed_authentication_message = make_signed_authentication_message(
                        signing_key,
                        &authentication_code
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
                local_ephemeral_public: &EphemeralPublic,
                remote_ephemeral_public: &EphemeralPublic,
                shared_secret: &SharedSecret
        ) -> [u8; 32]{
                let is_local_ephemeral_public_smaller_than_remote =
                        local_ephemeral_public.as_bytes() < remote_ephemeral_public.as_bytes();

                let mut transcript = Transcript::new(b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH");

                let (smaller_ephemeral_public,
                        bigger_ephemeral_public) = match is_local_ephemeral_public_smaller_than_remote {
                        true => (local_ephemeral_public, remote_ephemeral_public),
                        false => (remote_ephemeral_public, local_ephemeral_public)
                };

                transcript.append_message(b"EPHEMERAL_LOWER_PUBLIC_KEY", smaller_ephemeral_public.as_bytes());
                transcript.append_message(b"EPHEMERAL_UPPER_PUBLIC_KEY", bigger_ephemeral_public.as_bytes());
                transcript.append_message(b"DH_SECRET", shared_secret.as_bytes());

                let mut message_authentication_code = [0u8; 32];
                transcript.challenge_bytes(b"SECRET_CONNECTION_MAC", &mut message_authentication_code);

                message_authentication_code
        }

        fn make_signed_authentication_message(
                signing_key: &SigningKey,
                authentication_code: &[u8;32],
        ) -> Result<Vec<u8>>{
                let signed_authentication_code = signing_key.sign(authentication_code);

                let mut signed_authentication_message =
                        proto_rust::signed_authentication_message::SignedAuthenticationMessage::new();

                signed_authentication_message.signed_authentication = signed_authentication_code
                        .to_bytes()
                        .to_vec();

                signed_authentication_message.verification_key
                        .mut_or_insert_default()
                        .set_ed25519(
                                signing_key.verification_key().as_bytes().to_vec()
                        );

                signed_authentication_message
                        .write_length_delimited_to_bytes()
                        .map_err(Error::ProtoWriteFailed)
        }

        #[cfg(test)]
        mod tests {
                use rand_core::OsRng;
                use super::*;

                // TODO add tests
                #[test]
                pub fn make_signed_authentication_message_success() {
                        let local_signing = SigningKey::new(OsRng);
                        let authentication_code = [8u8;32];

                        let result = make_signed_authentication_message(
                                &local_signing,
                                &authentication_code
                        );

                        assert!(result.is_ok());
                }
        }
}