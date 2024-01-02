mod setup;
mod connection;
mod encryption;

use std::{thread};
use rand_core::OsRng;
use x25519_dalek::{
        EphemeralSecret as EphemeralSecret,
        PublicKey as EphemeralPublic,
};
use crate::config::Config;
use crate::result::{Result};
use crate::peer::{
        connection::*,
        encryption::Encryption,
        setup::{
                read_remote_ephemeral_public::read_remote_ephemeral_public,
                write_local_ephemeral_public::write_local_ephemeral_public,
                make_encryption_keys::make_encryption_keys,
                read_write_authentication::read_write_authentication
        }
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerAction {
        Authenticate,
        Listen
}

pub struct Peer {
        pub config: Config,
        pub connection: Connection,
        pub action: PeerAction,
        pub encryption: Option<Encryption>,
}

impl Peer {
        pub fn try_new_tcp(config: &Config, ip: [u8; 4], port: u16) -> Result<Self>{
                Ok(Peer {
                        config: config.clone(),
                        connection: Connection::Tcp(ConnectionTcp::try_new(ip, port)?),
                        action: PeerAction::Authenticate,
                        encryption: None
                })
        }

        pub fn run(mut self) -> Result<()> {
                thread::spawn(move || -> Result<()> {
                        loop {
                                let result = match self.action {
                                        PeerAction::Authenticate => self.authenticate(),
                                        PeerAction::Listen => {Ok(())}
                                };

                                if let Err(e) = result{
                                        println!("Error: {:?}", e);
                                        return Err(e);
                                }
                        }

                        Ok(())
                });

                Ok(())
        }

        fn authenticate(&mut self) -> Result<()>{
                let local_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
                let local_ephemeral_public = EphemeralPublic::from(&local_ephemeral_secret);

                write_local_ephemeral_public(
                        &mut self.connection,
                        &local_ephemeral_public
                )?;

                let remote_ephemeral_public = read_remote_ephemeral_public(
                        &mut self.connection)?;

                let shared_secret = local_ephemeral_secret
                        .diffie_hellman(&remote_ephemeral_public);

                self.encryption = Some(make_encryption_keys(
                        local_ephemeral_public.as_bytes() < remote_ephemeral_public.as_bytes(),
                        &shared_secret
                )?);

                read_write_authentication(
                        &self.config.signing_key,
                        &local_ephemeral_public,
                        &remote_ephemeral_public,
                        &shared_secret,
                        &mut self.connection,
                        self.encryption
                                .as_mut()
                                .expect("already set")
                )?;

                self.action = PeerAction::Listen;

                Ok(())
        }
}

impl Default for Peer {
        fn default() -> Self {
                Peer {
                        config: Config::default(),
                        connection: Connection::Fake(ConnectionFake::default()),
                        action: PeerAction::Authenticate,
                        encryption: Default::default(),
                }
        }
}