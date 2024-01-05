mod authenticate;
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
        authenticate::*
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeerAction {
        Authenticate,
        Listen
}

pub struct Peer {
        pub id: String,
        pub address: Option<[u8; 20]>,
        pub config: Config,
        pub connection: Connection,
        pub action: PeerAction,
        pub encryption: Option<Encryption>,
}

impl Peer {
        pub fn try_new_tcp(config: &Config, ip: [u8; 4], port: u16, address: Option<[u8; 20]>) -> Result<Self>{
                Ok(Peer {
                        id: format!("{}.{}.{}.{}:{}",ip[0], ip[1], ip[2], ip[3], port),
                        address,
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
                println!("Try to authenticate peer({})...", self.id);
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

                let authentication_challenge_code = make_authentication_challenge_code(
                        &local_ephemeral_public,
                        &remote_ephemeral_public,
                        &shared_secret
                );

                read_write_authentication(
                        &self.address,
                        &self.config.signing_key,
                        &authentication_challenge_code,
                        &mut self.connection,
                        self.encryption
                                .as_mut()
                                .expect("already set")
                )?;

                self.action = PeerAction::Listen;

                println!("Authentication for peer({}) done.", self.id);
                Ok(())
        }
}

impl Default for Peer {
        fn default() -> Self {
                Peer {
                        id: "fake".into(),
                        address: None,
                        config: Config::default(),
                        connection: Connection::Fake(ConnectionFake::default()),
                        action: PeerAction::Authenticate,
                        encryption: Default::default(),
                }
        }
}