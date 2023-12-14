use super::hash::sha256;
use crate::proto::public_key::KeyData;
use bytes::{BufMut, Bytes, BytesMut};
use enum_dispatch::enum_dispatch;

#[enum_dispatch]
pub trait ECPublicKey {
    fn curve_name(&self) -> &'static str;
    fn encode(&self) -> Bytes;
}

pub trait DsaPublicKey {
    fn verify<Msg, Sig>(&self, message: Msg, signature: Sig) -> Result<(), String>
    where
        Msg: AsRef<[u8]>,
        Sig: AsRef<[u8]>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[enum_dispatch(ECPublicKey)]
pub enum ECPublicKeyAny {
    Secp256k1(Secp256k1PublicKey),
}

impl ECPublicKeyAny {
    pub fn from_key_data(key_data: &KeyData) -> Result<Self, String> {
        let curve_name: &str = match key_data {
            KeyData::EcKeyData(k) => &k.curve,
            KeyData::CompressedEcKeyData(k) => &k.curve,
        };

        match curve_name {
            "secp256k1" => Ok(Self::Secp256k1(Secp256k1PublicKey::from_key_data(
                key_data,
            )?)),
            _ => Err(format!("Unsupported curve: {}", curve_name)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secp256k1PublicKey(secp256k1::PublicKey);

impl Secp256k1PublicKey {
    pub fn from_key_data(key_data: &KeyData) -> Result<Self, String> {
        let mut data: BytesMut;
        match key_data {
            KeyData::EcKeyData(key_data) => {
                data = BytesMut::with_capacity(65);
                data.put_u8(0x04);
                data.put(key_data.x.as_ref());
                data.put(key_data.y.as_ref());
            }
            KeyData::CompressedEcKeyData(key_data) => {
                data = BytesMut::with_capacity(33);
                data.put(key_data.data.as_ref());
            }
        }
        let pk = secp256k1::PublicKey::from_slice(&data).map_err(|e| e.to_string())?;
        Ok(Self(pk))
    }

    pub fn random() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (_, pk) = secp.generate_keypair(&mut rand::thread_rng());
        Self(pk)
    }
}

impl ECPublicKey for Secp256k1PublicKey {
    fn curve_name(&self) -> &'static str {
        "secp256k1"
    }

    fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(self.0.serialize().as_slice())
    }
}

impl DsaPublicKey for Secp256k1PublicKey {
    fn verify<Msg, Sig>(&self, message: Msg, signature: Sig) -> Result<(), String>
    where
        Msg: AsRef<[u8]>,
        Sig: AsRef<[u8]>,
    {
        let secp = secp256k1::Secp256k1::verification_only();
        let msg = secp256k1::Message::from_slice(sha256(message).as_bytes())
            .map_err(|e| e.to_string())?;
        let sig =
            secp256k1::ecdsa::Signature::from_der(signature.as_ref()).map_err(|e| e.to_string())?;

        secp.verify_ecdsa(&msg, &sig, &self.0)
            .map_err(|e| e.to_string())
    }
}
