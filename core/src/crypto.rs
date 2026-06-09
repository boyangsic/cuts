use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use crate::types::Errors;

pub fn get_master_key(password: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Errors> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| Errors::EncryptionFailed)?;

    return Ok(key);
}

fn subkey(master: &[u8; 32], domain: u8, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut material = Vec::with_capacity(1 + info.len());
    material.push(domain);
    material.extend_from_slice(info);
    Zeroizing::new(*blake3::keyed_hash(master, &material).as_bytes())
}

pub fn asset_key(master: &[u8; 32], id: &[u8]) -> Zeroizing<[u8; 32]> {
    subkey(master, 1, id)
}

pub fn index_key(master: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    subkey(master, 0, &[])
}

pub fn index_aad(version: u16, assets_count: u32, salt: &[u8; 32], index_start: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 2 + 4 + 32 + 8);
    aad.extend_from_slice(b"CUTS");
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&assets_count.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&index_start.to_le_bytes());
    return aad;
}

pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    data: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Errors> {
    let chacha = ChaCha20Poly1305::new(Key::from_slice(key));

    // [nonce][encdata][tag]
    let cipher = chacha
        .encrypt(Nonce::from_slice(nonce), Payload { msg: data, aad })
        .map_err(|_| Errors::EncryptionFailed)?;

    let mut result = Vec::with_capacity(nonce.len() + cipher.len());
    result.extend_from_slice(nonce);
    result.extend_from_slice(&cipher);

    return Ok(result);
}

pub fn decrypt(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Errors> {
    if data.len() < 12 + 16 {
        return Err(Errors::DecryptionFailed);
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let cipher = &data[12..]; // encdata || tag

    let chacha = ChaCha20Poly1305::new(Key::from_slice(key));
    let plain = chacha
        .decrypt(nonce, Payload { msg: cipher, aad })
        .map_err(|_| Errors::DecryptionFailed)?;

    return Ok(plain);
}
