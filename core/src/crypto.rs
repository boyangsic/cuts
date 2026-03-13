use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

use crate::types::Errors;

pub fn get_asset_key(id: &[u8], password: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut key = Vec::new();
    key.extend_from_slice(id);
    key.extend_from_slice(password);
    key.extend_from_slice(salt);
    return Sha256::digest(&key).into();
}

pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &[u8]) -> Result<Vec<u8>, Errors> {
    let chacha = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(*nonce));

    let mut cipher = data.to_vec();
    let tag = chacha.encrypt(&mut cipher, None);

    let mut result = Vec::new();
    result.extend_from_slice(nonce);
    result.extend_from_slice(&cipher);
    result.extend_from_slice(&tag);

    return Ok(result);
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Errors> {
    if data.len() < 12 + 16 {
        return Err(Errors::DecryptionFailed);
    }

    let nonce: &[u8; 12] = &data[..12]
        .try_into()
        .map_err(|_| Errors::DecryptionFailed)?;
    let mut cipher = data[12..data.len() - 16].to_vec();
    let tag: &[u8; 16] = &data[data.len() - 16..]
        .try_into()
        .map_err(|_| Errors::DecryptionFailed)?;

    let chacha = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(*nonce));
    chacha
        .decrypt(&mut cipher, *tag, None)
        .map_err(|_| Errors::DecryptionFailed)?;

    return Ok(cipher);
}
