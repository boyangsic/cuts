use std::io::{Seek, SeekFrom, Write};

use byteorder::{LittleEndian, WriteBytesExt};
use lz4::EncoderBuilder;
use rand::Rng;

use crate::{
    crypto::encrypt,
    types::{Asset, AssetFlags, Errors},
};

pub fn write_placeholder<W: Write + Seek>(
    writer: &mut W,
    version: u16,
    assets_count: u32,
    salt: [u8; 32],
) -> Result<(), Errors> {
    writer
        .write_all(b"CUTS")
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u16::<LittleEndian>(version)
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u32::<LittleEndian>(assets_count)
        .map_err(|_| Errors::InvalidHeader)?;
    writer.write_all(&salt).map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u64::<LittleEndian>(0)
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u32::<LittleEndian>(0)
        .map_err(|_| Errors::InvalidHeader)?;
    return Ok(());
}

pub fn write_asset<W: Write + Seek>(
    writer: &mut W,
    id: &str,
    data: &[u8],
    compress: bool,
    key: &[u8; 32],
) -> Result<Asset, Errors> {
    let hash = blake3::hash(data);
    let size_original = data.len() as u32;

    let payload: Vec<u8> = if compress {
        let mut encoder = EncoderBuilder::new()
            .level(4)
            .build(Vec::new())
            .map_err(|_| Errors::InvalidAsset)?;
        std::io::copy(&mut &data[..], &mut encoder).map_err(|_| Errors::InvalidAsset)?;
        let (compressed, result) = encoder.finish();
        result.map_err(|_| Errors::InvalidAsset)?;
        compressed
    } else {
        data.to_vec()
    };

    let mut nonce: [u8; 12] = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    let data = encrypt(key, &nonce, &payload).map_err(|_| Errors::EncryptionFailed)?;

    let start = writer.stream_position().map_err(|_| Errors::InvalidAsset)?;

    writer.write_all(&data).map_err(|_| Errors::InvalidAsset)?;

    let size = data.len() as u32;

    let asset = Asset {
        id_len: id.len() as u16,
        id: id.to_string(),
        start,
        size,
        size_expected: size_original as u32,
        flags: {
            let mut f = AssetFlags::from_bits_truncate(0);
            if compress {
                f |= AssetFlags::COMPRESSED;
            }
            f
        },
        hash: {
            let mut h = [0u8; 32]; // BLAKE3
            h.copy_from_slice(hash.as_bytes());
            h
        },
    };

    return Ok(asset);
}

pub fn write_index<W: Write + Seek>(
    writer: &mut W,
    header_pos: u64,
    version: u16,
    assets: &[Asset],
    salt: [u8; 32],
    key: &[u8; 32],
) -> Result<(), Errors> {
    let index_start = writer
        .stream_position()
        .map_err(|_| Errors::InvalidHeader)?;

    let mut plain = Vec::new();
    for asset in assets {
        plain
            .write_u16::<LittleEndian>(asset.id_len)
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_all(asset.id.as_bytes())
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_u64::<LittleEndian>(asset.start)
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_u32::<LittleEndian>(asset.size)
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_u32::<LittleEndian>(asset.size_expected)
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_u8(asset.flags.bits())
            .map_err(|_| Errors::InvalidIndex)?;
        plain
            .write_all(&asset.hash)
            .map_err(|_| Errors::InvalidIndex)?;
    }

    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let index = encrypt(key, &nonce, &plain).map_err(|_| Errors::EncryptionFailed)?;

    writer.write_all(&index).map_err(|_| Errors::InvalidIndex)?;

    let index_size = index.len() as u32;

    writer
        .seek(SeekFrom::Start(header_pos))
        .map_err(|_| Errors::InvalidHeader)?;

    writer
        .write_all(b"CUTS")
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u16::<LittleEndian>(version)
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u32::<LittleEndian>(assets.len() as u32)
        .map_err(|_| Errors::InvalidHeader)?;
    writer.write_all(&salt).map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u64::<LittleEndian>(index_start)
        .map_err(|_| Errors::InvalidHeader)?;
    writer
        .write_u32::<LittleEndian>(index_size)
        .map_err(|_| Errors::InvalidHeader)?;

    return Ok(());
}
