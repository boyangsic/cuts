use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use lz4::Decoder;

use crate::{
    crypto::decrypt,
    types::{Asset, AssetFlags, Errors, Header},
};

pub fn read_header<R: Read + Seek>(reader: &mut R) -> Result<Header, Errors> {
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| Errors::InvalidHeader)?;

    if magic != *b"CUTS" {
        return Err(Errors::InvalidFileType);
    }

    let version = reader
        .read_u16::<LittleEndian>()
        .map_err(|_| Errors::InvalidHeader)?;

    let assets_count = reader
        .read_u32::<LittleEndian>()
        .map_err(|_| Errors::InvalidHeader)?;

    let mut salt = [0u8; 32];
    reader
        .read_exact(&mut salt)
        .map_err(|_| Errors::InvalidHeader)?;

    let index_start = reader
        .read_u64::<LittleEndian>()
        .map_err(|_| Errors::InvalidHeader)?;

    let index_size = match reader.read_u32::<LittleEndian>() {
        Ok(size) => size,
        Err(_) => return Err(Errors::InvalidHeader),
    };

    return Ok(Header {
        magic,
        version,
        assets_count,
        salt,
        index_start,
        index_size,
    });
}

pub fn read_index<R: Read + Seek>(
    reader: &mut R,
    header: &Header,
    key: &[u8; 32],
) -> Result<Vec<Asset>, Errors> {
    let mut assets: Vec<Asset> = Vec::new();

    reader
        .seek(SeekFrom::Start(header.index_start))
        .map_err(|_| Errors::InvalidIndex)?;

    let mut encrypted = vec![0u8; header.index_size as usize];
    reader
        .read_exact(&mut encrypted)
        .map_err(|_| Errors::InvalidIndex)?;

    let decrypted = decrypt(key, &encrypted)?;
    let decrypted_len = decrypted.len() as u64;
    let mut cursor = Cursor::new(decrypted);

    for _ in 0..header.assets_count {
        let pos = cursor.stream_position().map_err(|_| Errors::InvalidIndex)?;
        if pos >= decrypted_len {
            return Err(Errors::InvalidIndex);
        }

        let id_len = cursor
            .read_u16::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let mut id_buf = vec![0u8; id_len as usize];
        cursor
            .read_exact(&mut id_buf)
            .map_err(|_| Errors::InvalidIndex)?;

        let id = String::from_utf8(id_buf).map_err(|_| Errors::InvalidIndex)?;

        let start = cursor
            .read_u64::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let size = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let size_expected = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let flags_raw = cursor.read_u8().map_err(|_| Errors::InvalidIndex)?;
        let flags = AssetFlags::from_bits_truncate(flags_raw);

        let mut hash = [0u8; 32];
        cursor
            .read_exact(&mut hash)
            .map_err(|_| Errors::InvalidIndex)?;

        assets.push(Asset {
            id_len,
            id,
            start,
            size,
            size_expected,
            flags,
            hash,
        });
    }

    return Ok(assets);
}

pub fn read_asset<R: Read + Seek>(
    reader: &mut R,
    asset: &Asset,
    key: &[u8; 32],
) -> Result<Vec<u8>, Errors> {
    reader
        .seek(SeekFrom::Start(asset.start))
        .map_err(|_| Errors::InvalidAsset)?;

    let mut data_raw = vec![0u8; asset.size as usize];
    reader
        .read_exact(&mut data_raw)
        .map_err(|_| Errors::InvalidAsset)?;

    let decrypted = decrypt(key, &data_raw).map_err(|_| Errors::DecryptionFailed)?;

    let data = if asset.flags.contains(AssetFlags::COMPRESSED) {
        decompress(decrypted, asset).map_err(|_| Errors::DecompressFailed)?
    } else {
        decrypted
    };

    let hash = blake3::hash(&data);
    if hash.as_bytes() != &asset.hash {
        return Err(Errors::AssetHashMismatch);
    }

    return Ok(data);
}

fn decompress(data_raw: Vec<u8>, asset: &Asset) -> Result<Vec<u8>, Errors> {
    let mut decoder = Decoder::new(&data_raw[..]).map_err(|_| Errors::DecompressFailed)?;

    let mut decompressed = Vec::with_capacity(asset.size_expected as usize);

    decoder
        .read_to_end(&mut decompressed)
        .map_err(|_| Errors::DecompressFailed)?;
    if decompressed.len() != asset.size_expected as usize {
        return Err(Errors::DecompressFailed);
    }

    return Ok(decompressed);
}
