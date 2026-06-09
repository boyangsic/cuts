use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use lz4::Decoder;

use crate::{
    crypto::{asset_key, decrypt, index_aad, index_key},
    types::{Asset, AssetFlags, Errors, Header, VERSION},
};

fn stream_len<R: Seek>(reader: &mut R) -> std::io::Result<u64> {
    let cur = reader.stream_position()?;
    let end = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(cur))?;
    Ok(end)
}

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

    if version != VERSION {
        return Err(Errors::InCompatibleVersion(version)); // 빌드마다아마 형식다를껄?...
    }

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
    master: &[u8; 32],
) -> Result<Vec<Asset>, Errors> {
    let mut assets: Vec<Asset> = Vec::new();

    let file_len = stream_len(reader).map_err(|_| Errors::InvalidIndex)?;
    if header.index_start > file_len || header.index_size as u64 > file_len - header.index_start {
        return Err(Errors::InvalidIndex);
    }

    reader
        .seek(SeekFrom::Start(header.index_start))
        .map_err(|_| Errors::InvalidIndex)?;

    let mut encrypted = vec![0u8; header.index_size as usize];
    reader
        .read_exact(&mut encrypted)
        .map_err(|_| Errors::InvalidIndex)?;

    let aad = index_aad(
        header.version,
        header.assets_count,
        &header.salt,
        header.index_start,
    );
    let decrypted = decrypt(&index_key(master), &encrypted, &aad)?;
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
            .read_u64::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let size_expected = cursor
            .read_u64::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        let flags_raw = cursor.read_u8().map_err(|_| Errors::InvalidIndex)?;
        let flags = AssetFlags::from_bits_truncate(flags_raw);

        let chunk_size = cursor
            .read_u64::<LittleEndian>()
            .map_err(|_| Errors::InvalidIndex)?;

        if flags.contains(AssetFlags::STREAMABLE) && chunk_size < 1 {
            return Err(Errors::InvalidIndex);
        }

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
            chunk_size,
            hash,
        });
    }

    return Ok(assets);
}

pub fn read_asset<R: Read + Seek>(
    reader: &mut R,
    asset: &Asset,
    master: &[u8; 32],
) -> Result<Vec<u8>, Errors> {
    let file_len = stream_len(reader).map_err(|_| Errors::InvalidAsset)?;
    if asset.start > file_len || asset.size as u64 > file_len - asset.start {
        return Err(Errors::InvalidAsset);
    }

    reader
        .seek(SeekFrom::Start(asset.start))
        .map_err(|_| Errors::InvalidAsset)?;

    let mut data_raw = vec![0u8; asset.size as usize];
    reader
        .read_exact(&mut data_raw)
        .map_err(|_| Errors::InvalidAsset)?;

    let decrypted = decrypt(
        &asset_key(master, asset.id.as_bytes()),
        &data_raw,
        asset.id.as_bytes(),
    )
    .map_err(|_| Errors::DecryptionFailed)?;

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
    if asset.size_expected as u64 > (1024 * 1024 * 1024) {
        // 한파일당 1GB넘는거 X
        return Err(Errors::DecompressFailed);
    }

    let decoder = Decoder::new(&data_raw[..]).map_err(|_| Errors::DecompressFailed)?;

    let mut limited = decoder.take(asset.size_expected as u64 + 1);

    let mut decompressed = Vec::with_capacity(asset.size_expected as usize);
    limited
        .read_to_end(&mut decompressed)
        .map_err(|_| Errors::DecompressFailed)?;

    if decompressed.len() != asset.size_expected as usize {
        return Err(Errors::DecompressFailed);
    }

    return Ok(decompressed);
}
