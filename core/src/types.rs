use bitflags::bitflags;

pub const VERSION: u16 = 2;
pub const MAX_DECOMPRESSED: u64 = 1024 * 1024 * 1024; // 1gb넘는건 필요가업슴...
#[derive(Debug)]

pub struct Header {
    pub magic: [u8; 4],
    pub version: u16,

    pub assets_count: u32,

    pub salt: [u8; 32],

    pub index_start: u64,
    pub index_size: u32,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub id_len: u16,
    pub id: String, // "stuff/stuff2/stuff3.png"

    pub start: u64, // [nonce12B][encdata][tag16B]
    pub size: u64,  // 이미 암호화된거(nonce포함)

    pub size_expected: u64, // << 미리 할당전용으로 저장해놔야함

    pub flags: AssetFlags,

    pub hash: [u8; 32], // BLAKE3
}

bitflags! {
    #[derive(Debug, Clone)]
    pub struct AssetFlags: u8 {
        const COMPRESSED = 1 << 0;
    }
}

#[derive(Debug)]

pub enum Errors {
    InvalidFileType,
    InvalidHeader,
    InCompatibleVersion(u16), // [V1 / V2 (거의다뜯어고쳣농)],
    InvalidIndex,
    InvalidAsset,
    DecompressFailed,
    EncryptionFailed,
    DecryptionFailed,
    AssetHashMismatch,
}
