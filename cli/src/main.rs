use core::panic;
use std::{
    env,
    fs::{self, File, FileType, create_dir, read_dir},
    io,
    path::Path,
    time::Instant,
};

use cuts_core::{reader, types::Asset, writer};
use rand::Rng;
use walkdir::{DirEntry, WalkDir};

fn pack(path_raw: String, out_name: Option<String>) {
    if !Path::new(&path_raw).is_dir() {
        panic!("folder '{}' not found", path_raw);
    }

    let out_name = out_name.unwrap_or("out".into()) + ".cuts";
    let out = &mut File::create(&out_name).unwrap();

    let dir: Vec<DirEntry> = WalkDir::new(&path_raw)
        .into_iter()
        .filter_map(|file| file.ok())
        .filter(|file| file.file_type().is_file())
        .collect();
    let count = dir.len() as u32;

    let salt = &mut [0u8; 32];
    rand::rng().fill_bytes(salt);
    let key = &mut [0u8; 32];
    rand::rng().fill_bytes(key);

    let mut assets: Vec<Asset> = Vec::new();

    println!("{} files", count);

    writer::write_placeholder(out, cuts_core::types::VERSION, count, *salt)
        .expect("failed to write header");

    dir.iter().for_each(|file| {
        let start = Instant::now();
        let id = file.path().to_str().unwrap();
        println!("processing file '{}'", id);
        let data = fs::read(file.path()).unwrap();
        let asset = writer::write_asset(out, file.path().to_str().unwrap(), &data, true, key)
            .expect(&format!("failed to write asset '{}'", id));
        assets.push(asset);
        println!("processed '{}' in {:?}", id, start.elapsed());
    });

    println!("processing index");
    writer::write_index(out, 0, cuts_core::types::VERSION, &assets, *salt, key)
        .expect("failed to write index");

    println!("wrote file '{}'\nkey >> {}", out_name, hex::encode(key));
}

fn unpack(path_raw: String, out_name: Option<String>) {
    if !Path::new(&path_raw).is_file() {
        panic!("file '{}' not found", path_raw);
    }

    let stdin = io::stdin();
    let mut key_raw = String::new();

    println!("enter key >> ");
    stdin.read_line(&mut key_raw).expect("failed to read key");

    let key_raw = key_raw.trim();
    let key = hex::decode(key_raw).expect("failed to decode key");

    if key.len() != 32 {
        panic!("key must be 32 bytes");
    }

    let key: [u8; 32] = key.try_into().expect("failed to convert key");

    let out_name = out_name.unwrap_or("out".into());
    create_dir(&out_name).expect("failed to create output folder");

    let mut file = File::open(&path_raw).expect("failed to open file");
    let header = reader::read_header(&mut file).expect("failed to read header");
    let assets = reader::read_index(&mut file, &header, &key).expect("failed to read index");
    println!("{} assets", assets.len());

    assets.iter().for_each(|asset| {
        let start = Instant::now();
        println!("processing asset '{}'", asset.id);
        let data = reader::read_asset(&mut file, asset, &key)
            .expect(&format!("failed to read asset '{}'", asset.id));
        let out_path = Path::new(&out_name).join(&asset.id);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).expect("failed to create output folder");
        }
        fs::write(out_path, data).expect("failed to write output file");
        println!("processed '{}' in {:?}", asset.id, start.elapsed());
    });

    println!("unpacked to folder '{}'", out_name);
}

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("cuts [pack|unpack] [path] [out?]");
    let path = args.next().expect("cuts [pack|unpack] [path] [out?]");
    let out = args.next();

    match mode.as_str() {
        "pack" => pack(path, out),
        "unpack" => unpack(path, out),
        _ => {
            panic!("cuts [pack|unpack] [path] [out?]");
        }
    }
}
