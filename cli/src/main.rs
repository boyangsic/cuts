use core::panic;
use std::{
    env,
    fs::{self, File, create_dir},
    path::{Component, Path, PathBuf},
    time::Instant,
};

use cuts_core::{crypto::get_master_key, reader, types::Asset, writer};
use rand::Rng;
use walkdir::{DirEntry, WalkDir};
use zeroize::Zeroizing;

fn safe_join(base: &Path, id: &str) -> Option<PathBuf> {
    if id.is_empty() || id.contains('\0') || id.contains('\\') {
        return None;
    }
    let mut path = base.to_path_buf();
    for comp in Path::new(id).components() {
        match comp {
            Component::Normal(c) => path.push(c),
            _ => return None,
        }
    }
    Some(path)
}

fn pack(path_raw: String, out_name: Option<String>) {
    if !Path::new(&path_raw).is_dir() {
        panic!("folder '{}' not found", path_raw);
    }

    let out_name = out_name.unwrap_or("out".into()) + ".cuts";

    let dir: Vec<DirEntry> = WalkDir::new(&path_raw)
        .into_iter()
        .filter_map(|file| file.ok())
        .filter(|file| file.file_type().is_file())
        .collect();
    let count = dir.len() as u32;

    let salt = &mut [0u8; 32];
    rand::rng().fill_bytes(salt);

    let password = Zeroizing::new(
        rpassword::prompt_password("set password >> ").expect("failed to read password"),
    );
    let confirm = Zeroizing::new(
        rpassword::prompt_password("confirm password >> ").expect("failed to read password"),
    );
    if *password != *confirm {
        panic!("passwords do not match");
    }
    if password.is_empty() {
        panic!("password must not be empty");
    }

    let master = get_master_key(password.as_bytes(), salt).expect("failed to derive key");

    let out = &mut File::create(&out_name).unwrap();

    let mut assets: Vec<Asset> = Vec::new();

    println!("{} files", count);

    writer::write_placeholder(out, cuts_core::types::VERSION, count, *salt)
        .expect("failed to write header");

    dir.iter().for_each(|file| {
        let start = Instant::now();
        let id = file.path().to_str().unwrap();
        println!("processing file '{}'", id);
        let data = fs::read(file.path()).unwrap();
        let asset = writer::write_asset(
            out,
            file.path().to_str().unwrap(),
            &data,
            true,
            false,
            None,
            &master,
        )
        .expect(&format!("failed to write asset '{}'", id));
        assets.push(asset);
        println!("processed '{}' in {:?}", id, start.elapsed());
    });

    println!("processing index");
    writer::write_index(out, 0, cuts_core::types::VERSION, &assets, *salt, &master)
        .expect("failed to write index");

    println!("wrote file '{}'", out_name);
}

fn unpack(path_raw: String, out_name: Option<String>) {
    if !Path::new(&path_raw).is_file() {
        panic!("file '{}' not found", path_raw);
    }

    let mut file = File::open(&path_raw).expect("failed to open file");
    let header = reader::read_header(&mut file).expect("failed to read header");

    let password = Zeroizing::new(
        rpassword::prompt_password("enter password >> ").expect("failed to read password"),
    );
    let master = get_master_key(password.as_bytes(), &header.salt).expect("failed to derive key");

    let assets = reader::read_index(&mut file, &header, &master)
        .expect("failed to read index!! (wrong password?)");
    println!("{} assets", assets.len());

    let out_name = out_name.unwrap_or("out".into());
    create_dir(&out_name).expect("failed to create output folder");

    assets.iter().for_each(|asset| {
        let start = Instant::now();
        println!("processing asset '{}'", asset.id);
        let data = reader::read_asset(&mut file, asset, &master)
            .expect(&format!("failed to read asset '{}'", asset.id));
        let out_path = match safe_join(Path::new(&out_name), &asset.id) {
            Some(p) => p,
            None => panic!("unsafe asset id '{}'", asset.id),
        };
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
