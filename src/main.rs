use nom::bytes::complete::{take_till, take_until};
use nom::character::is_hex_digit;
use nom::IResult;
use pbr::{ProgressBar, Units};
use std::fs::File;
use std::io::prelude::*;
use tar::Archive;
use std::env;

const BUFFER_SIZE: usize = 8192;

#[derive(Debug)]
enum ChecksumType {
    SHA1,
    None,
}

// #[derive(Debug)]
// struct OvaFile {
// manifest: Manifest,
// }

#[derive(Debug)]
struct Manifest {
    name: String,
    contents: Vec<ManifestItem>,
}

#[derive(Debug)]
struct ManifestItem {
    name: String,
    checksum_type: ChecksumType,
    checksum: String,
}

fn main() -> std::io::Result<()> {
    let args = env::args().collect::<Vec<String>>();
    let filename = &args[1];
    let file = File::open(filename)?;
    let mut a = Archive::new(file);

    let mut manifest = Manifest {
        name: String::new(),
        contents: Vec::new(),
    };
    for file in a.entries()? {
        let mut file = file?;

        let path = file
            .header()
            .path()?
            .into_owned()
            .as_path()
            .to_str()
            .unwrap()
            .to_string();
        if path.ends_with(".mf") {
            manifest.name = path;
            let mut manifest_contents = String::new();
            file.read_to_string(&mut manifest_contents)?;
            let lines = manifest_contents
                .as_str()
                .lines()
                .map(|x| x.to_string())
                .collect::<Vec<String>>();
            for line in lines {
                let x: IResult<&str, &str> = take_until("(")(line.as_str());
                let (remainder, hash_type) = x.unwrap();
                let x: IResult<&str, &str> = take_until(")")(remainder.trim_start_matches('('));
                let (remainder, file_name) = x.unwrap();
                let x: IResult<&[u8], &[u8]> = take_till(is_hex_digit)(remainder.as_bytes());
                let checksum = String::from_utf8_lossy(x.unwrap().0);

                let checksum_type = if hash_type == "SHA1" {
                    ChecksumType::SHA1
                } else {
                    ChecksumType::None
                };

                manifest.contents.push(ManifestItem {
                    name: file_name.to_string(),
                    checksum_type,
                    checksum: checksum.to_string(),
                });
            }
        }
    }
    let file = File::open(filename)?;

    let mut a = Archive::new(file);

    for entry in a.entries()? {
        let mut entry = entry?;
        for item in &manifest.contents {
            if item.name
                == entry
                    .header()
                    .path()?
                    .into_owned()
                    .as_path()
                    .to_str()
                    .unwrap()
            {
                let n_bytes = entry.header().size()?;
                println!("{}", item.name);
                let mut pb = ProgressBar::new(n_bytes);
                pb.set_units(Units::Bytes);
                let mut m = sha1::Sha1::new();

                let mut buf = vec![0u8; BUFFER_SIZE];
                while let Ok(amount_read) = entry.read(&mut buf) {
                    if amount_read == 0 { break; }
                    m.update(&buf[..amount_read]);
                    pb.add(amount_read as u64);
                }

                if item.checksum == m.hexdigest() {
                    println!("PASSED {:?} {}", item.checksum_type, m.hexdigest());
                } else {
                    println!("FAILED {:?} {}", item.checksum_type, m.hexdigest());
                }
            }
        }
    }
    Ok(())
}
