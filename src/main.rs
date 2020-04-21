use crypto::digest::Digest;
use crypto::sha1::Sha1;
use nom::bytes::complete::{take_until, take_while};
use nom::character::is_hex_digit;
use nom::IResult;
use pbr::{ProgressBar, Units};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use tar::Archive;

const BUFFER_SIZE: usize = 8192;

#[derive(Debug, PartialEq)]
enum ChecksumType {
    SHA1,
    None,
}

#[derive(Debug)]
struct Manifest {
    name: String,
    contents: Vec<ManifestItem>,
}

#[derive(Debug, PartialEq)]
struct ManifestItem {
    name: String,
    checksum_type: ChecksumType,
    checksum: String,
}

fn parse_mf(mf_contents: String) -> Vec<ManifestItem> {
    let mut items = vec![];
    let lines = mf_contents
        .as_str()
        .lines()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    for line in lines {
        let x: IResult<&str, &str> = take_until("(")(&line);
        let (remainder, hash_type) = x.unwrap();
        let remainder: String = remainder.trim_start_matches('(').chars().rev().collect();
        let x: IResult<&[u8], &[u8]> = take_while(is_hex_digit)(remainder.as_bytes());
        let (remainder, checksum_rev) = x.unwrap();
        let checksum =
            String::from_utf8(checksum_rev.iter().clone().rev().copied().collect()).unwrap();
        let x: IResult<&[u8], &[u8]> = take_until(")")(remainder);
        let file_name: String = String::from_utf8_lossy(x.unwrap().0)
            .trim_start_matches(')')
            .chars()
            .rev()
            .collect();

        let checksum_type = if hash_type == "SHA1" {
            ChecksumType::SHA1
        } else {
            ChecksumType::None
        };

        items.push(ManifestItem {
            name: file_name.to_string(),
            checksum_type,
            checksum: checksum.to_string(),
        });
    }
    items
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
            manifest.contents = parse_mf(manifest_contents);
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
                let mut m = Sha1::new();

                let mut buf = vec![0u8; BUFFER_SIZE];
                while let Ok(amount_read) = entry.read(&mut buf) {
                    if amount_read == 0 {
                        break;
                    }
                    m.input(&buf[..amount_read]);
                    pb.add(amount_read as u64);
                }

                let digest = m.result_str();

                if item.checksum == digest {
                    println!("PASSED {:?} {}", item.checksum_type, digest);
                } else {
                    println!("FAILED {:?} {}", item.checksum_type, digest);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_mf() {
        let got = parse_mf("SHA1(filename.ext)= 7302647992be1de77d6fc6a6b6395c87c4325ead\nSHA1(filename-(2).ext)= 8fcb142e98dc83b470291fe0820629fe1e1f05b1\n".to_string());
        let expected: Vec<ManifestItem> = vec![
            ManifestItem {
                name: "filename.ext".to_string(),
                checksum_type: ChecksumType::SHA1,
                checksum: "7302647992be1de77d6fc6a6b6395c87c4325ead".to_string(),
            },
            ManifestItem {
                name: "filename-(2).ext".to_string(),
                checksum_type: ChecksumType::SHA1,
                checksum: "8fcb142e98dc83b470291fe0820629fe1e1f05b1".to_string(),
            },
        ];
        assert_eq!(got, expected);
    }
}
