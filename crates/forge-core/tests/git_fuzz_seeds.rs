use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use forge_core::{GitObjectFormat, parse_status_porcelain_v2};

fn checked_in_seed_paths() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let corpus =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/parse_status_porcelain_v2");
    let mut seeds = Vec::new();
    for entry in fs::read_dir(&corpus)? {
        let path = entry?.path();
        if path.is_file() && path.extension() == Some(OsStr::new("seed")) {
            seeds.push(path);
        }
    }
    seeds.sort();
    Ok(seeds)
}

#[test]
fn checked_in_corpus_never_panics_parser_in_either_object_format()
-> Result<(), Box<dyn std::error::Error>> {
    let seeds = checked_in_seed_paths()?;
    assert!(
        seeds.len() >= 4,
        "expected the initial external porcelain-v2 seed corpus"
    );

    for seed in seeds {
        let input = fs::read(&seed)?;
        let _ = parse_status_porcelain_v2(&input, GitObjectFormat::Sha1);
        let _ = parse_status_porcelain_v2(&input, GitObjectFormat::Sha256);
    }
    Ok(())
}
