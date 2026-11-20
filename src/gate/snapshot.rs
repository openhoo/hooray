//! Copy and hash the same bounded stream from a single open regular file.
//! Subsequent parsing only sees the copies in a process-private temporary directory.
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use crate::config::Config;

const MAX_POLICY: u64 = 16 * 1024 * 1024;

fn copy_digest(path: &Path, maximum: u64, mut sink: impl Write) -> Result<String> {
    // open_regular_nofollow checks the final component atomically on Unix.
    // On Windows explicitly decline reparse points using the opened handle.
    #[cfg(not(windows))]
    let mut reader = crate::input::open_regular_nofollow(path)?;
    #[cfg(windows)]
    let mut reader = {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let file = File::options()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
            "gate input must be a regular file: {}",
            path.display()
        );
        file
    };
    ensure!(
        reader.metadata()?.len() <= maximum,
        "gate input exceeds {maximum} bytes: {}",
        path.display()
    );
    let mut sha = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0; 16 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("gate input length overflow")?;
        ensure!(
            count <= maximum,
            "gate input exceeds {maximum} bytes: {}",
            path.display()
        );
        sha.update(&buf[..n]);
        sink.write_all(&buf[..n])?;
    }
    Ok(crate::util::hex_lower(&sha.finalize()))
}

fn policy_extension(policy: &Path) -> Result<&'static str> {
    match policy
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("yaml" | "yml") => Ok("yaml"),
        Some("toml") => Ok("toml"),
        _ => bail!("gate policy must use YAML or TOML"),
    }
}

pub(super) struct Snapshots {
    _dir: tempfile::TempDir,
    pub artifact: PathBuf,
    pub policy: PathBuf,
    pub artifact_sha256: String,
    pub policy_sha256: String,
}

impl Snapshots {
    pub fn new(artifact: &Path, policy: &Path, maximum: u64) -> Result<Self> {
        let extension = policy_extension(policy)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix("hooray-gate-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let dir = builder.tempdir()?;
        let a = dir.path().join("artifact.zip");
        let p = dir.path().join(format!("policy.{extension}"));
        let artifact_sha256 = copy_digest(artifact, maximum, File::create_new(&a)?)?;
        let policy_sha256 = copy_digest(policy, MAX_POLICY, File::create_new(&p)?)?;
        Ok(Self {
            _dir: dir,
            artifact: a,
            policy: p,
            artifact_sha256,
            policy_sha256,
        })
    }
}

pub(super) fn digests(artifact: &Path, policy: &Path) -> Result<(String, String)> {
    policy_extension(policy)?;
    Ok((
        copy_digest(artifact, Config::default().max_input_bytes, io::sink())?,
        copy_digest(policy, MAX_POLICY, io::sink())?,
    ))
}
