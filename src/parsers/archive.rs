use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::input::{InputError, malformed_msg, normalize_relative, read_limited};

pub(crate) fn read_zip_file(
    path: &Path,
    config: &Config,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    read_zip(
        File::open(path).map_err(|source| InputError::Io {
            path: path.to_owned(),
            source,
        })?,
        config,
    )
}

fn read_zip<R: Read + io::Seek>(
    reader: R,
    config: &Config,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut archive = zip::ZipArchive::new(reader)?;
    if archive.len() > config.max_archive_entries {
        return Err(InputError::TooManyArchiveEntries {
            maximum: config.max_archive_entries,
        });
    }
    let mut files = BTreeMap::new();
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let path = entry
            .enclosed_name()
            .ok_or_else(|| InputError::PathTraversal(entry.name().to_owned()))?;
        let path = normalize_relative(&path)?;
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(InputError::ArchiveLink(path));
        }
        if !entry.is_file() {
            continue;
        }
        let expected = entry.size();
        let bytes = read_entry_bounded(&mut entry, expected, &path, "ZIP", config, &mut expanded)?;
        files.insert(path, bytes);
    }
    Ok(files)
}

pub(crate) fn read_tar_file(
    path: &Path,
    config: &Config,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    read_tar(
        Cursor::new(read_limited(path, config.max_input_bytes)?),
        config,
    )
}

fn read_tar<R: Read>(reader: R, config: &Config) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut expanded = 0;
    read_tar_with_expanded(reader, config, &mut expanded)
}

pub(crate) fn read_tar_with_expanded<R: Read>(
    reader: R,
    config: &Config,
    expanded: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut archive = tar::Archive::new(reader);
    let mut files = BTreeMap::new();
    let mut count = 0_usize;
    let entries = archive.entries().map_err(|source| InputError::Io {
        path: PathBuf::from("<tar>"),
        source,
    })?;
    for entry in entries {
        count += 1;
        if count > config.max_archive_entries {
            return Err(InputError::TooManyArchiveEntries {
                maximum: config.max_archive_entries,
            });
        }
        let mut entry = entry.map_err(|source| InputError::Io {
            path: PathBuf::from("<tar>"),
            source,
        })?;
        let path = normalize_relative(&entry.path().map_err(|source| InputError::Io {
            path: PathBuf::from("<tar>"),
            source,
        })?)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(InputError::ArchiveLink(path));
        }
        if !entry_type.is_file() {
            continue;
        }
        let expected = entry.size();
        let bytes = read_entry_bounded(&mut entry, expected, &path, "TAR", config, expanded)?;
        files.insert(path, bytes);
    }
    Ok(files)
}

pub(crate) fn add_archive_size(
    current: u64,
    entry: u64,
    config: &Config,
) -> Result<u64, InputError> {
    let actual = current.saturating_add(entry);
    if actual > config.max_archive_bytes {
        Err(InputError::ArchiveTooLarge {
            actual,
            maximum: config.max_archive_bytes,
        })
    } else {
        Ok(actual)
    }
}

/// Shared bounded-entry pipeline for archive readers: size accounting against
/// `max_archive_bytes`, a read capped one byte past the declared entry size,
/// and the truncated/oversized-entry check. ZIP and TAR readers must stay in
/// lockstep here.
pub(crate) fn read_entry_bounded(
    reader: &mut impl Read,
    expected: u64,
    path: &str,
    format: &'static str,
    config: &Config,
    expanded: &mut u64,
) -> Result<Vec<u8>, InputError> {
    *expanded = add_archive_size(*expanded, expected, config)?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(expected.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| InputError::Io {
            path: PathBuf::from(path),
            source,
        })?;
    if bytes.len() as u64 != expected {
        return Err(malformed_msg(path, format, "entry size mismatch"));
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use crate::input::{config, scan_path, tar_bytes, write_tar};
    use crate::model::AssetKind;
    use tempfile::tempdir;
    #[test]
    fn scans_zip_and_rejects_traversal() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("requirements.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"a==1\n").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert_eq!(read_zip(Cursor::new(bytes), &config()).unwrap().len(), 1);
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(matches!(
            read_zip(Cursor::new(bytes), &config()),
            Err(InputError::PathTraversal(_))
        ));
    }
    #[test]
    fn rejects_tar_links_and_expansion_limit() {
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            header.set_link_name("target").unwrap();
            builder
                .append_data(&mut header, "link", io::empty())
                .unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            read_tar(Cursor::new(bytes), &config()),
            Err(InputError::ArchiveLink(_))
        ));
        let mut small = config();
        small.max_archive_bytes = 2;
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_size(3);
            header.set_cksum();
            builder
                .append_data(&mut header, "requirements.txt", &b"abc"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            read_tar(Cursor::new(bytes), &small),
            Err(InputError::ArchiveTooLarge { .. })
        ));
    }
    #[test]
    fn scans_tar_file_end_to_end_and_rejects_empty_archive() {
        let dir = tempdir().unwrap();
        let tar_path = dir.path().join("project.tar");
        write_tar(&tar_path, &[("nested/requirements.txt", b"safe==1\n")]);
        let inventory = scan_path(&tar_path, &config()).unwrap();
        assert_eq!(inventory.asset.kind, AssetKind::Filesystem);
        assert!(inventory.components.values().any(|c| c.name == "safe"));

        let empty_path = dir.path().join("empty.tar");
        write_tar(&empty_path, &[]);
        assert!(matches!(
            scan_path(&empty_path, &config()),
            Err(InputError::UnsupportedFormat(_))
        ));
    }
    #[test]
    fn zip_enforces_entry_count_size_links_and_ignores_directories() {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .add_directory("dir/", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file("dir/a", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"a").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut one_entry = config();
        one_entry.max_archive_entries = 1;
        assert!(matches!(
            read_zip(Cursor::new(bytes.clone()), &one_entry),
            Err(InputError::TooManyArchiveEntries { maximum: 1 })
        ));
        assert_eq!(read_zip(Cursor::new(bytes), &config()).unwrap().len(), 1);

        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("large", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"ab").unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        let mut one_byte = config();
        one_byte.max_archive_bytes = 1;
        assert!(matches!(
            read_zip(Cursor::new(bytes), &one_byte),
            Err(InputError::ArchiveTooLarge {
                actual: 2,
                maximum: 1
            })
        ));

        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .add_symlink("link", "target", zip::write::SimpleFileOptions::default())
            .unwrap();
        let bytes = writer.finish().unwrap().into_inner();
        assert!(matches!(
            read_zip(Cursor::new(bytes), &config()),
            Err(InputError::ArchiveLink(path)) if path == "link"
        ));
    }
    #[test]
    fn archive_zero_limits_reject_nonempty_inputs_at_the_boundary() {
        let tar = tar_bytes(&[("a", b"x")]);
        let mut zero_entries = config();
        zero_entries.max_archive_entries = 0;
        assert!(matches!(
            read_tar(Cursor::new(tar.clone()), &zero_entries),
            Err(InputError::TooManyArchiveEntries { maximum: 0 })
        ));
        let mut zero_bytes = config();
        zero_bytes.max_archive_bytes = 0;
        assert!(matches!(
            read_tar(Cursor::new(tar), &zero_bytes),
            Err(InputError::ArchiveTooLarge {
                actual: 1,
                maximum: 0
            })
        ));
        assert_eq!(
            add_archive_size(u64::MAX, 1, &config())
                .unwrap_err()
                .to_string(),
            format!(
                "archive expanded size {} exceeds maximum {} bytes",
                u64::MAX,
                config().max_archive_bytes
            )
        );
    }
}
