use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Cursor, Read};
use std::path::{Component as PathComponent, Path, PathBuf};

use crate::config::Config;
use crate::input::{InputError, malformed_msg, normalize_relative, read_limited};

/// Opens an archive file for reading without following a final-component
/// symlink and rejecting non-regular files, mirroring the input layer's
/// `open_regular_nofollow` (kept local so the parsers surface stays
/// self-contained).
fn open_regular_nofollow(path: &Path) -> Result<File, InputError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW: i32 = 0x20_000;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW: i32 = 0x100;
        options.custom_flags(O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| {
        if is_symlink_open_error(&source) {
            InputError::Symlink(path.to_owned())
        } else {
            InputError::Io {
                path: path.to_owned(),
                source,
            }
        }
    })?;
    let metadata = file.metadata().map_err(|source| InputError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(InputError::UnsupportedPath(path.to_owned()));
    }
    Ok(file)
}

/// `ELOOP` per target: Linux/Android use 40, Darwin and the BSDs use 62.
/// Raw errno matching is required because `io::ErrorKind::FilesystemLoop`
/// is not available on the pinned toolchain; a single hardcoded 40 would
/// misclassify symlink rejections on every non-Linux unix target.
#[cfg(any(target_os = "linux", target_os = "android"))]
const ELOOP: i32 = 40;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const ELOOP: i32 = 62;

#[cfg(unix)]
fn is_symlink_open_error(source: &io::Error) -> bool {
    source.raw_os_error() == Some(ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_: &io::Error) -> bool {
    false
}

/// Marker error `BoundedReader` raises so archive readers can report an
/// over-budget stream as `ArchiveTooLarge` rather than a bare I/O error.
#[derive(Debug)]
struct ArchiveBoundExceeded;

impl std::fmt::Display for ArchiveBoundExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("archive stream exceeded decompressed byte bound")
    }
}

impl std::error::Error for ArchiveBoundExceeded {}

/// Byte-counting `Read` wrapper that errors once the wrapped stream yields
/// more than `maximum` bytes. Wrap decompressed archive streams so skipped
/// entries (whose declared sizes tar-rs drains through the reader) count
/// against the same budget as extracted ones.
struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            remaining: maximum,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other(ArchiveBoundExceeded));
        }
        let limit = (self.remaining.min(buf.len() as u64)) as usize;
        let read = self.inner.read(&mut buf[..limit])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Maps an archive-stream I/O error: a `BoundedReader` bound violation
/// becomes `ArchiveTooLarge`, anything else stays an `Io` error.
fn archive_stream_error(source: io::Error, path: PathBuf, config: &Config) -> InputError {
    if source
        .get_ref()
        .is_some_and(|e| e.is::<ArchiveBoundExceeded>())
    {
        InputError::ArchiveTooLarge {
            actual: config.max_archive_bytes.saturating_add(1),
            maximum: config.max_archive_bytes,
        }
    } else {
        InputError::Io { path, source }
    }
}

pub(crate) fn read_zip_file(
    path: &Path,
    config: &Config,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    read_zip(open_regular_nofollow(path)?, config)
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
        decompress_archive(Cursor::new(read_limited(path, config.max_archive_bytes)?))?,
        config,
    )
}

fn read_tar<R: Read>(reader: R, config: &Config) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    let mut expanded = 0;
    read_tar_with_expanded(reader, config, &mut expanded)
}

/// Wraps an archive byte stream in the decompressor its leading magic bytes
/// declare (gzip `1f 8b`, zstd `28 b5 2f fd`); anything else passes through
/// as a plain tar. The peeked prefix is chained back so no input bytes are
/// lost, and decompressed bytes still count against `max_archive_bytes`
/// inside the tar reader.
pub(crate) fn decompress_archive<'a, R: Read + 'a>(
    mut reader: R,
) -> Result<Box<dyn Read + 'a>, InputError> {
    const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
    let mut prefix = Vec::with_capacity(ZSTD_MAGIC.len());
    reader
        .by_ref()
        .take(ZSTD_MAGIC.len() as u64)
        .read_to_end(&mut prefix)
        .map_err(|source| InputError::Io {
            path: PathBuf::from("<archive>"),
            source,
        })?;
    let gzip = prefix.starts_with(&GZIP_MAGIC);
    let zstd = prefix.starts_with(&ZSTD_MAGIC);
    let stream = Cursor::new(prefix).chain(reader);
    if gzip {
        Ok(Box::new(flate2::read::MultiGzDecoder::new(stream)))
    } else if zstd {
        zstd::stream::read::Decoder::new(stream)
            .map(|decoder| Box::new(decoder) as Box<dyn Read>)
            .map_err(|source| InputError::Io {
                path: PathBuf::from("<archive>"),
                source,
            })
    } else {
        Ok(Box::new(stream))
    }
}

/// Normalizes a tar entry path for the traversal and link checks. Entries
/// whose path is only `.` segments (`./`, `.`, `./.`) name the archive root
/// itself — GNU tar emits `./` for every `tar -cf out.tar -C dir .` — and
/// carry no addressable content, so they yield `None` and are skipped like
/// other non-file entries. Genuine traversal (`../x`) still fails closed in
/// `normalize_relative`.
pub(crate) fn tar_entry_path<R: Read>(
    entry: &tar::Entry<'_, R>,
) -> Result<Option<String>, InputError> {
    let path = entry.path().map_err(|source| InputError::Io {
        path: PathBuf::from("<tar>"),
        source,
    })?;
    if path
        .components()
        .all(|component| matches!(component, PathComponent::CurDir))
    {
        return Ok(None);
    }
    normalize_relative(&path).map(Some)
}

pub(crate) fn read_tar_with_expanded<R: Read>(
    reader: R,
    config: &Config,
    expanded: &mut u64,
) -> Result<BTreeMap<String, Vec<u8>>, InputError> {
    // Bound the decompressed stream, not just extracted bytes: tar-rs drains
    // skipped entries through the reader, so a crafted archive whose
    // directory entries declare huge sizes would otherwise decompress
    // unboundedly.
    let mut archive = tar::Archive::new(BoundedReader::new(reader, config.max_archive_bytes));
    let mut files = BTreeMap::new();
    let mut count = 0_usize;
    let entries = archive
        .entries()
        .map_err(|source| archive_stream_error(source, PathBuf::from("<tar>"), config))?;
    for entry in entries {
        count += 1;
        if count > config.max_archive_entries {
            return Err(InputError::TooManyArchiveEntries {
                maximum: config.max_archive_entries,
            });
        }
        let mut entry =
            entry.map_err(|source| archive_stream_error(source, PathBuf::from("<tar>"), config))?;
        let Some(path) = tar_entry_path(&entry)? else {
            continue;
        };
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
        .map_err(|source| archive_stream_error(source, PathBuf::from(path), config))?;
    if bytes.len() as u64 != expected {
        return Err(malformed_msg(path, format, "entry size mismatch"));
    }
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
    fn skips_curdir_root_entries_and_still_rejects_traversal() {
        // `tar -cf out.tar -C dir .` emits a `./` root directory entry and
        // `./`-prefixed members; both must scan like the unprefixed tar (#67).
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, "./", io::empty()).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(6);
            header.set_cksum();
            builder
                .append_data(&mut header, "./requirements.txt", &b"a==1\n\n"[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let files = read_tar(Cursor::new(bytes), &config()).unwrap();
        assert_eq!(files.keys().collect::<Vec<_>>(), ["requirements.txt"]);
        // A genuine traversal entry still fails closed; the tar builder
        // rejects `..` in set_path, so the name is written into the raw
        // GNU header field instead.
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.as_gnu_mut().unwrap().name[..7].copy_from_slice(b"../evil");
            header.set_size(1);
            header.set_cksum();
            builder.append(&header, &b"x"[..]).unwrap();
            builder.finish().unwrap();
        }
        assert!(matches!(
            read_tar(Cursor::new(bytes), &config()),
            Err(InputError::PathTraversal(_))
        ));
    }
    #[test]
    fn reads_gzip_and_zstd_compressed_tars_within_bounds() {
        let tar = tar_bytes(&[("requirements.txt", b"a==1\n")]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        let gzipped = encoder.finish().unwrap();
        let zstded = zstd::stream::encode_all(&tar[..], 3).unwrap();
        for compressed in [gzipped, zstded] {
            let files = read_tar(
                decompress_archive(Cursor::new(compressed)).unwrap(),
                &config(),
            )
            .unwrap();
            assert_eq!(files.keys().collect::<Vec<_>>(), ["requirements.txt"]);
        }

        // A gzip bomb fails closed against the expanded-size bound.
        let fat_tar = tar_bytes(&[("big.bin", &[0u8; 4096])]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&fat_tar).unwrap();
        let bomb = encoder.finish().unwrap();
        let mut tiny = config();
        tiny.max_archive_bytes = 8;
        assert!(matches!(
            read_tar(decompress_archive(Cursor::new(bomb)).unwrap(), &tiny),
            Err(InputError::ArchiveTooLarge { .. })
        ));
    }
    #[test]
    fn scan_path_accepts_compressed_tar_suffixes() {
        let dir = tempdir().unwrap();
        let tar = tar_bytes(&[("requirements.txt", b"safe==1\n")]);
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).unwrap();
        let gzipped = encoder.finish().unwrap();
        for name in ["project.tar.gz", "project.tgz"] {
            let path = dir.path().join(name);
            fs::write(&path, &gzipped).unwrap();
            let inventory = scan_path(&path, &config()).unwrap();
            assert!(inventory.components.values().any(|c| c.name == "safe"));
        }
        let path = dir.path().join("project.tar.zst");
        fs::write(&path, zstd::stream::encode_all(&tar[..], 3).unwrap()).unwrap();
        let inventory = scan_path(&path, &config()).unwrap();
        assert!(inventory.components.values().any(|c| c.name == "safe"));
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

    #[cfg(unix)]
    #[test]
    fn read_zip_file_rejects_symlinked_archive() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.zip");
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("a", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        fs::write(&real, writer.finish().unwrap().into_inner()).unwrap();
        let link = dir.path().join("link.zip");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            read_zip_file(&link, &config()),
            Err(InputError::Symlink(_))
        ));
    }

    #[test]
    fn tar_stream_bound_counts_skipped_entry_bytes() {
        // A tar whose only file entry is skipped (a directory entry
        // carrying a large declared size) still drains those bytes through
        // the reader: the decompressed stream bound must trip even though
        // no file content is ever extracted.
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(4096);
            header.set_cksum();
            builder
                .append_data(&mut header, "dir/", vec![b'x'; 4096].as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut small = config();
        small.max_archive_bytes = 8;
        assert!(matches!(
            read_tar(Cursor::new(bytes), &small),
            Err(InputError::ArchiveTooLarge { .. })
        ));
    }

    #[test]
    fn read_tar_file_caps_input_at_archive_bound() {
        // The on-disk tar is capped by `max_archive_bytes`, not the smaller
        // `max_input_bytes` ceiling used for single lockfiles.
        let dir = tempdir().unwrap();
        let tar_path = dir.path().join("big.tar");
        write_tar(&tar_path, &[("requirements.txt", b"safe==1\n")]);
        let mut limits = config();
        limits.max_input_bytes = 1;
        limits.max_archive_bytes = 1 << 20;
        assert!(read_tar_file(&tar_path, &limits).is_ok());
        limits.max_archive_bytes = 1;
        assert!(matches!(
            read_tar_file(&tar_path, &limits),
            Err(InputError::InputTooLarge { maximum: 1, .. })
        ));
    }
}
