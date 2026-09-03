use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub(crate) const IGNORE_CONTROL_NAMES: &[&str] = &[".gitignore", ".ignore", ".hoorayignore"];
/// Maximum bytes admitted from one ignore-control file.
pub(crate) const MAX_IGNORE_CONTROL_FILE_BYTES: usize = 1024 * 1024;
/// Maximum bytes admitted from all ignore-control files in one walk.
pub(crate) const MAX_IGNORE_CONTROL_TOTAL_BYTES: usize = 8 * 1024 * 1024;
/// Maximum active (non-empty, non-comment) patterns in one ignore-control file.
pub(crate) const MAX_IGNORE_CONTROL_FILE_PATTERNS: usize = 16 * 1024;
/// Maximum active patterns in all ignore-control files in one walk.
pub(crate) const MAX_IGNORE_CONTROL_TOTAL_PATTERNS: usize = 128 * 1024;

#[derive(Debug, Clone)]
struct IgnoreViolation {
    path: PathBuf,
    message: String,
}

#[derive(Debug, Default)]
struct IgnoreBudget {
    bytes: usize,
    patterns: usize,
    violation: Option<IgnoreViolation>,
}

type SharedIgnoreBudget = Arc<Mutex<IgnoreBudget>>;

pub(crate) struct RepositoryWalk {
    inner: ignore::Walk,
    budget: SharedIgnoreBudget,
    finished: bool,
}

pub(crate) fn repository_walk(
    root: &Path,
    follow_links: bool,
    max_depth: Option<usize>,
) -> RepositoryWalk {
    let budget = Arc::new(Mutex::new(IgnoreBudget::default()));
    if root.is_dir() {
        inspect_ancestor_ignore_controls(root, &budget);
    }
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .add_custom_ignore_filename(".hoorayignore")
        .follow_links(follow_links)
        .git_global(false)
        .git_exclude(false)
        .hidden(false)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp);
    builder.max_depth(max_depth);
    let filter_budget = Arc::clone(&budget);
    builder.filter_entry(move |entry| {
        if entry.depth() > 0
            && max_depth.is_none_or(|limit| entry.depth() < limit)
            && entry.file_type().is_some_and(|kind| kind.is_dir())
        {
            inspect_ignore_controls(entry.path(), &filter_budget);
        }
        !has_ignore_violation(&filter_budget)
    });
    RepositoryWalk {
        inner: builder.build(),
        budget,
        finished: false,
    }
}

fn inspect_ancestor_ignore_controls(root: &Path, budget: &SharedIgnoreBudget) {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
    let mut directories = Vec::new();
    let mut directory = root;
    loop {
        directories.push(directory.clone());
        let Some(parent) = directory.parent() else {
            break;
        };
        if parent == directory {
            break;
        }
        directory = parent.to_owned();
    }
    for directory in directories.into_iter().rev() {
        inspect_ignore_controls(&directory, budget);
        if has_ignore_violation(budget) {
            break;
        }
    }
}

impl Iterator for RepositoryWalk {
    type Item = Result<ignore::DirEntry, ignore::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(error) = take_ignore_violation(&self.budget) {
            self.finished = true;
            return Some(Err(error));
        }
        match self.inner.next() {
            Some(item) => {
                if let Some(error) = take_ignore_violation(&self.budget) {
                    self.finished = true;
                    Some(Err(error))
                } else {
                    Some(item)
                }
            }
            None => {
                self.finished = true;
                take_ignore_violation(&self.budget).map(Err)
            }
        }
    }
}

fn inspect_ignore_controls(directory: &Path, budget: &SharedIgnoreBudget) {
    for name in IGNORE_CONTROL_NAMES {
        let path = directory.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                record_ignore_violation(
                    budget,
                    path,
                    format!("could not inspect ignore-control file: {error}"),
                );
                return;
            }
        };
        if !metadata.file_type().is_file() {
            record_ignore_violation(
                budget,
                path,
                "ignore-control path is not a regular file".to_owned(),
            );
            return;
        }
        let bytes = match read_ignore_control(&path) {
            Ok(bytes) => bytes,
            Err(message) => {
                record_ignore_violation(budget, path, message);
                return;
            }
        };
        let patterns = match active_ignore_patterns(&bytes) {
            Ok(patterns) => patterns,
            Err(message) => {
                record_ignore_violation(budget, path, message);
                return;
            }
        };
        let mut state = budget.lock().expect("ignore budget mutex is not poisoned");
        if state.violation.is_some() {
            return;
        }
        let total_bytes = state.bytes.saturating_add(bytes.len());
        if total_bytes > MAX_IGNORE_CONTROL_TOTAL_BYTES {
            state.violation = Some(IgnoreViolation {
                path: path.clone(),
                message: format!(
                    "ignore-control bytes exceed cumulative limit of {} bytes",
                    MAX_IGNORE_CONTROL_TOTAL_BYTES
                ),
            });
            return;
        }
        let total_patterns = state.patterns.saturating_add(patterns);
        if total_patterns > MAX_IGNORE_CONTROL_TOTAL_PATTERNS {
            state.violation = Some(IgnoreViolation {
                path: path.clone(),
                message: format!(
                    "ignore-control patterns exceed cumulative limit of {}",
                    MAX_IGNORE_CONTROL_TOTAL_PATTERNS
                ),
            });
            return;
        }
        state.bytes = total_bytes;
        state.patterns = total_patterns;
    }
}

fn read_ignore_control(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let file =
        File::open(path).map_err(|error| format!("could not read ignore-control file: {error}"))?;
    file.take(MAX_IGNORE_CONTROL_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read ignore-control file: {error}"))?;
    if bytes.len() > MAX_IGNORE_CONTROL_FILE_BYTES {
        return Err(format!(
            "ignore-control file exceeds per-file limit of {} bytes",
            MAX_IGNORE_CONTROL_FILE_BYTES
        ));
    }
    Ok(bytes)
}

fn active_ignore_patterns(bytes: &[u8]) -> Result<usize, String> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("ignore-control file is not valid UTF-8: {error}"))?;
    let mut patterns = 0_usize;
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let line = if line.ends_with("\\ ") {
            line
        } else {
            line.trim_end()
        };
        if !line.is_empty() {
            patterns = patterns.saturating_add(1);
            if patterns > MAX_IGNORE_CONTROL_FILE_PATTERNS {
                return Err(format!(
                    "ignore-control file exceeds per-file pattern limit of {}",
                    MAX_IGNORE_CONTROL_FILE_PATTERNS
                ));
            }
        }
    }
    Ok(patterns)
}

fn record_ignore_violation(budget: &SharedIgnoreBudget, path: PathBuf, message: String) {
    let mut state = budget.lock().expect("ignore budget mutex is not poisoned");
    if state.violation.is_none() {
        state.violation = Some(IgnoreViolation { path, message });
    }
}

fn has_ignore_violation(budget: &SharedIgnoreBudget) -> bool {
    budget
        .lock()
        .expect("ignore budget mutex is not poisoned")
        .violation
        .is_some()
}

fn take_ignore_violation(budget: &SharedIgnoreBudget) -> Option<ignore::Error> {
    let violation = budget
        .lock()
        .expect("ignore budget mutex is not poisoned")
        .violation
        .take()?;
    Some(ignore::Error::WithPath {
        path: violation.path,
        err: Box::new(ignore::Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            violation.message,
        ))),
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, io};

    use tempfile::tempdir;

    use super::repository_walk;

    #[test]
    fn repository_walk_honors_project_ignores_but_keeps_hidden_sources() {
        let directory = tempdir().unwrap();
        fs::create_dir(directory.path().join("ignored")).unwrap();
        fs::create_dir(directory.path().join("fixtures")).unwrap();
        fs::create_dir(directory.path().join(".github")).unwrap();
        fs::write(directory.path().join(".gitignore"), "ignored/\n").unwrap();
        fs::write(directory.path().join(".hoorayignore"), "fixtures/\n").unwrap();
        fs::write(directory.path().join("ignored/secret.py"), "ignored").unwrap();
        fs::write(directory.path().join("fixtures/bad.py"), "ignored").unwrap();
        fs::write(directory.path().join(".github/workflow.yml"), "visible").unwrap();
        fs::write(directory.path().join("main.py"), "visible").unwrap();

        let files: BTreeSet<_> = repository_walk(directory.path(), false, None)
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(directory.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert!(files.contains(".github/workflow.yml"));
        assert!(files.contains("main.py"));
        assert!(!files.contains("ignored/secret.py"));
        assert!(!files.contains("fixtures/bad.py"));
    }

    #[test]
    fn inherited_ignore_controls_keep_semantics_and_enforce_limits() {
        let directory = tempdir().unwrap();
        let root = directory.path().join("project");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("ignored")).unwrap();
        fs::write(
            directory.path().join(".gitignore"),
            format!("{}/ignored/\n", root.file_name().unwrap().to_string_lossy()),
        )
        .unwrap();
        fs::write(root.join("visible.txt"), "visible").unwrap();
        fs::write(root.join("ignored/secret.txt"), "ignored").unwrap();

        let files: BTreeSet<_> = repository_walk(&root, false, None)
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
            .map(|entry| entry.path().strip_prefix(&root).unwrap().to_owned())
            .collect();
        assert!(files.contains(std::path::Path::new("visible.txt")));
        assert!(!files.contains(std::path::Path::new("ignored/secret.txt")));

        let oversized = directory.path().join(".ignore");
        fs::write(
            &oversized,
            vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1],
        )
        .unwrap();
        let error = repository_walk(&root, false, None)
            .find_map(Result::err)
            .expect("oversized inherited control must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(".ignore"));

        fs::write(
            &oversized,
            " #pattern\n".repeat(super::MAX_IGNORE_CONTROL_FILE_PATTERNS + 1),
        )
        .unwrap();
        let error = repository_walk(&root, false, None)
            .find_map(Result::err)
            .expect("pattern-heavy inherited control must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("per-file pattern limit"));
    }

    #[cfg(unix)]
    #[test]
    fn inherited_ignore_control_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let root = directory.path().join("project");
        fs::create_dir(&root).unwrap();
        let target = directory.path().join("ignore-target");
        fs::write(&target, "ignored/\n").unwrap();
        symlink(&target, directory.path().join(".gitignore")).unwrap();

        let error = repository_walk(&root, false, None)
            .find_map(Result::err)
            .expect("inherited ignore-control symlink must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(".gitignore"));
    }
    #[test]
    fn ignore_control_file_byte_limits_are_fail_closed() {
        for name in super::IGNORE_CONTROL_NAMES {
            let directory = tempdir().unwrap();
            let exact = directory.path().join(name);
            fs::write(&exact, vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES]).unwrap();
            assert!(repository_walk(directory.path(), false, None).all(|item| item.is_ok()));

            fs::write(&exact, vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1]).unwrap();
            let error = repository_walk(directory.path(), false, None)
                .find_map(Result::err)
                .expect("oversized root control must yield an error");
            assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(name));

            let nested = directory.path().join("nested");
            fs::create_dir(&nested).unwrap();
            fs::remove_file(&exact).unwrap();
            fs::write(
                nested.join(name),
                vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1],
            )
            .unwrap();
            let error = repository_walk(directory.path(), false, None)
                .find_map(Result::err)
                .expect("oversized nested control must yield an error");
            assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(&format!("nested/{name}")));
        }
    }

    #[test]
    fn ignore_control_pattern_limits_are_fail_closed() {
        let directory = tempdir().unwrap();
        let content = " #pattern\n".repeat(super::MAX_IGNORE_CONTROL_FILE_PATTERNS + 1);
        fs::write(directory.path().join(".gitignore"), content).unwrap();
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("per-file pattern overflow must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("per-file pattern limit"));
    }
    #[test]
    fn ignore_control_pattern_count_accepts_bom_blank_and_comments() {
        let bytes = b"\xef\xbb\xbf# comment\n\n visible/\n# another\n #leading\n";
        assert_eq!(super::active_ignore_patterns(bytes).unwrap(), 2);
    }

    #[test]
    fn ignore_control_aggregate_byte_limit_is_fail_closed() {
        let directory = tempdir().unwrap();
        let content = vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES];
        for index in 0..3 {
            let nested = directory.path().join(format!("nested-{index}"));
            fs::create_dir(&nested).unwrap();
            for name in super::IGNORE_CONTROL_NAMES {
                fs::write(nested.join(name), &content).unwrap();
            }
        }
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("aggregate ignore-control byte overflow must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cumulative limit"));
    }

    #[test]
    fn ignore_control_aggregate_pattern_limit_is_fail_closed() {
        let directory = tempdir().unwrap();
        let content = " #pattern\n".repeat(super::MAX_IGNORE_CONTROL_FILE_PATTERNS);
        for index in 0..3 {
            let nested = directory.path().join(format!("nested-{index}"));
            fs::create_dir(&nested).unwrap();
            for name in super::IGNORE_CONTROL_NAMES {
                fs::write(nested.join(name), &content).unwrap();
            }
        }
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("aggregate ignore-control pattern overflow must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cumulative limit"));
    }

    #[test]
    fn git_info_exclude_is_disabled_before_bounded_ignore_inspection() {
        let directory = tempdir().unwrap();
        let info = directory.path().join(".git/info");
        fs::create_dir_all(&info).unwrap();
        fs::write(
            info.join("exclude"),
            vec![b'#'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(
            repository_walk(directory.path(), false, None).all(|item| item.is_ok()),
            "disabled Git excludes must not bypass or trigger Hooray's bounded controls"
        );
    }

    #[test]
    fn ignore_controls_beyond_max_depth_are_not_admitted() {
        let directory = tempdir().unwrap();
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            nested.join(".gitignore"),
            vec![b'x'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(repository_walk(directory.path(), false, Some(0)).all(|item| item.is_ok()));
        assert!(repository_walk(directory.path(), false, Some(1)).all(|item| item.is_ok()));
    }

    #[cfg(unix)]
    #[test]
    fn ignore_control_symlinks_and_special_files_fail_closed() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };

        let directory = tempdir().unwrap();
        let target = directory.path().join("oversized");
        fs::write(
            &target,
            vec![b'x'; super::MAX_IGNORE_CONTROL_FILE_BYTES + 1],
        )
        .unwrap();
        let symlinked = directory.path().join(".gitignore");
        symlink(&target, &symlinked).unwrap();
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("ignore-control symlink must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(".gitignore"));

        fs::remove_file(&symlinked).unwrap();
        let fifo = directory.path().join(".gitignore");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o644) }, 0);
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("special ignore-control file must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(".gitignore"));
    }

    #[test]
    fn ignore_control_invalid_utf8_is_fail_closed() {
        let directory = tempdir().unwrap();
        fs::write(directory.path().join(".ignore"), [0xff_u8, 0xfe_u8]).unwrap();
        let error = repository_walk(directory.path(), false, None)
            .find_map(Result::err)
            .expect("invalid UTF-8 control must yield an error");
        assert_eq!(error.io_error().unwrap().kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn ignore_control_read_failure_is_reported_by_bounded_reader() {
        let directory = tempdir().unwrap();
        let control = directory.path().join(".gitignore");
        fs::create_dir(&control).unwrap();
        let error = super::read_ignore_control(&control).unwrap_err();
        assert!(error.contains("could not read ignore-control file"));
    }
}
