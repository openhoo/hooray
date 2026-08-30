use std::path::Path;

pub(crate) fn repository_walk(
    root: &Path,
    follow_links: bool,
    max_depth: Option<usize>,
) -> ignore::Walk {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .add_custom_ignore_filename(".hoorayignore")
        .follow_links(follow_links)
        .git_global(false)
        .hidden(false)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp);
    builder.max_depth(max_depth);
    builder.build()
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

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
}
