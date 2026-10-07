use hooray::{config::Config, input::scan_path};

#[test]
fn jsonc_comments_cannot_join_distinct_json_tokens() {
    for value in [
        "1/* separator */2",
        "tr/* separator */ue",
        "nu/* separator */ll",
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bun.lock"),
            format!(r#"{{"packages":{{}},"lockfileVersion":{value}}}"#),
        )
        .unwrap();
        assert!(
            scan_path(dir.path(), &Config::default()).is_err(),
            "accepted malformed JSONC: {value}"
        );
    }
}

#[test]
fn jsonc_unterminated_comments_fail_closed() {
    for value in [r#"{"packages":{}}/*"#, r#"{"packages":{}}/* unfinished"#] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bun.lock"), value).unwrap();
        assert!(
            scan_path(dir.path(), &Config::default()).is_err(),
            "accepted an unterminated comment"
        );
    }
}

#[test]
fn jsonc_comments_and_trailing_commas_keep_valid_dependency_inventory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("bun.lock"),
        r#"{
        // A normal line comment.
        "packages": {
            "left-pad": ["left-pad@1.3.0", /* normal block comment */],
        },
    } // A final line comment is valid."#,
    )
    .unwrap();
    let inventory = scan_path(dir.path(), &Config::default()).unwrap();
    assert_eq!(inventory.components.len(), 1);
    let component = inventory.components.values().next().unwrap();
    assert_eq!(component.purl, "pkg:npm/left-pad@1.3.0");
    assert_eq!(component.version, "1.3.0");
}
