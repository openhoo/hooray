use serde_yaml::Value;

const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");

#[test]
fn manual_publication_is_limited_to_main_except_dry_run() {
    let workflow: Value = serde_yaml::from_str(RELEASE_WORKFLOW).expect("release workflow YAML");
    let condition = workflow["jobs"]["prepare"]["if"]
        .as_str()
        .expect("prepare job publication guard");

    assert_eq!(
        condition,
        "github.event_name != 'workflow_dispatch' || inputs.dry_run || github.ref_name == 'main'"
    );
}
