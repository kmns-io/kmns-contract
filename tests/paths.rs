use kmns_contract::{PathError, ResourcePath, TargetAccountPaths};
use std::path::{Path, PathBuf};

fn target(home: Option<&str>, xdg: Option<&str>) -> TargetAccountPaths {
    TargetAccountPaths::new(home.map(PathBuf::from), xdg.map(PathBuf::from))
}

fn xdg_path(relative: &str) -> ResourcePath {
    serde_json::from_value(serde_json::json!({
        "base": "xdg_config_home", "relative": relative
    }))
    .unwrap()
}

#[test]
fn target_account_context_controls_xdg_resolution() {
    let path = xdg_path("kmns/validate/config.yaml");
    for invalid_override in [None, Some(""), Some("relative/config")] {
        assert_eq!(
            path.resolve(&target(Some("/home/test-user"), invalid_override))
                .unwrap(),
            Path::new("/home/test-user/.config/kmns/validate/config.yaml")
        );
    }
    assert_eq!(
        path.resolve(&target(None, Some("/srv/test-service/config")))
            .unwrap(),
        Path::new("/srv/test-service/config/kmns/validate/config.yaml")
    );
    assert_eq!(
        path.resolve(&target(Some("/home/another"), None)).unwrap(),
        Path::new("/home/another/.config/kmns/validate/config.yaml")
    );
}

#[test]
fn missing_absolute_account_context_fails_without_environment_fallback() {
    for home in [None, Some(""), Some("relative/home")] {
        assert_eq!(
            xdg_path("kmns/config.yaml").resolve(&target(home, None)),
            Err(PathError::MissingAccountContext)
        );
    }
}

#[test]
fn relative_targets_cannot_escape_the_selected_base() {
    for relative in [
        "",
        "/etc/shadow",
        "../private",
        "dir/../../private",
        "dir/../file",
        "a\u{0}b",
    ] {
        assert!(xdg_path(relative)
            .resolve(&target(Some("/home/test-user"), None))
            .is_err());
    }
}

#[test]
fn unknown_bases_and_extra_identity_fields_are_rejected() {
    for value in [
        serde_json::json!({"base": "home", "relative": "config.yaml"}),
        serde_json::json!({"base": "xdg_config_home", "relative": "config.yaml", "user": "root"}),
    ] {
        assert!(serde_json::from_value::<ResourcePath>(value).is_err());
    }
}

#[test]
fn literal_paths_are_not_shell_expanded() {
    let context = target(Some("/home/test-user"), None);
    for literal in ["~/.config/kmns.yaml", "$HOME/config.yaml", "relative.yaml"] {
        let path: ResourcePath = serde_json::from_value(serde_json::json!(literal)).unwrap();
        assert_eq!(path.resolve(&context).unwrap(), Path::new(literal));
    }
    let path: ResourcePath =
        serde_json::from_value(serde_json::json!("/etc/kmns/config.yaml")).unwrap();
    assert_eq!(
        path.resolve(&context).unwrap(),
        Path::new("/etc/kmns/config.yaml")
    );
}
