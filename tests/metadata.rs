use kmns_contract::{CheckMetadata, ContractMetadata, MetadataLimits, Severity};

const CONTRACT: &str = r#"
name: Example validation
description: Verify configuration and seal state.
version: "0.1.0"
language: en
owner: kmns
component: example
pillar: P5-SEC
tags: [security, secrets]
references:
  - id: REF-SEC-002
    title: Example specification
    uri: https://example.com/docs/security.md
"#;

const CHECK: &str = r#"
name: Seal state
description: Verify the declared seal state.
severity: high
rationale: The state must match the deployment stage.
remediation:
  summary: Review the operational runbook.
  reference_ids: [REF-SEC-002]
tags: [seal-state]
"#;

fn limits() -> MetadataLimits {
    // Test fixture limits, not production policy defaults.
    MetadataLimits {
        max_string_bytes: 1024,
        max_list_items: 16,
        max_total_bytes: 8192,
    }
}

#[test]
fn authored_metadata_survives_serialization_for_later_pool_extraction() {
    let contract: ContractMetadata = serde_yaml::from_str(CONTRACT).unwrap();
    let check: CheckMetadata = serde_yaml::from_str(CHECK).unwrap();
    contract.validate(&limits()).unwrap();
    check.validate(&contract, &limits()).unwrap();
    assert_eq!(check.severity, Severity::High);
    let json = serde_json::to_value(&check).unwrap();
    assert_eq!(json["name"], "Seal state");
    assert_eq!(json["remediation"]["reference_ids"][0], "REF-SEC-002");
    assert_eq!(
        serde_json::from_value::<CheckMetadata>(json).unwrap(),
        check
    );
    let json = serde_json::to_value(&contract).unwrap();
    assert_eq!(
        serde_json::from_value::<ContractMetadata>(json).unwrap(),
        contract
    );
}

#[test]
fn unknown_fields_and_legacy_display_aliases_are_rejected() {
    for extra in ["title: legacy", "command: echo unsafe", "unexpected: true"] {
        assert!(serde_yaml::from_str::<ContractMetadata>(&format!("{CONTRACT}\n{extra}")).is_err());
        assert!(serde_yaml::from_str::<CheckMetadata>(&format!("{CHECK}\n{extra}")).is_err());
    }
    assert!(
        serde_yaml::from_str::<ContractMetadata>(&CONTRACT.replace("name:", "title:")).is_err()
    );
}

#[test]
fn required_names_descriptions_and_severity_are_validated() {
    let contract: ContractMetadata = serde_yaml::from_str(CONTRACT).unwrap();
    for field in ["name", "description"] {
        let mut check =
            serde_json::to_value(serde_yaml::from_str::<CheckMetadata>(CHECK).unwrap()).unwrap();
        check[field] = serde_json::json!("   ");
        assert!(serde_json::from_value::<CheckMetadata>(check)
            .unwrap()
            .validate(&contract, &limits())
            .is_err());
    }
    assert!(serde_yaml::from_str::<CheckMetadata>(&CHECK.replace("high", "urgent")).is_err());
}

#[test]
fn references_must_resolve_without_collisions() {
    let contract: ContractMetadata = serde_yaml::from_str(CONTRACT).unwrap();
    let mut check: CheckMetadata = serde_yaml::from_str(CHECK).unwrap();
    check.references = contract.references.clone();
    assert!(check.validate(&contract, &limits()).is_err());
    check.references.clear();
    let mut missing = contract.clone();
    missing.references.clear();
    assert!(check.validate(&missing, &limits()).is_err());
    let mut duplicate = contract.clone();
    duplicate.references.extend(contract.references.clone());
    assert!(duplicate.validate(&limits()).is_err());
}

#[test]
fn bounds_and_unsafe_display_values_are_rejected() {
    let contract: ContractMetadata = serde_yaml::from_str(CONTRACT).unwrap();
    for small in [
        MetadataLimits {
            max_string_bytes: 8,
            ..limits()
        },
        MetadataLimits {
            max_list_items: 0,
            ..limits()
        },
        MetadataLimits {
            max_total_bytes: 1,
            ..limits()
        },
    ] {
        assert!(contract.validate(&small).is_err());
    }
    let mut invalid = contract.clone();
    invalid.name = "hidden\u{001b}[2J".into();
    assert!(invalid.validate(&limits()).is_err());
    for uri in [
        "file:///etc/passwd",
        "http://example.com",
        "/docs/../secret",
        "//example.com",
    ] {
        invalid = contract.clone();
        invalid.references[0].uri = uri.into();
        assert!(invalid.validate(&limits()).is_err());
    }
}
