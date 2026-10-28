use kmns_contract::{
    CompiledContract, Contract, ContractError, ContractErrorCode, ContractLimits, ContractResolver,
    MetadataLimits, NativeResourceKind, ResolvedContract, MAX_CHECK_ID_BYTES,
    MAX_CONTRACT_ID_BYTES,
};
use std::collections::HashMap;

fn limits() -> ContractLimits {
    ContractLimits {
        max_artifact_bytes: 16_384,
        max_graph_bytes: 65_536,
        max_checks: 8,
        max_graph_checks: 16,
        max_contract_depth: 4,
        max_yaml_depth: 16,
        metadata: MetadataLimits {
            max_string_bytes: 1024,
            max_list_items: 16,
            max_total_bytes: 8192,
        },
    }
}

struct MemoryResolver {
    artifacts: HashMap<String, (String, Vec<u8>)>,
}

impl ContractResolver for MemoryResolver {
    fn resolve(
        &self,
        _parent_scope: &str,
        reference: &str,
    ) -> Result<ResolvedContract, ContractError> {
        self.artifacts
            .get(reference)
            .map(|(scope_identity, bytes)| ResolvedContract {
                scope_identity: scope_identity.clone(),
                bytes: bytes.clone(),
            })
            .ok_or_else(|| ContractError::ContractNotFound(reference.to_string()))
    }
}

const CONTRACT: &str = r#"
schema_version: kmns.io/validate/v1alpha1
id: TEST_CONTRACT
metadata:
  name: Example validation
  description: Verify the declared state.
  version: "0.1.0"
  language: en
checks:
  - id: CONFIG_FILE
    kind: resource
    metadata:
      name: Configuration file
      description: Verify the local configuration file.
      severity: high
    resource:
      kind: file
      path: /etc/kmns/example.yaml
    expect:
      exists: true
  - id: STATUS
    kind: plugin
    metadata:
      name: Example status
      description: Verify seal state.
      severity: high
    provider: test:example
    capability: example:status:read
    args:
      endpoint: http://127.0.0.1:8200
    expect:
      sealed: true
  - id: NETWORK
    kind: contract
    metadata:
      name: Network validation
      description: Verify network prerequisites.
      severity: medium
    contract:
      ref: example/network
"#;

#[test]
fn parser_preserves_ordered_mixed_checks() {
    let contract = Contract::parse(CONTRACT.as_bytes(), &limits()).unwrap();
    assert_eq!(contract.checks.len(), 3);
    let resource = match &contract.checks[0] {
        kmns_contract::ContractCheck::Resource(resource) => resource,
        _ => panic!("expected resource check"),
    };
    assert_eq!(resource.resource.kind, NativeResourceKind::File);
    assert!(matches!(
        contract.checks[1],
        kmns_contract::ContractCheck::Plugin(_)
    ));
    assert!(matches!(
        contract.checks[2],
        kmns_contract::ContractCheck::Contract(_)
    ));
}

#[test]
fn parser_accepts_only_the_approved_host_observation_fields() {
    let host_contract = r#"
schema_version: kmns.io/validate/v1alpha1
id: host
metadata:
  name: Host baseline
  description: Report bounded host facts.
  version: "0.1.0"
  language: en
checks:
  - id: HOSTNAME
    kind: resource
    metadata:
      name: Hostname
      description: Report the local hostname.
      severity: low
    resource:
      kind: host
      field: hostname
"#;
    assert!(Contract::parse(host_contract.as_bytes(), &limits()).is_ok());
    assert!(Contract::parse(
        host_contract
            .replace("field: hostname", "field: interfaces")
            .as_bytes(),
        &limits()
    )
    .is_err());
}

#[test]
fn parser_rejects_unknown_kinds_duplicate_ids_and_unsafe_references() {
    for invalid in [
        CONTRACT.replace("kind: resource", "kind: unknown"),
        CONTRACT.replace("- id: STATUS", "- id: CONFIG_FILE"),
        CONTRACT.replace("ref: example/network", "ref: ../private"),
    ] {
        assert!(Contract::parse(invalid.as_bytes(), &limits()).is_err());
    }
}

#[test]
fn report_identifiers_are_bounded_readable_ascii_transport_keys() {
    assert_eq!(MAX_CONTRACT_ID_BYTES, 32);
    assert_eq!(MAX_CHECK_ID_BYTES, 32);

    for invalid in [
        CONTRACT.replacen(
            "id: TEST_CONTRACT",
            &format!("id: {}", "A".repeat(MAX_CONTRACT_ID_BYTES + 1)),
            1,
        ),
        CONTRACT.replace(
            "id: CONFIG_FILE",
            &format!("id: {}", "A".repeat(MAX_CHECK_ID_BYTES + 1)),
        ),
        CONTRACT.replacen("id: TEST_CONTRACT", "id: TEST_CONTRACTÉ", 1),
    ] {
        assert!(matches!(
            Contract::parse(invalid.as_bytes(), &limits()),
            Err(ContractError::InvalidIdentity(_))
        ));
    }
}

#[test]
fn parser_rejects_unsupported_schema_and_oversized_input() {
    let invalid = CONTRACT.replace("v1alpha1", "v2");
    assert!(matches!(
        Contract::parse(invalid.as_bytes(), &limits()),
        Err(ContractError::UnsupportedSchemaVersion(_))
    ));
    let small = ContractLimits {
        max_artifact_bytes: 1,
        ..limits()
    };
    assert!(matches!(
        Contract::parse(CONTRACT.as_bytes(), &small),
        Err(ContractError::InputTooLarge)
    ));
}

#[test]
fn approved_defaults_bound_input_graph_and_yaml_nesting() {
    let defaults = ContractLimits::default();
    assert_eq!(defaults.max_artifact_bytes, 1024 * 1024);
    assert_eq!(defaults.max_graph_bytes, 4 * 1024 * 1024);
    assert_eq!(defaults.max_checks, 1024);
    assert_eq!(defaults.max_graph_checks, 1024);
    assert_eq!(defaults.max_contract_depth, 16);
    assert_eq!(defaults.max_yaml_depth, 32);
    assert_eq!(defaults.metadata.max_string_bytes, 16 * 1024);
    assert_eq!(defaults.metadata.max_list_items, 64);

    let shallow_limit = ContractLimits {
        max_yaml_depth: 1,
        ..limits()
    };
    assert!(matches!(
        Contract::parse(CONTRACT.as_bytes(), &shallow_limit),
        Err(ContractError::YamlDepthExceeded)
    ));
}

#[test]
fn errors_have_fixed_wire_values_and_ascii_symbols() {
    let error = Contract::parse(
        CONTRACT.as_bytes(),
        &ContractLimits {
            max_artifact_bytes: 1,
            ..limits()
        },
    )
    .unwrap_err();

    assert_eq!(error.code(), ContractErrorCode::InputTooLarge);
    assert_eq!(error.code().wire_value(), 0x1001);
    assert_eq!(error.code().symbol(), "CT_INPUT_SIZE");
    assert!(error
        .code()
        .symbol()
        .bytes()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'));
    assert!(error.code().symbol().len() <= 16);
    assert!(error.to_string().contains("byte limit"));
}

#[test]
fn compiler_expands_nested_checks_in_declared_depth_first_order() {
    let root = Contract::parse(CONTRACT.as_bytes(), &limits()).unwrap();
    let child = CONTRACT.replace(
            "  - id: NETWORK\n    kind: contract\n    metadata:\n      name: Network validation\n      description: Verify network prerequisites.\n      severity: medium\n    contract:\n      ref: example/network\n",
            "",
    );
    let resolver = MemoryResolver {
        artifacts: HashMap::from([(
            "example/network".to_string(),
            ("scope://root/network".to_string(), child.into_bytes()),
        )]),
    };

    let CompiledContract { checks, .. } =
        root.compile("scope://root", &resolver, &limits()).unwrap();
    let paths: Vec<Vec<String>> = checks.into_iter().map(|check| check.id_path).collect();
    assert_eq!(
        paths,
        vec![
            vec!["CONFIG_FILE".to_string()],
            vec!["STATUS".to_string()],
            vec!["NETWORK".to_string(), "CONFIG_FILE".to_string()],
            vec!["NETWORK".to_string(), "STATUS".to_string()],
        ]
    );
}

#[test]
fn compiler_rejects_missing_cycles_and_graph_limit() {
    let root = Contract::parse(CONTRACT.as_bytes(), &limits()).unwrap();
    let missing = MemoryResolver {
        artifacts: HashMap::new(),
    };
    assert!(matches!(
        root.compile("scope://root", &missing, &limits()),
        Err(ContractError::ContractNotFound(_))
    ));

    let cyclic = CONTRACT.replace("ref: example/network", "ref: example/root");
    let resolver = MemoryResolver {
        artifacts: HashMap::from([
            (
                "example/network".to_string(),
                ("scope://root/network".to_string(), cyclic.into_bytes()),
            ),
            (
                "example/root".to_string(),
                ("scope://root".to_string(), CONTRACT.as_bytes().to_vec()),
            ),
        ]),
    };
    assert!(matches!(
        root.compile("scope://root", &resolver, &limits()),
        Err(ContractError::ContractCycle(_))
    ));

    let constrained = ContractLimits {
        max_graph_checks: 1,
        ..limits()
    };
    assert!(matches!(
        root.compile("scope://root", &resolver, &constrained),
        Err(ContractError::GraphCheckLimitExceeded)
    ));
}

#[test]
fn compiler_bounds_graph_input_and_hashes_canonical_resolved_content() {
    let root = Contract::parse(CONTRACT.as_bytes(), &limits()).unwrap();
    let child = CONTRACT.replace(
        "  - id: NETWORK\n    kind: contract\n    metadata:\n      name: Network validation\n      description: Verify network prerequisites.\n      severity: medium\n    contract:\n      ref: example/network\n",
        "",
    );
    let child_bytes = child.as_bytes().to_vec();
    let resolver = MemoryResolver {
        artifacts: HashMap::from([(
            "example/network".to_string(),
            ("scope://root/network".to_string(), child_bytes.clone()),
        )]),
    };

    let first = root.compile("scope://root", &resolver, &limits()).unwrap();
    let second = root.compile("scope://root", &resolver, &limits()).unwrap();
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.digest.as_bytes().len(), 32);
    assert_eq!(first.digest.to_hex().len(), 64);

    let left = CONTRACT.replace(
        "      endpoint: http://127.0.0.1:8200",
        "      settings:\n        alpha: true\n        beta: true\n      endpoint: http://127.0.0.1:8200",
    );
    let right = CONTRACT.replace(
        "      endpoint: http://127.0.0.1:8200",
        "      settings:\n        beta: true\n        alpha: true\n      endpoint: http://127.0.0.1:8200",
    );
    let left = Contract::parse(left.as_bytes(), &limits()).unwrap();
    let right = Contract::parse(right.as_bytes(), &limits()).unwrap();
    assert_eq!(
        left.compile("scope://root", &resolver, &limits())
            .unwrap()
            .digest,
        right
            .compile("scope://root", &resolver, &limits())
            .unwrap()
            .digest
    );

    let changed_child = child.replace("Verify seal state.", "Verify changed seal state.");
    let changed_resolver = MemoryResolver {
        artifacts: HashMap::from([(
            "example/network".to_string(),
            (
                "scope://root/network".to_string(),
                changed_child.into_bytes(),
            ),
        )]),
    };
    let changed = root
        .compile("scope://root", &changed_resolver, &limits())
        .unwrap();
    assert_ne!(first.digest, changed.digest);

    let constrained = ContractLimits {
        max_graph_bytes: CONTRACT.len() + child_bytes.len() - 1,
        ..limits()
    };
    assert!(matches!(
        root.compile("scope://root", &resolver, &constrained),
        Err(ContractError::GraphInputTooLarge)
    ));
}

fn native_contract(kind: &str, target: &str, target_value: &str, expect: &str) -> String {
    format!(
        r#"
schema_version: kmns.io/validate/v1alpha1
id: NATIVE_CHECK
metadata:
  name: Native {kind}
  description: Verify native {kind}.
  version: "0.1.0"
  language: en
checks:
  - id: RESOURCE_CHECK
    kind: resource
    metadata:
      name: Native {kind}
      description: Verify native {kind}.
      severity: low
    resource:
      kind: {kind}
      {target}: {target_value}
    expect:
      {expect}
"#
    )
}

#[test]
fn every_existing_native_kind_maps_to_legacy_field_names() {
    let cases = [
        ("addr", "address", "127.0.0.1", "reachable: true", "address"),
        ("command", "command", "true", "exit-status: 0", "command"),
        ("container", "name", "app", "status: running", "name"),
        ("dns", "host", "localhost", "resolvable: true", "host"),
        ("exec", "path", "/bin/true", "exit-status: 0", "path"),
        ("file", "path", "/etc/hosts", "exists: true", "path"),
        ("group", "groupname", "root", "exists: true", "groupname"),
        ("http", "url", "http://127.0.0.1", "status: 200", "url"),
        ("interface", "interface", "lo", "exists: true", "interface"),
        (
            "kernel",
            "parameter",
            "kernel.hostname",
            "value: host",
            "parameter",
        ),
        ("mount", "mount_point", "/", "exists: true", "mount_point"),
        ("package", "package", "bash", "installed: true", "package"),
        ("port", "port", "tcp:80", "listening: true", "port"),
        ("process", "process", "init", "running: true", "process"),
        ("service", "name", "sshd", "running: true", "name"),
        ("user", "username", "root", "exists: true", "username"),
    ];

    for (kind, target, target_value, expect, legacy_target) in cases {
        let contract = Contract::parse(
            native_contract(kind, target, target_value, expect).as_bytes(),
            &limits(),
        )
        .unwrap();
        let resource = match &contract.checks[0] {
            kmns_contract::ContractCheck::Resource(resource) => resource,
            _ => unreachable!(),
        };
        let legacy = resource.to_legacy_fields().unwrap();
        assert!(legacy.contains_key(legacy_target), "{kind}");
        assert!(
            legacy.contains_key(expect.split(':').next().unwrap()),
            "{kind}"
        );
    }
}

#[test]
fn native_mapping_rejects_missing_targets_unknown_fields_and_collisions() {
    let missing = native_contract("file", "path", "/etc/hosts", "exists: true")
        .replace("      path: /etc/hosts\n", "");
    assert!(Contract::parse(missing.as_bytes(), &limits()).is_err());

    let unknown = native_contract("service", "name", "sshd", "running: true").replace(
        "      name: sshd",
        "      name: sshd\n      arbitrary: value",
    );
    assert!(Contract::parse(unknown.as_bytes(), &limits()).is_err());

    let collision = native_contract("file", "path", "/etc/hosts", "path: /tmp/other");
    assert!(Contract::parse(collision.as_bytes(), &limits()).is_err());
}

#[test]
fn compiled_contract_filters_by_tags() {
    let raw = r#"schema_version: kmns.io/validate/v1alpha1
id: test-tags
metadata:
  name: Stage Tagging Test
  description: Tests check filtering by stage tags
  version: "1.0.0"
  language: en
checks:
  - kind: resource
    id: pre-check
    metadata:
      name: Pre-installation assertion
      description: Run before install
      severity: info
      tags: ["pre-install"]
    resource:
      kind: file
      path: /etc/hosts
  - kind: resource
    id: migration-check
    metadata:
      name: Database migration assertion
      description: Run during migration
      severity: medium
      tags: ["migration"]
    resource:
      kind: file
      path: /etc/hosts
  - kind: resource
    id: prod-check
    metadata:
      name: Live production service assertion
      description: Run in production
      severity: high
      tags: ["production"]
    resource:
      kind: file
      path: /etc/hosts
"#;

    struct EmptyResolver;
    impl kmns_contract::ContractResolver for EmptyResolver {
        fn resolve(
            &self,
            _parent: &str,
            _reference: &str,
        ) -> Result<kmns_contract::ResolvedContract, kmns_contract::ContractError> {
            Err(kmns_contract::ContractError::ContractNotFound(
                "none".to_string(),
            ))
        }
    }

    let contract = Contract::parse(raw.as_bytes(), &limits()).unwrap();
    let compiled = contract
        .compile("scope://test", &EmptyResolver, &limits())
        .unwrap();
    assert_eq!(compiled.checks.len(), 3);

    // Empty filter returns all
    let all = compiled.filter_by_tags(&[]);
    assert_eq!(all.checks.len(), 3);

    // Filter by single stage
    let pre = compiled.filter_by_tags(&["pre-install".to_string()]);
    assert_eq!(pre.checks.len(), 1);
    assert_eq!(pre.checks[0].id_path, vec!["pre-check"]);

    // Filter by multiple stages
    let multi = compiled.filter_by_tags(&["pre-install".to_string(), "production".to_string()]);
    assert_eq!(multi.checks.len(), 2);
    assert_eq!(multi.checks[0].id_path, vec!["pre-check"]);
    assert_eq!(multi.checks[1].id_path, vec!["prod-check"]);

    // Filter by unmatched stage
    let unmatched = compiled.filter_by_tags(&["nonexistent".to_string()]);
    assert_eq!(unmatched.checks.len(), 0);
}
