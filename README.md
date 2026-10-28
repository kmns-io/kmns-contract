# `kmns-contract`

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Documentation](https://img.shields.io/badge/docs-validate.kmns.io-blue)](https://validate.kmns.io)

Typed declarative infrastructure contract grammar, AST models, and schema parser for [`kmns-validate`](https://github.com/kmns-io/kmns-validate).

## Overview

`kmns-contract` provides the underlying data model, parsing engine, path evaluation, and validation rules for KMNS declarative infrastructure contracts (`schema_version: kmns.io/validate/v1alpha1`).

## Installation

Add the published crate to your project's `Cargo.toml`:

```toml
[dependencies]
kmns-contract = "0.2.0"
```

## Features

- **Typed AST Grammar**: Strongly-typed Rust models for resource checks, matcher expressions, and metadata boundaries.
- **Defensive Parsing**: Strict bounded limits (`ContractLimits`, `MetadataLimits`) defending against YAML bomb injection and excessive depth traversal.
- **Zero Dynamic Unsafe**: Guaranteed `#![forbid(unsafe_code)]` safety.
- **Fast Execution**: Sub-millisecond parsing and validation designed for CLI, agentic workflows, and CI/CD pipelines.

## Usage

```rust
use kmns_contract::{Contract, ContractLimits};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = br#"
schema_version: kmns.io/validate/v1alpha1
id: EXAMPLE_CONTRACT
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
"#;

    let contract = Contract::parse(yaml, &ContractLimits::default())?;
    println!("Loaded contract: {} ({} checks)", contract.id, contract.checks.len());
    Ok(())
}
```

## License

`kmns-contract` is open-source software licensed under the **[Apache License 2.0](LICENSE)**.
