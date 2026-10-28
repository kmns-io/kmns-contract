use crate::{CheckMetadata, ContractError, ContractLimits, ContractMetadata};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
const SCHEMA_VERSION: &str = "kmns.io/validate/v1alpha1";
/// Maximum 7-bit-ASCII byte length for a human-readable contract identifier.
pub const MAX_CONTRACT_ID_BYTES: usize = 32;
/// Maximum 7-bit-ASCII byte length for a human-readable check identifier.
pub const MAX_CHECK_ID_BYTES: usize = 32;
const MAX_NAMESPACE_IDENTIFIER_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub schema_version: String,
    pub id: String,
    pub metadata: ContractMetadata,
    pub checks: Vec<ContractCheck>,
    #[serde(skip)]
    source_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ContractCheck {
    Resource(ResourceCheck),
    Plugin(PluginCheck),
    Contract(NestedContractCheck),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceCheck {
    pub id: String,
    pub metadata: CheckMetadata,
    pub resource: NativeResource,
    #[serde(default)]
    pub expect: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeResource {
    pub kind: NativeResourceKind,
    #[serde(flatten)]
    pub fields: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeResourceKind {
    Addr,
    Command,
    Container,
    Dns,
    Exec,
    File,
    Group,
    Http,
    Interface,
    Kernel,
    Mount,
    Package,
    Port,
    Process,
    Service,
    User,
    Host,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginCheck {
    pub id: String,
    pub metadata: CheckMetadata,
    pub provider: String,
    pub capability: String,
    #[serde(default)]
    pub args: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    pub expect: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedContractCheck {
    pub id: String,
    pub metadata: CheckMetadata,
    pub contract: ContractReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractReference {
    #[serde(rename = "ref")]
    pub reference: String,
}
impl Contract {
    /// Parses one bounded artifact. Graph limits and resolution remain host operations.
    pub fn parse(bytes: &[u8], limits: &ContractLimits) -> Result<Self, ContractError> {
        if bytes.len() > limits.max_artifact_bytes {
            return Err(ContractError::InputTooLarge);
        }
        let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes)?;
        if yaml_depth(&value) > limits.max_yaml_depth {
            return Err(ContractError::YamlDepthExceeded);
        }
        let mut contract = serde_yaml::from_value::<Self>(value)?;
        contract.source_bytes = bytes.len();
        contract.validate(limits)?;
        Ok(contract)
    }

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub fn validate(&self, limits: &ContractLimits) -> Result<(), ContractError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        validate_report_id(&self.id, MAX_CONTRACT_ID_BYTES)?;
        self.metadata.validate(&limits.metadata)?;
        if self.checks.len() > limits.max_checks {
            return Err(ContractError::CheckLimitExceeded);
        }
        let mut ids = HashSet::new();
        for check in &self.checks {
            let (id, metadata) = check.identity_and_metadata();
            validate_report_id(id, MAX_CHECK_ID_BYTES)?;
            if !ids.insert(id) {
                return Err(ContractError::DuplicateCheckId(id.to_string()));
            }
            metadata.validate(&self.metadata, &limits.metadata)?;
            check.validate_shape()?;
        }
        Ok(())
    }
}

fn yaml_depth(value: &serde_yaml::Value) -> usize {
    match value {
        serde_yaml::Value::Sequence(values) => {
            1 + values.iter().map(yaml_depth).max().unwrap_or_default()
        }
        serde_yaml::Value::Mapping(values) => {
            1 + values
                .iter()
                .map(|(key, value)| yaml_depth(key).max(yaml_depth(value)))
                .max()
                .unwrap_or_default()
        }
        serde_yaml::Value::Tagged(tagged) => 1 + yaml_depth(&tagged.value),
        _ => 1,
    }
}

impl ContractCheck {
    pub fn identity_and_metadata(&self) -> (&str, &CheckMetadata) {
        match self {
            Self::Resource(check) => (&check.id, &check.metadata),
            Self::Plugin(check) => (&check.id, &check.metadata),
            Self::Contract(check) => (&check.id, &check.metadata),
        }
    }

    pub(crate) fn validate_shape(&self) -> Result<(), ContractError> {
        match self {
            Self::Plugin(check) => {
                validate_namespace_identifier(&check.provider)?;
                validate_namespace_identifier(&check.capability)?;
            }
            Self::Contract(check) => {
                if check.contract.reference.trim().is_empty()
                    || check.contract.reference.starts_with('/')
                    || check.contract.reference.contains("..")
                {
                    return Err(ContractError::InvalidIdentity(
                        check.contract.reference.clone(),
                    ));
                }
            }
            Self::Resource(check) => check.validate_shape()?,
        }
        Ok(())
    }
}
fn validate_report_id(identity: &str, maximum_bytes: usize) -> Result<(), ContractError> {
    let valid = !identity.is_empty()
        && identity.len() <= maximum_bytes
        && identity.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.' | b'/')
        });
    if valid {
        Ok(())
    } else {
        Err(ContractError::InvalidIdentity(identity.to_string()))
    }
}

fn validate_namespace_identifier(identity: &str) -> Result<(), ContractError> {
    let valid = !identity.is_empty()
        && identity.len() <= MAX_NAMESPACE_IDENTIFIER_BYTES
        && identity.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':' | '.' | '/')
        });
    if valid {
        Ok(())
    } else {
        Err(ContractError::InvalidIdentity(identity.to_string()))
    }
}
