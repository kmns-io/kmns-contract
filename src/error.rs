use crate::{MetadataError, MetadataLimits, NativeResourceKind};
use thiserror::Error;

/// Stable contract-error identity for compact network reports.
///
/// The numeric value is a fixed-width `u16` wire representation. The symbolic value is strict
/// 7-bit ASCII (`A-Z`, `0-9`, `_`) and is safe to expose in terse reports. Human-readable error
/// text is deliberately kept out of this type and is available only through [`ContractError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ContractErrorCode {
    InputTooLarge = 0x1001,
    Parse = 0x1002,
    UnsupportedSchema = 0x1003,
    InvalidIdentity = 0x1004,
    DuplicateCheckId = 0x1005,
    CheckLimit = 0x1006,
    GraphCheckLimit = 0x1007,
    ContractDepth = 0x1008,
    ContractNotFound = 0x1009,
    ContractCycle = 0x100A,
    MissingResourceField = 0x100B,
    UnsupportedResourceField = 0x100C,
    ResourceFieldCollision = 0x100D,
    Metadata = 0x100E,
    GraphInputTooLarge = 0x100F,
    YamlDepth = 0x1010,
    Canonicalization = 0x1011,
}

impl ContractErrorCode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    pub const fn symbol(self) -> &'static str {
        match self {
            Self::InputTooLarge => "CT_INPUT_SIZE",
            Self::Parse => "CT_PARSE",
            Self::UnsupportedSchema => "CT_SCHEMA",
            Self::InvalidIdentity => "CT_INVALID_ID",
            Self::DuplicateCheckId => "CT_DUPLICATE_ID",
            Self::CheckLimit => "CT_CHECK_LIMIT",
            Self::GraphCheckLimit => "CT_GRAPH_LIMIT",
            Self::ContractDepth => "CT_DEPTH_LIMIT",
            Self::ContractNotFound => "CT_REF_MISSING",
            Self::ContractCycle => "CT_REF_CYCLE",
            Self::MissingResourceField => "CT_FIELD_MISSING",
            Self::UnsupportedResourceField => "CT_FIELD_UNKNOWN",
            Self::ResourceFieldCollision => "CT_FIELD_CONFLICT",
            Self::Metadata => "CT_METADATA",
            Self::GraphInputTooLarge => "CT_GRAPH_SIZE",
            Self::YamlDepth => "CT_YAML_DEPTH",
            Self::Canonicalization => "CT_CANONICAL",
        }
    }
}
/// Bounds selected by the embedding host before parsing an untrusted artifact.
///
/// [`Default`] is the standard production policy. Tests may use narrower values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractLimits {
    pub max_artifact_bytes: usize,
    pub max_graph_bytes: usize,
    pub max_checks: usize,
    pub max_graph_checks: usize,
    pub max_contract_depth: usize,
    pub max_yaml_depth: usize,
    pub metadata: MetadataLimits,
}

impl Default for ContractLimits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 1024 * 1024,
            max_graph_bytes: 4 * 1024 * 1024,
            max_checks: 1024,
            max_graph_checks: 1024,
            max_contract_depth: 16,
            max_yaml_depth: 32,
            metadata: MetadataLimits {
                max_string_bytes: 16 * 1024,
                max_list_items: 64,
                max_total_bytes: 4 * 1024 * 1024,
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum ContractError {
    #[error("contract input exceeds its configured byte limit")]
    InputTooLarge,
    #[error("resolved contract graph exceeds its configured byte limit")]
    GraphInputTooLarge,
    #[error("contract YAML exceeds its configured nesting depth")]
    YamlDepthExceeded,
    #[error("contract YAML is invalid: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("unsupported contract schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("contract identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error("contract has duplicate check identity: {0}")]
    DuplicateCheckId(String),
    #[error("contract exceeds its configured check limit")]
    CheckLimitExceeded,
    #[error("contract graph exceeds its configured check limit")]
    GraphCheckLimitExceeded,
    #[error("contract graph exceeds its configured nesting depth")]
    ContractDepthExceeded,
    #[error("contract reference was not found: {0}")]
    ContractNotFound(String),
    #[error("contract reference cycle detected: {0}")]
    ContractCycle(String),
    #[error("resource {kind:?} is missing required target field: {field}")]
    MissingResourceField {
        kind: NativeResourceKind,
        field: &'static str,
    },
    #[error("resource {kind:?} has unsupported {section} field: {field}")]
    UnsupportedResourceField {
        kind: NativeResourceKind,
        section: &'static str,
        field: String,
    },
    #[error("resource {kind:?} repeats field in target and expectation: {field}")]
    ResourceFieldCollision {
        kind: NativeResourceKind,
        field: String,
    },
    #[error("contract check metadata is invalid: {0}")]
    Metadata(#[from] MetadataError),
    #[error("contract cannot be represented as canonical JSON: {0}")]
    Canonicalization(#[from] serde_json::Error),
}

impl ContractError {
    /// Stable identity for terse reports and binary transport.
    pub const fn code(&self) -> ContractErrorCode {
        match self {
            Self::InputTooLarge => ContractErrorCode::InputTooLarge,
            Self::GraphInputTooLarge => ContractErrorCode::GraphInputTooLarge,
            Self::YamlDepthExceeded => ContractErrorCode::YamlDepth,
            Self::Parse(_) => ContractErrorCode::Parse,
            Self::UnsupportedSchemaVersion(_) => ContractErrorCode::UnsupportedSchema,
            Self::InvalidIdentity(_) => ContractErrorCode::InvalidIdentity,
            Self::DuplicateCheckId(_) => ContractErrorCode::DuplicateCheckId,
            Self::CheckLimitExceeded => ContractErrorCode::CheckLimit,
            Self::GraphCheckLimitExceeded => ContractErrorCode::GraphCheckLimit,
            Self::ContractDepthExceeded => ContractErrorCode::ContractDepth,
            Self::ContractNotFound(_) => ContractErrorCode::ContractNotFound,
            Self::ContractCycle(_) => ContractErrorCode::ContractCycle,
            Self::MissingResourceField { .. } => ContractErrorCode::MissingResourceField,
            Self::UnsupportedResourceField { .. } => ContractErrorCode::UnsupportedResourceField,
            Self::ResourceFieldCollision { .. } => ContractErrorCode::ResourceFieldCollision,
            Self::Metadata(_) => ContractErrorCode::Metadata,
            Self::Canonicalization(_) => ContractErrorCode::Canonicalization,
        }
    }
}
