#![forbid(unsafe_code)]

//! Typed declarative contract grammar and parser for kmns-validate.

mod compile;
mod error;
mod metadata;
mod path;
mod resource;
mod schema;

pub use compile::{
    CompiledCheck, CompiledContract, ContractDigest, ContractResolver, ExecutableCheck,
    ResolvedContract,
};
pub use error::{ContractError, ContractErrorCode, ContractLimits};
pub use metadata::{
    CheckMetadata, ContractMetadata, MetadataError, MetadataLimits, Pillar, Reference, Remediation,
    Severity,
};
pub use path::{BasedPath, PathBase, PathError, ResourcePath, TargetAccountPaths};
pub use schema::{
    Contract, ContractCheck, ContractReference, NativeResource, NativeResourceKind,
    NestedContractCheck, PluginCheck, ResourceCheck, MAX_CHECK_ID_BYTES, MAX_CONTRACT_ID_BYTES,
};
