use crate::{
    CheckMetadata, Contract, ContractCheck, ContractError, ContractLimits, PluginCheck,
    ResourceCheck,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Trusted resolution result used to detect reference cycles without global contract IDs.
pub struct ResolvedContract {
    /// Resolver-owned canonical location; never read from the contract artifact.
    pub scope_identity: String,
    pub bytes: Vec<u8>,
}

/// Resolves one same-scope contract reference into its trusted artifact and canonical location.
/// The host owns filesystem policy, user/root scope selection, and access authorization.
pub trait ContractResolver {
    fn resolve(
        &self,
        parent_scope: &str,
        reference: &str,
    ) -> Result<ResolvedContract, ContractError>;
}

/// A leaf check with a stable path through nested contract references.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledCheck {
    pub id_path: Vec<String>,
    pub check: ExecutableCheck,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExecutableCheck {
    Resource(ResourceCheck),
    Plugin(PluginCheck),
}

impl ExecutableCheck {
    pub fn metadata(&self) -> &CheckMetadata {
        match self {
            ExecutableCheck::Resource(resource) => &resource.metadata,
            ExecutableCheck::Plugin(plugin) => &plugin.metadata,
        }
    }
}

/// Fully expanded, deterministic execution plan. It is deliberately independent of transport.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledContract {
    pub id: String,
    pub checks: Vec<CompiledCheck>,
    pub digest: ContractDigest,
}

impl CompiledContract {
    /// Returns a new CompiledContract containing only checks matching any of the specified tags.
    /// If `tags` is empty, all checks are retained.
    pub fn filter_by_tags(&self, tags: &[String]) -> Self {
        if tags.is_empty() {
            return self.clone();
        }
        let checks = self
            .checks
            .iter()
            .filter(|compiled_check| {
                let check_tags = &compiled_check.check.metadata().tags;
                tags.iter().any(|req_tag| {
                    check_tags
                        .iter()
                        .any(|check_tag| check_tag.eq_ignore_ascii_case(req_tag.trim()))
                })
            })
            .cloned()
            .collect();

        Self {
            id: self.id.clone(),
            checks,
            digest: self.digest,
        }
    }
}

/// SHA-256 identity of the canonical resolved contract graph.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContractDigest([u8; 32]);

impl ContractDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl std::fmt::Debug for ContractDigest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ContractDigest")
            .field(&self.to_hex())
            .finish()
    }
}

#[derive(Serialize)]
struct DigestEntry {
    scope_identity: String,
    contract: Contract,
}

struct ExpansionState {
    stack: Vec<String>,
    checks: Vec<CompiledCheck>,
    graph_bytes: usize,
    digest_entries: Vec<DigestEntry>,
}

impl Contract {
    /// Resolves nested contracts depth-first before any executor receives a check.
    pub fn compile<R: ContractResolver>(
        &self,
        root_scope: &str,
        resolver: &R,
        limits: &ContractLimits,
    ) -> Result<CompiledContract, ContractError> {
        self.validate(limits)?;
        let mut state = ExpansionState {
            stack: vec![root_scope.to_owned()],
            checks: Vec::new(),
            graph_bytes: self.source_bytes(),
            digest_entries: vec![DigestEntry {
                scope_identity: root_scope.to_owned(),
                contract: self.clone(),
            }],
        };
        if state.graph_bytes > limits.max_graph_bytes {
            return Err(ContractError::GraphInputTooLarge);
        }
        self.expand(resolver, limits, 0, Vec::new(), &mut state)?;
        let canonical_json = canonical_json(&state.digest_entries)?;
        let digest = ContractDigest(Sha256::digest(canonical_json).into());
        Ok(CompiledContract {
            id: self.id.clone(),
            checks: state.checks,
            digest,
        })
    }

    fn expand<R: ContractResolver>(
        &self,
        resolver: &R,
        limits: &ContractLimits,
        depth: usize,
        prefix: Vec<String>,
        state: &mut ExpansionState,
    ) -> Result<(), ContractError> {
        if depth > limits.max_contract_depth {
            return Err(ContractError::ContractDepthExceeded);
        }
        for check in &self.checks {
            let (id, _) = check.identity_and_metadata();
            let mut id_path = prefix.clone();
            id_path.push(id.to_string());
            match check {
                ContractCheck::Resource(resource) => state.checks.push(CompiledCheck {
                    id_path,
                    check: ExecutableCheck::Resource(resource.clone()),
                }),
                ContractCheck::Plugin(plugin) => state.checks.push(CompiledCheck {
                    id_path,
                    check: ExecutableCheck::Plugin(plugin.clone()),
                }),
                ContractCheck::Contract(nested) => {
                    let resolved = resolver.resolve(
                        state.stack.last().expect("root scope exists"),
                        &nested.contract.reference,
                    )?;
                    if state
                        .stack
                        .iter()
                        .any(|ancestor| ancestor == &resolved.scope_identity)
                    {
                        return Err(ContractError::ContractCycle(resolved.scope_identity));
                    }
                    let next_graph_bytes = state
                        .graph_bytes
                        .checked_add(resolved.bytes.len())
                        .ok_or(ContractError::GraphInputTooLarge)?;
                    if next_graph_bytes > limits.max_graph_bytes {
                        return Err(ContractError::GraphInputTooLarge);
                    }
                    let child = Self::parse(&resolved.bytes, limits)?;
                    state.graph_bytes = next_graph_bytes;
                    state.stack.push(resolved.scope_identity);
                    state.digest_entries.push(DigestEntry {
                        scope_identity: state.stack.last().expect("nested scope exists").clone(),
                        contract: child.clone(),
                    });
                    child.expand(resolver, limits, depth + 1, id_path, state)?;
                    state.stack.pop();
                }
            }
            if state.checks.len() > limits.max_graph_checks {
                return Err(ContractError::GraphCheckLimitExceeded);
            }
        }
        Ok(())
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let value = serde_json::to_value(value)?;
    serde_json::to_vec(&canonicalize_json(value)).map_err(ContractError::from)
}

fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonicalize_json).collect())
        }
        serde_json::Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values.into_iter().collect();
            let mut canonical = serde_json::Map::new();
            for (key, value) in sorted {
                canonical.insert(key, canonicalize_json(value));
            }
            serde_json::Value::Object(canonical)
        }
        scalar => scalar,
    }
}
