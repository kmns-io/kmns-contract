use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
/// Bounds for contract and check metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLimits {
    pub max_string_bytes: usize,
    pub max_list_items: usize,
    pub max_total_bytes: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MetadataError {
    #[error("metadata contains an empty required value")]
    EmptyValue,
    #[error("metadata exceeds its configured bounds")]
    LimitExceeded,
    #[error("metadata contains unsupported control characters")]
    ControlCharacter,
    #[error("metadata reference URI is not a root-relative path or HTTPS URL")]
    InvalidReference,
    #[error("metadata reference identity is duplicated: {0}")]
    DuplicateReference(String),
    #[error("metadata remediation reference is missing: {0}")]
    MissingReference(String),
    #[error("metadata language is unsupported; expected en")]
    UnsupportedLanguage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pillar {
    #[serde(rename = "P1-PROD")]
    Product,
    #[serde(rename = "P2-INFRA")]
    Infrastructure,
    #[serde(rename = "P3-NET")]
    Network,
    #[serde(rename = "P4-OPS")]
    Operations,
    #[serde(rename = "P5-SEC")]
    Security,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub id: String,
    pub title: String,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    pub summary: String,
    #[serde(default)]
    pub reference_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractMetadata {
    pub name: String,
    pub description: String,
    pub version: String,
    pub language: String,
    pub owner: Option<String>,
    pub component: Option<String>,
    pub pillar: Option<Pillar>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<Reference>,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckMetadata {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub owner: Option<String>,
    pub component: Option<String>,
    pub pillar: Option<Pillar>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub references: Vec<Reference>,
    pub rationale: Option<String>,
    pub remediation: Option<Remediation>,
}

struct Budget<'a> {
    limits: &'a MetadataLimits,
    bytes: usize,
}

impl<'a> Budget<'a> {
    fn new(limits: &'a MetadataLimits) -> Self {
        Self { limits, bytes: 0 }
    }

    fn text(&mut self, text: &str) -> Result<(), MetadataError> {
        if text.trim().is_empty() {
            return Err(MetadataError::EmptyValue);
        }
        if text
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(MetadataError::ControlCharacter);
        }
        self.bytes = self
            .bytes
            .checked_add(text.len())
            .ok_or(MetadataError::LimitExceeded)?;
        if text.len() > self.limits.max_string_bytes || self.bytes > self.limits.max_total_bytes {
            return Err(MetadataError::LimitExceeded);
        }
        Ok(())
    }

    fn list(&self, length: usize) -> Result<(), MetadataError> {
        if length > self.limits.max_list_items {
            return Err(MetadataError::LimitExceeded);
        }
        Ok(())
    }

    fn strings<'b>(
        &mut self,
        values: impl IntoIterator<Item = &'b String>,
    ) -> Result<(), MetadataError> {
        for value in values {
            self.text(value)?;
        }
        Ok(())
    }

    fn references<'b>(
        &mut self,
        references: &'b [Reference],
    ) -> Result<HashSet<&'b str>, MetadataError> {
        self.list(references.len())?;
        let mut ids = HashSet::new();
        for reference in references {
            self.strings([&reference.id, &reference.title, &reference.uri])?;
            if !ids.insert(reference.id.as_str()) {
                return Err(MetadataError::DuplicateReference(reference.id.clone()));
            }
            let uri = &reference.uri;
            let root_relative = uri.starts_with('/')
                && !uri.starts_with("//")
                && !uri.split('/').any(|part| part == ".." || part == ".");
            let https = uri.strip_prefix("https://").is_some_and(|rest| {
                let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
                !authority.is_empty() && !authority.contains('@')
            });
            if !(root_relative || https)
                || uri.chars().any(char::is_whitespace)
                || uri.contains('\\')
            {
                return Err(MetadataError::InvalidReference);
            }
        }
        Ok(ids)
    }
}

impl ContractMetadata {
    pub fn validate(&self, limits: &MetadataLimits) -> Result<(), MetadataError> {
        let mut budget = Budget::new(limits);
        budget.strings([&self.name, &self.description, &self.version, &self.language])?;
        if self.language != "en" {
            return Err(MetadataError::UnsupportedLanguage);
        }
        budget.strings(
            self.owner
                .iter()
                .chain(&self.component)
                .chain(&self.rationale),
        )?;
        budget.list(self.tags.len())?;
        budget.strings(&self.tags)?;
        budget.references(&self.references)?;
        Ok(())
    }
}

impl CheckMetadata {
    pub fn validate(
        &self,
        contract: &ContractMetadata,
        limits: &MetadataLimits,
    ) -> Result<(), MetadataError> {
        contract.validate(limits)?;
        let mut budget = Budget::new(limits);
        budget.strings([&self.name, &self.description])?;
        budget.strings(
            self.owner
                .iter()
                .chain(&self.component)
                .chain(&self.rationale),
        )?;
        budget.list(self.tags.len())?;
        budget.strings(&self.tags)?;
        let mut ids: HashSet<&str> = contract
            .references
            .iter()
            .map(|reference| reference.id.as_str())
            .collect();
        for id in budget.references(&self.references)? {
            if !ids.insert(id) {
                return Err(MetadataError::DuplicateReference(id.to_owned()));
            }
        }
        if let Some(remediation) = &self.remediation {
            budget.text(&remediation.summary)?;
            budget.list(remediation.reference_ids.len())?;
            for id in &remediation.reference_ids {
                budget.text(id)?;
                if !ids.contains(id.as_str()) {
                    return Err(MetadataError::MissingReference(id.clone()));
                }
            }
        }
        Ok(())
    }
}
