use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};
use thiserror::Error;

/// Trusted target-account context supplied by the host, never deserialized from a request.
pub struct TargetAccountPaths {
    home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
}

impl TargetAccountPaths {
    pub fn new(home: Option<PathBuf>, xdg_config_home: Option<PathBuf>) -> Self {
        Self {
            home,
            xdg_config_home,
        }
    }

    fn config_home(&self) -> Result<PathBuf, PathError> {
        if let Some(base) = self
            .xdg_config_home
            .as_ref()
            .filter(|path| path.is_absolute())
        {
            return Ok(base.clone());
        }
        self.home
            .as_ref()
            .filter(|path| path.is_absolute())
            .map(|home| home.join(".config"))
            .ok_or(PathError::MissingAccountContext)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("target account has neither an absolute configuration home nor an absolute home")]
    MissingAccountContext,
    #[error("resource path is empty or contains a NUL byte")]
    InvalidPath,
    #[error("XDG resource path must be relative and cannot traverse parent directories")]
    UnsafeRelativePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourcePath {
    Literal(String),
    Based(BasedPath),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasedPath {
    pub base: PathBase,
    pub relative: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathBase {
    XdgConfigHome,
}

impl ResourcePath {
    /// Lexical target resolution only: no environment reads, filesystem access, or shell expansion.
    /// The host still owns literal-relative-path anchoring and filesystem/symlink policy.
    pub fn resolve(&self, account: &TargetAccountPaths) -> Result<PathBuf, PathError> {
        match self {
            Self::Literal(value) => {
                if value.is_empty() || value.contains('\0') {
                    return Err(PathError::InvalidPath);
                }
                Ok(PathBuf::from(value))
            }
            Self::Based(path) => {
                if path.relative.is_empty() || path.relative.contains('\0') {
                    return Err(PathError::InvalidPath);
                }
                let relative = PathBuf::from(&path.relative);
                if relative.components().any(|part| {
                    matches!(
                        part,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                }) {
                    return Err(PathError::UnsafeRelativePath);
                }
                let base = match path.base {
                    PathBase::XdgConfigHome => account.config_home()?,
                };
                Ok(base.join(relative))
            }
        }
    }
}
