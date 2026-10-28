use crate::{ContractError, NativeResource, NativeResourceKind, ResourceCheck};
use std::collections::BTreeMap;
impl ResourceCheck {
    pub(crate) fn validate_shape(&self) -> Result<(), ContractError> {
        self.resource.validate_fields(&self.expect)
    }

    /// Reconstructs the field map expected by the existing native engine.
    /// This bridge is deterministic and side-effect free; execution stays outside this crate.
    pub fn to_legacy_fields(&self) -> Result<BTreeMap<String, serde_yaml::Value>, ContractError> {
        self.validate_shape()?;
        let mut fields = self.resource.fields.clone();
        for (name, value) in &self.expect {
            if fields.insert(name.clone(), value.clone()).is_some() {
                return Err(ContractError::ResourceFieldCollision {
                    kind: self.resource.kind,
                    field: name.clone(),
                });
            }
        }
        Ok(fields)
    }
}

impl NativeResource {
    fn validate_fields(
        &self,
        expectations: &BTreeMap<String, serde_yaml::Value>,
    ) -> Result<(), ContractError> {
        let rule = resource_rule(self.kind);
        if !self.fields.contains_key(rule.target) {
            return Err(ContractError::MissingResourceField {
                kind: self.kind,
                field: rule.target,
            });
        }
        for field in self.fields.keys() {
            if !rule.resource_fields.contains(&field.as_str()) {
                return Err(ContractError::UnsupportedResourceField {
                    kind: self.kind,
                    section: "resource",
                    field: field.clone(),
                });
            }
            if expectations.contains_key(field) {
                return Err(ContractError::ResourceFieldCollision {
                    kind: self.kind,
                    field: field.clone(),
                });
            }
        }
        for field in expectations.keys() {
            if !rule.expectation_fields.contains(&field.as_str()) {
                return Err(ContractError::UnsupportedResourceField {
                    kind: self.kind,
                    section: "expect",
                    field: field.clone(),
                });
            }
        }
        if self.kind == NativeResourceKind::Host {
            let field = self
                .fields
                .get("field")
                .and_then(serde_yaml::Value::as_str)
                .filter(|field| matches!(*field, "hostname" | "os" | "machine-id" | "uptime"))
                .ok_or_else(|| {
                    ContractError::InvalidIdentity("invalid host observation field".to_owned())
                })?;
            if field.is_empty() {
                return Err(ContractError::InvalidIdentity(
                    "invalid host observation field".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

struct ResourceRule {
    target: &'static str,
    resource_fields: &'static [&'static str],
    expectation_fields: &'static [&'static str],
}

fn resource_rule(kind: NativeResourceKind) -> ResourceRule {
    match kind {
        NativeResourceKind::Addr => ResourceRule {
            target: "address",
            resource_fields: &["address", "timeout"],
            expectation_fields: &["reachable"],
        },
        NativeResourceKind::Command => ResourceRule {
            target: "command",
            resource_fields: &["command", "timeout"],
            expectation_fields: &["exit-status", "stdout", "stderr"],
        },
        NativeResourceKind::Container => ResourceRule {
            target: "name",
            resource_fields: &["name", "socket", "user", "timeout"],
            expectation_fields: &["status", "image", "ports"],
        },
        NativeResourceKind::Dns => ResourceRule {
            target: "host",
            resource_fields: &["host", "server", "timeout"],
            expectation_fields: &["resolvable", "addrs"],
        },
        NativeResourceKind::Exec => ResourceRule {
            target: "path",
            resource_fields: &["path", "args", "timeout"],
            expectation_fields: &["exit-status", "stdout", "stderr"],
        },
        NativeResourceKind::File => ResourceRule {
            target: "path",
            resource_fields: &["path"],
            expectation_fields: &[
                "exists",
                "mode",
                "owner",
                "group",
                "filetype",
                "linked-to",
                "contents",
            ],
        },
        NativeResourceKind::Group => ResourceRule {
            target: "groupname",
            resource_fields: &["groupname"],
            expectation_fields: &["exists", "gid"],
        },
        NativeResourceKind::Http => ResourceRule {
            target: "url",
            resource_fields: &[
                "url",
                "method",
                "allow-insecure",
                "no-follow-redirects",
                "timeout",
                "request-headers",
                "username",
                "password",
                "ca-file",
                "cert-file",
                "key-file",
                "proxy",
            ],
            expectation_fields: &["status", "body", "headers"],
        },
        NativeResourceKind::Interface => ResourceRule {
            target: "interface",
            resource_fields: &["interface"],
            expectation_fields: &["exists", "addrs"],
        },
        NativeResourceKind::Kernel => ResourceRule {
            target: "parameter",
            resource_fields: &["parameter"],
            expectation_fields: &["value"],
        },
        NativeResourceKind::Mount => ResourceRule {
            target: "mount_point",
            resource_fields: &["mount_point"],
            expectation_fields: &["exists", "opts", "source", "vfs"],
        },
        NativeResourceKind::Package => ResourceRule {
            target: "package",
            resource_fields: &["package"],
            expectation_fields: &["installed", "version"],
        },
        NativeResourceKind::Port => ResourceRule {
            target: "port",
            resource_fields: &["port"],
            expectation_fields: &["listening", "ip"],
        },
        NativeResourceKind::Process => ResourceRule {
            target: "process",
            resource_fields: &["process"],
            expectation_fields: &["running", "uid", "gid"],
        },
        NativeResourceKind::Service => ResourceRule {
            target: "name",
            resource_fields: &["name"],
            expectation_fields: &["enabled", "running"],
        },
        NativeResourceKind::User => ResourceRule {
            target: "username",
            resource_fields: &["username"],
            expectation_fields: &["exists", "uid", "gid", "groups", "home", "shell"],
        },
        NativeResourceKind::Host => ResourceRule {
            target: "field",
            resource_fields: &["field"],
            expectation_fields: &[],
        },
    }
}
