//! Strongly typed identifiers used by Forge's public contracts.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! string_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

string_id!(RepoId, "Stable repository identity.");
string_id!(UnitId, "Stable project-unit identity.");
string_id!(CommandId, "Stable project-command identity.");
string_id!(ReceiptId, "Stable local receipt identity.");
string_id!(EvidenceId, "Stable evidence-bundle identity.");
string_id!(Digest, "Versioned content or policy digest.");
string_id!(DiagnosticCode, "Stable FGE diagnostic code.");
string_id!(ManagedBlockId, "Stable managed-block identity.");
string_id!(LanguageId, "Stable language-provider identity.");

#[cfg(test)]
mod tests {
    use super::{CommandId, RepoId};

    #[test]
    fn different_identifier_types_remain_explicit() {
        let repository = RepoId::from("repo/example");
        let command = CommandId::from("rust.check");

        assert_eq!(repository.as_str(), "repo/example");
        assert_eq!(command.as_str(), "rust.check");
    }
}
