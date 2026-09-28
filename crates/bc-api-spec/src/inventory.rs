//! Operations: what a document declares and what the code serves.
//!
//! Every standard describes its operations as a kind and an address. For
//! OpenAPI the kind is the lower-case HTTP method and the address the path
//! template; for GraphQL the root operation type (`query`, `mutation`,
//! `subscription`) and the root field; for AsyncAPI `send` or `receive`
//! and the channel address; for OpenRPC `call` and the method name; for
//! Protocol Buffers `service` and the gRPC service name. The inventory the
//! generator builds from code, and the comparison with a document, use
//! that same shape for every standard.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One operation: its kind (`method`) and its address (`path`), as the
/// standard spells them (see the module comment).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Operation {
    pub method: String,
    pub path: String,
}

impl Operation {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
        }
    }
}

/// One operation the code serves, with the code that serves it: a
/// repository file, a 1-based line and an exact snippet from that line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitedOperation {
    pub method: String,
    pub path: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

/// How a document's operations compare with an inventory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completeness {
    /// Served by the code, absent from the document.
    pub missing: Vec<Operation>,
    /// Documented, but not found in the inventory. They are kept and
    /// flagged: static discovery misses operations, so absence from the
    /// inventory is never a reason to delete a documented one.
    pub unverified: Vec<Operation>,
}

impl Completeness {
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Compare documented operations with an inventory by comparison key:
/// `documented` pairs each documented operation with the keys it matches
/// under, and `key` gives an inventory operation's key.
pub fn compare_by_key<K: Ord>(
    documented: Vec<(Operation, Vec<K>)>,
    inventory: &[Operation],
    key: impl Fn(&Operation) -> K,
) -> Completeness {
    let documented_keys: BTreeSet<&K> = documented.iter().flat_map(|(_, keys)| keys).collect();
    let served: BTreeSet<K> = inventory.iter().map(&key).collect();
    let missing: BTreeSet<Operation> = inventory
        .iter()
        .filter(|operation| !documented_keys.contains(&key(operation)))
        .cloned()
        .collect();
    let unverified: BTreeSet<Operation> = documented
        .iter()
        .filter(|(_, keys)| !keys.iter().any(|key| served.contains(key)))
        .map(|(operation, _)| operation.clone())
        .collect();
    Completeness {
        missing: missing.into_iter().collect(),
        unverified: unverified.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_decide_what_is_missing_and_what_is_unverified() {
        let documented = vec![
            (Operation::new("call", "a"), vec!["a".to_string()]),
            (Operation::new("call", "b"), vec!["b".to_string()]),
        ];
        let inventory = [Operation::new("call", "A"), Operation::new("call", "c")];
        let result = compare_by_key(documented, &inventory, |operation| {
            operation.path.to_lowercase()
        });
        assert_eq!(result.missing, [Operation::new("call", "c")]);
        assert_eq!(result.unverified, [Operation::new("call", "b")]);
        assert!(!result.is_complete());
        let nothing_documented = compare_by_key(
            Vec::<(Operation, Vec<String>)>::new(),
            &[Operation::new("call", "a")],
            |_| String::new(),
        );
        assert_eq!(nothing_documented.missing.len(), 1);
    }
}
