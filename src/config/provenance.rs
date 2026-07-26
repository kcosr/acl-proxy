use std::fmt;

use super::source_snapshot::{RulesDirectoryState, SourceInventorySummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PolicySourceId(u16);

impl PolicySourceId {
    fn from_index(index: usize) -> Result<Self, ProvenanceError> {
        u16::try_from(index)
            .map(Self)
            .map_err(|_| ProvenanceError::TooManySources)
    }

    fn index(self) -> usize {
        usize::from(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicySourceKind {
    Main,
    Fragment { file: String },
}

impl PolicySourceKind {
    pub(crate) fn display_name(&self) -> String {
        match self {
            Self::Main => "main".to_owned(),
            Self::Fragment { file } => format!("rules.d/{file}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PolicyRuleSource {
    source_id: PolicySourceId,
    source_rule_index: u32,
    global_cursor: u32,
}

impl PolicyRuleSource {
    pub(crate) fn source_rule_index(self) -> usize {
        self.source_rule_index as usize
    }

    pub(crate) fn global_cursor(self) -> usize {
        self.global_cursor as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyProvenance {
    catalog: Box<[PolicySourceKind]>,
    rules: Box<[PolicyRuleSource]>,
}

impl PolicyProvenance {
    #[cfg(test)]
    pub(crate) fn main_only(rule_count: usize) -> Result<Self, ProvenanceError> {
        let mut builder = PolicyProvenanceBuilder::new()?;
        builder.append_main_rules(rule_count)?;
        builder.finish(rule_count)
    }

    pub(crate) fn rules(&self) -> &[PolicyRuleSource] {
        &self.rules
    }

    pub(crate) fn source(&self, rule: PolicyRuleSource) -> &PolicySourceKind {
        &self.catalog[rule.source_id.index()]
    }

    pub(crate) fn resolve_cursor(
        &self,
        cursor: usize,
    ) -> Option<(&PolicySourceKind, PolicyRuleSource)> {
        let rule = *self.rules.get(cursor)?;
        if rule.global_cursor() != cursor {
            return None;
        }
        Some((self.source(rule), rule))
    }

    #[cfg(test)]
    pub(crate) fn source_count(&self) -> usize {
        self.catalog.len()
    }
}

pub(super) struct PolicyProvenanceBuilder {
    catalog: Vec<PolicySourceKind>,
    rules: Vec<PendingRuleSource>,
}

impl PolicyProvenanceBuilder {
    pub(super) fn new() -> Result<Self, ProvenanceError> {
        let mut catalog = Vec::new();
        catalog
            .try_reserve_exact(1)
            .map_err(|_| ProvenanceError::Allocation)?;
        catalog.push(PolicySourceKind::Main);
        Ok(Self {
            catalog,
            rules: Vec::new(),
        })
    }

    pub(super) fn add_fragment(&mut self, file: &str) -> Result<PolicySourceId, ProvenanceError> {
        let source_id = PolicySourceId::from_index(self.catalog.len())?;
        let mut owned_file = String::new();
        owned_file
            .try_reserve_exact(file.len())
            .map_err(|_| ProvenanceError::Allocation)?;
        owned_file.push_str(file);
        self.catalog
            .try_reserve(1)
            .map_err(|_| ProvenanceError::Allocation)?;
        self.catalog
            .push(PolicySourceKind::Fragment { file: owned_file });
        Ok(source_id)
    }

    pub(super) fn append_fragment_rules(
        &mut self,
        source_id: PolicySourceId,
        count: usize,
    ) -> Result<(), ProvenanceError> {
        self.append_rules(source_id, count)
    }

    pub(super) fn append_main_rules(&mut self, count: usize) -> Result<(), ProvenanceError> {
        self.append_rules(PolicySourceId(0), count)
    }

    pub(super) fn finish(
        self,
        authored_rule_count: usize,
    ) -> Result<PolicyProvenance, ProvenanceError> {
        if self.rules.len() != authored_rule_count {
            return Err(ProvenanceError::Misaligned {
                rules: authored_rule_count,
                provenance: self.rules.len(),
            });
        }
        let mut rules = Vec::new();
        rules
            .try_reserve_exact(self.rules.len())
            .map_err(|_| ProvenanceError::Allocation)?;
        for (global_cursor, pending) in self.rules.into_iter().enumerate() {
            rules.push(PolicyRuleSource {
                source_id: pending.source_id,
                source_rule_index: pending.source_rule_index,
                global_cursor: u32::try_from(global_cursor)
                    .map_err(|_| ProvenanceError::TooManyRules)?,
            });
        }
        Ok(PolicyProvenance {
            catalog: self.catalog.into_boxed_slice(),
            rules: rules.into_boxed_slice(),
        })
    }

    fn append_rules(
        &mut self,
        source_id: PolicySourceId,
        count: usize,
    ) -> Result<(), ProvenanceError> {
        self.catalog
            .get(source_id.index())
            .ok_or(ProvenanceError::UnknownSource)?;
        self.rules
            .try_reserve(count)
            .map_err(|_| ProvenanceError::Allocation)?;
        for source_rule_index in 0..count {
            self.rules.push(PendingRuleSource {
                source_id,
                source_rule_index: u32::try_from(source_rule_index)
                    .map_err(|_| ProvenanceError::TooManyRules)?,
            });
        }
        Ok(())
    }
}

struct PendingRuleSource {
    source_id: PolicySourceId,
    source_rule_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySourceSummary {
    pub(crate) rules_directory: RulesDirectoryState,
    pub(crate) fragment_count: usize,
    pub(crate) fragment_bytes: usize,
    pub(crate) fragment_rule_count: usize,
    pub(crate) main_rule_count: usize,
    pub(crate) total_rule_count: usize,
}

impl PolicySourceSummary {
    pub(super) fn new(
        inventory: SourceInventorySummary,
        fragment_rule_count: usize,
        main_rule_count: usize,
    ) -> Result<Self, ProvenanceError> {
        let total_rule_count = fragment_rule_count
            .checked_add(main_rule_count)
            .ok_or(ProvenanceError::TooManyRules)?;
        Ok(Self {
            rules_directory: inventory.rules_directory,
            fragment_count: inventory.fragment_count,
            fragment_bytes: inventory.fragment_bytes,
            fragment_rule_count,
            main_rule_count,
            total_rule_count,
        })
    }

    #[cfg(test)]
    pub(crate) fn main_only(main_rule_count: usize) -> Self {
        Self {
            rules_directory: RulesDirectoryState::Missing,
            fragment_count: 0,
            fragment_bytes: 0,
            fragment_rule_count: 0,
            main_rule_count,
            total_rule_count: main_rule_count,
        }
    }

    pub(crate) fn rules_directory_state(&self) -> &'static str {
        match self.rules_directory {
            RulesDirectoryState::Missing => "missing",
            RulesDirectoryState::Empty => "empty",
            RulesDirectoryState::Populated => "populated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProvenanceError {
    Allocation,
    TooManySources,
    TooManyRules,
    UnknownSource,
    Misaligned { rules: usize, provenance: usize },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allocation => formatter.write_str("policy provenance allocation failed"),
            Self::TooManySources => formatter.write_str("policy has too many source files"),
            Self::TooManyRules => formatter.write_str("policy has too many rules"),
            Self::UnknownSource => {
                formatter.write_str("policy provenance refers to an unknown source")
            }
            Self::Misaligned { rules, provenance } => write!(
                formatter,
                "policy provenance is misaligned: {rules} rules and {provenance} source records"
            ),
        }
    }
}

impl std::error::Error for ProvenanceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_interns_fragment_names_and_assigns_dense_cursors() {
        let mut builder = PolicyProvenanceBuilder::new().unwrap();
        let first = builder.add_fragment("00-first.toml").unwrap();
        let second = builder.add_fragment("10-second.toml").unwrap();
        builder.append_fragment_rules(first, 2).unwrap();
        builder.append_fragment_rules(second, 1).unwrap();
        builder.append_main_rules(2).unwrap();
        let provenance = builder.finish(5).unwrap();

        assert_eq!(provenance.source_count(), 3);
        for cursor in 0..5 {
            let (_, rule) = provenance.resolve_cursor(cursor).unwrap();
            assert_eq!(rule.global_cursor(), cursor);
        }
        assert_eq!(
            provenance.resolve_cursor(0).unwrap().0.display_name(),
            "rules.d/00-first.toml"
        );
        assert_eq!(
            provenance.resolve_cursor(2).unwrap().0.display_name(),
            "rules.d/10-second.toml"
        );
        assert_eq!(
            provenance.resolve_cursor(3).unwrap().0.display_name(),
            "main"
        );
        assert_eq!(
            provenance.resolve_cursor(4).unwrap().1.source_rule_index(),
            1
        );
    }

    #[test]
    fn misalignment_never_produces_a_catalog() {
        let mut builder = PolicyProvenanceBuilder::new().unwrap();
        builder.append_main_rules(1).unwrap();
        assert!(matches!(
            builder.finish(2),
            Err(ProvenanceError::Misaligned { .. })
        ));
    }
}
