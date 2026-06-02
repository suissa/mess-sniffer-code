//! Catalogue-driven tainted-sink candidate detector (opt-in, `fallow security`).
//!
//! Matches category-blind [`SinkSite`](fallow_types::extract::SinkSite)s captured
//! by the extract layer against the data-driven catalogue
//! (`security_matchers.toml`). Findings are CANDIDATES for downstream agent
//! verification, NOT verified vulnerabilities: detection is deterministic and
//! syntactic, never taint-proof.
//!
//! Blind spots (sink-shaped nodes whose callee could not be flattened to a
//! static path) are surfaced in-band via [`TaintedSinkStats`], never silently
//! dropped: an empty finding set with a non-zero count is not a clean bill.

use std::sync::OnceLock;

use rustc_hash::FxHashMap;

use fallow_types::extract::ModuleInfo;
use fallow_types::output::{IssueAction, SuppressFileAction, SuppressFileKind};
use fallow_types::results::{SecurityFinding, SecurityFindingKind, TraceHop, TraceHopRole};
use fallow_types::suppress::IssueKind;

use super::catalogue::{Matcher, catalogue};
use super::{LineOffsetsMap, byte_offset_to_line_col};
use crate::discover::FileId;
use crate::graph::ModuleGraph;
use crate::suppress::SuppressionContext;

/// The inline suppression kind token for the tainted-sink catalogue rule. ONE
/// token covers every catalogue category.
const SUPPRESS_KIND: &str = "security-sink";

/// Include/exclude scope over catalogue category ids. Built from
/// `config.security.categories`; both unset admits every category.
#[derive(Debug, Default, Clone)]
pub struct CategoryFilter {
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
}

impl CategoryFilter {
    /// Build a filter from the optional config include/exclude lists.
    #[must_use]
    pub fn new(include: Option<Vec<String>>, exclude: Option<Vec<String>>) -> Self {
        Self { include, exclude }
    }

    /// Whether the given category id is admitted. When `include` is set, only
    /// listed ids are admitted; `exclude` then removes ids from the set.
    #[must_use]
    pub fn admits(&self, id: &str) -> bool {
        if let Some(include) = &self.include
            && !include.iter().any(|c| c == id)
        {
            return false;
        }
        if let Some(exclude) = &self.exclude
            && exclude.iter().any(|c| c == id)
        {
            return false;
        }
        true
    }
}

/// In-band blind-spot accounting for the tainted-sink detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct TaintedSinkStats {
    /// Sink-shaped nodes whose callee could not be flattened to a static path
    /// (dynamic dispatch, computed members, aliased bindings), summed across
    /// scanned modules. Surfaced so an empty result is never reported clean.
    pub sinks_skipped_dynamic_callee: usize,
}

/// Build the machine-actionable file-level suppress hint emitted on every
/// finding (`auto_fixable: false`: verifying the candidate is the agent's job).
fn build_actions() -> Vec<IssueAction> {
    vec![IssueAction::SuppressFile(SuppressFileAction {
        kind: SuppressFileKind::SuppressFile,
        auto_fixable: false,
        description: "Suppress with a file-level comment at the top of the file".to_string(),
        comment: format!("// fallow-ignore-file {SUPPRESS_KIND}"),
    })]
}

/// Whether the matcher's import provenance is satisfied by the module.
///
/// `None` provenance is always satisfied. Otherwise the module must import a
/// source matching the spec (tolerant of the `node:` prefix on either side).
/// For `command-injection`, the binding's `local_name` must also be the leading
/// identifier of the callee path (the binding-trace narrowing from the plan's
/// Open question 3), matching the `child_process.fork()` provenance precedent.
fn provenance_satisfied(matcher: &Matcher, module: &ModuleInfo, callee_path: &str) -> bool {
    let Some(spec) = &matcher.import_provenance else {
        return true;
    };
    let leading_ident = callee_path.split('.').next().unwrap_or(callee_path);
    let want_binding_trace = matcher.id == "command-injection";
    module.imports.iter().any(|imp| {
        let source_matches = import_source_matches(&imp.source, spec);
        if !source_matches {
            return false;
        }
        if want_binding_trace {
            imp.local_name == leading_ident
        } else {
            true
        }
    })
}

/// Compare an import source against a provenance spec, tolerant of the `node:`
/// prefix on either side (`node:child_process` matches `child_process`).
fn import_source_matches(source: &str, spec: &str) -> bool {
    let strip = |s: &str| s.strip_prefix("node:").unwrap_or(s).to_string();
    strip(source) == strip(spec)
}

/// Compiled glob set over [`PRODUCTION_EXCLUDE_PATTERNS`](crate::discover::PRODUCTION_EXCLUDE_PATTERNS),
/// built once. Used to skip security candidates anchored in test / spec / story
/// / build-config files, matching the production-mode exclusion semantics
/// (`literal_separator(true)` so `*` cannot cross a path separator).
fn production_exclude_globset() -> &'static globset::GlobSet {
    static SET: OnceLock<globset::GlobSet> = OnceLock::new();
    SET.get_or_init(|| {
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in crate::discover::PRODUCTION_EXCLUDE_PATTERNS {
            if let Ok(glob) = globset::GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
            {
                builder.add(glob);
            }
        }
        builder
            .build()
            .unwrap_or_else(|_| globset::GlobSet::empty())
    })
}

/// Whether a finding's anchor path is a low-value noise location for security
/// candidates: a test / spec / story / fixture file, or a tooling config file
/// (`vite.config.ts`, `jest.config.js`, etc.). Such files are excluded from
/// candidate generation, matching how production-mode dead-code exclusion drops
/// them. The match runs on the workspace-relative path (forward-slash
/// normalized) so the `**/` globs anchor consistently across platforms; the
/// config-file predicate is filename-only and is reused verbatim.
fn is_low_value_anchor(path: &std::path::Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    production_exclude_globset().is_match(&normalized)
        || crate::analyze::predicates::is_config_file(path)
}

/// Run the catalogue-driven tainted-sink detector. Returns the findings plus the
/// in-band blind-spot stats. Callers gate this on the `security_sink` rule
/// severity; it never runs under bare `fallow` or the `audit` gate.
#[must_use]
pub fn find_tainted_sinks(
    graph: &ModuleGraph,
    modules: &[ModuleInfo],
    suppressions: &SuppressionContext<'_>,
    line_offsets_by_file: &LineOffsetsMap<'_>,
    category_filter: &CategoryFilter,
    declared_deps: &rustc_hash::FxHashSet<String>,
    root: &std::path::Path,
) -> (Vec<SecurityFinding>, TaintedSinkStats) {
    let mut stats = TaintedSinkStats::default();

    // Pre-filter the catalogue by the category scope AND the framework enabler
    // gate (#861). `enabler_satisfied` depends only on the project's declared
    // dependency set, not the per-module state, so it is hoisted here: a
    // framework-scoped row whose enabler package is absent never participates.
    // Empty -> nothing to do.
    let active: Vec<&Matcher> = catalogue()
        .matchers()
        .iter()
        .filter(|m| category_filter.admits(&m.id) && m.enabler_satisfied(declared_deps))
        .collect();
    if active.is_empty() {
        return (Vec::new(), stats);
    }

    let modules_by_id: FxHashMap<FileId, &ModuleInfo> =
        modules.iter().map(|m| (m.file_id, m)).collect();

    let mut findings = Vec::new();
    for node in &graph.modules {
        let Some(module) = modules_by_id.get(&node.file_id) else {
            continue;
        };
        // Always count the module's blind spots, even when it has no sinks.
        stats.sinks_skipped_dynamic_callee += module.security_sinks_skipped as usize;
        if module.security_sinks.is_empty() {
            continue;
        }
        // Skip test / spec / story / fixture files and tooling config files
        // (`vite.config.ts`, `jest.config.js`, etc.). A sink there is low-value
        // noise: build configs run at build time and test files exercise code
        // with synthetic inputs, neither is an attacker-reachable surface. This
        // mirrors the production-mode dead-code exclusion. Matching runs on the
        // PROJECT-RELATIVE path so the `**/tests/**` glob does not catch every
        // file when the project itself lives under a `tests/` directory.
        let rel_path = node.path.strip_prefix(root).unwrap_or(&node.path);
        if is_low_value_anchor(rel_path) {
            continue;
        }
        let file_id = node.file_id;
        // File-level suppression opts the whole file out. Routed through the
        // SuppressionContext so the marker is recorded as consumed (otherwise a
        // working suppression would later be flagged stale).
        if suppressions.is_file_suppressed(file_id, IssueKind::SecuritySink) {
            continue;
        }

        for sink in &module.security_sinks {
            let Some(matcher) = active.iter().copied().find(|m| {
                m.sink_shape == sink.sink_shape
                    && m.arg_index == sink.arg_index
                    && sink.arg_is_non_literal
                    && m.admits_arg_kind(sink.arg_kind)
                    && m.first_matching_pattern(&sink.callee_path).is_some()
                    && provenance_satisfied(m, module, &sink.callee_path)
            }) else {
                continue;
            };

            let (line, col) =
                byte_offset_to_line_col(line_offsets_by_file, file_id, sink.span_start);
            if suppressions.is_suppressed(file_id, line, IssueKind::SecuritySink) {
                continue;
            }

            let pattern = matcher
                .first_matching_pattern(&sink.callee_path)
                .map_or("", super::catalogue::CalleePattern::raw);
            // The `{callee}` / `{pattern}` tokens are catalogue placeholders, not
            // Rust format args; the clippy lint misreads the literal.
            #[expect(
                clippy::literal_string_with_formatting_args,
                reason = "catalogue evidence placeholders, not format args"
            )]
            let evidence = matcher
                .evidence_template
                .replace("{callee}", &sink.callee_path)
                .replace("{pattern}", pattern);

            let path = node.path.clone();
            findings.push(SecurityFinding {
                kind: SecurityFindingKind::TaintedSink,
                category: Some(matcher.id.clone()),
                cwe: Some(matcher.cwe),
                path: path.clone(),
                line,
                col,
                evidence,
                trace: vec![TraceHop {
                    path,
                    line,
                    col,
                    role: TraceHopRole::Sink,
                }],
                actions: build_actions(),
                reachability: None,
            });
        }
    }

    findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.line.cmp(&b.line))
            .then(a.col.cmp(&b.col))
            .then(a.category.cmp(&b.category))
    });
    (findings, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_filter_default_admits_all() {
        let f = CategoryFilter::default();
        assert!(f.admits("dangerous-html"));
        assert!(f.admits("anything"));
    }

    #[test]
    fn category_filter_include_scopes() {
        let f = CategoryFilter::new(Some(vec!["dangerous-html".to_string()]), None);
        assert!(f.admits("dangerous-html"));
        assert!(!f.admits("sql-injection"));
    }

    #[test]
    fn category_filter_exclude_removes() {
        let f = CategoryFilter::new(None, Some(vec!["sql-injection".to_string()]));
        assert!(f.admits("dangerous-html"));
        assert!(!f.admits("sql-injection"));
    }

    #[test]
    fn import_source_matches_node_prefix() {
        assert!(import_source_matches("node:child_process", "child_process"));
        assert!(import_source_matches("child_process", "node:child_process"));
        assert!(!import_source_matches("child_process", "node:vm"));
    }

    #[test]
    fn low_value_anchor_excludes_tests_and_configs() {
        use std::path::Path;
        // Test / spec / story / fixture files are excluded.
        assert!(is_low_value_anchor(Path::new("src/foo.test.ts")));
        assert!(is_low_value_anchor(Path::new("src/foo.spec.ts")));
        assert!(is_low_value_anchor(Path::new("src/Button.stories.tsx")));
        assert!(is_low_value_anchor(Path::new("test/helper.ts")));
        assert!(is_low_value_anchor(Path::new(
            "packages/app/__tests__/x.ts"
        )));
        // Tooling config files are excluded (filename predicate).
        assert!(is_low_value_anchor(Path::new("vite.config.ts")));
        assert!(is_low_value_anchor(Path::new(
            "packages/app/vite.config.ts"
        )));
        assert!(is_low_value_anchor(Path::new("jest.config.js")));
        // Ordinary source files are NOT excluded.
        assert!(!is_low_value_anchor(Path::new("src/sink.ts")));
        assert!(!is_low_value_anchor(Path::new("src/db/query.ts")));
        // An app-level config that is not a tooling config is NOT excluded.
        assert!(!is_low_value_anchor(Path::new("src/app/app.config.ts")));
    }
}
