//! Data-driven catalogue of syntactic security-sink candidate matchers.
//!
//! The catalogue is community-maintainable: every matcher lives in
//! `crates/core/data/security_matchers.toml`, embedded via `include_str!` and
//! parsed once behind a `OnceLock`. There is NO regeneration step. Adding a
//! category is a single `[[matcher]]` TOML edit plus ZERO Rust enum or
//! discriminant churn (the `tainted_sink` detector matches captured
//! category-blind `SinkSite`s against the loaded catalogue).
//!
//! Findings are CANDIDATES for downstream agent verification, NOT verified
//! vulnerabilities: fallow is deterministic and syntactic, never taint-proof.
//! Every matcher fires only on a non-literal argument (false-negatives over
//! false-positives).

use fallow_types::extract::{SinkArgKind, SinkShape};

/// Embedded catalogue source. Because it is `include_str!`-embedded at compile
/// time, a green `security_catalogue_parses` test guarantees the released
/// binary parses.
const CATALOGUE_TOML: &str = include_str!("../../../data/security_matchers.toml");

#[derive(serde::Deserialize)]
struct RawCatalogue {
    #[serde(default)]
    matcher: Vec<RawMatcher>,
}

#[derive(serde::Deserialize)]
struct RawMatcher {
    id: String,
    cwe: u32,
    title: String,
    /// Kebab-case shape string, validated into [`SinkShape`].
    sink_shape: String,
    callee_patterns: Vec<String>,
    arg_index: u32,
    evidence_template: String,
    #[serde(default)]
    import_provenance: Option<String>,
    /// Optional framework enabler: a package name that gates this row on the
    /// active framework (issue #861). The plugin system already activates on the
    /// declared dependency set, so a row carrying `enabler = "@angular/platform-browser"`
    /// fires only when that package (or, with a trailing `/`, any package under
    /// that prefix) is present in the project's declared dependencies. Lets a
    /// framework-specific idiom (`bypassSecurityTrustHtml`, `dangerouslySetInnerHTML`)
    /// be recognized with higher precision without a new enum variant. Unset means
    /// the row is global (the prior behavior).
    #[serde(default)]
    enabler: Option<String>,
    /// Optional allowlist of argument shapes. When set, the captured sink site's
    /// `arg_kind` must be one of the listed kebab-case kinds for the matcher to
    /// fire. Lets a matcher require the unsafe SQL shapes (`concat`,
    /// `template-with-subst`) and exclude the safely-parameterized forms
    /// (`object` for `.execute({ sql, args })`, the bare `sql` tag). Unset means
    /// any non-literal argument shape matches (the prior behavior).
    #[serde(default)]
    arg_kinds: Option<Vec<String>>,
}

/// A pre-segmented callee pattern. Matching is segment-aware (NOT substring):
/// the pattern is split on `.`, and a leading `*` segment means "any object",
/// so `*.innerHTML` matches `el.innerHTML` and `this.node.innerHTML` by
/// suffix-matching the trailing non-`*` segments.
#[derive(Debug, Clone)]
pub struct CalleePattern {
    /// The literal source pattern (`"*.innerHTML"`, `"child_process.exec"`),
    /// surfaced in evidence rendering as `{pattern}`.
    raw: String,
    /// Trailing segments after any leading `*` (e.g. `["innerHTML"]` for
    /// `*.innerHTML`, `["child_process", "exec"]` for the exact dotted form).
    suffix_segments: Vec<String>,
    /// Whether the pattern began with a `*` wildcard object segment.
    leading_wildcard: bool,
}

impl CalleePattern {
    /// The original pattern text, for evidence templating.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Segment-aware match against a captured dotted/bare callee path.
    ///
    /// With a leading `*`, the trailing segments must equal the tail of the
    /// candidate's segments (suffix match), so `*.innerHTML` matches
    /// `el.innerHTML` but not `el.innerHTMLFoo`. Without it, the whole
    /// segment list must match exactly, so `fetch` matches `fetch` but not
    /// `myfetch`.
    #[must_use]
    pub fn matches(&self, callee_path: &str) -> bool {
        let candidate: Vec<&str> = callee_path.split('.').collect();
        if self.leading_wildcard {
            // A leading `*.` requires at least one object segment before the
            // suffix, so the candidate must have strictly more segments than
            // the suffix (`*.innerHTML` matches `el.innerHTML`, not `innerHTML`).
            if self.suffix_segments.len() >= candidate.len() {
                return false;
            }
            // With only a `*` and no trailing segments, match nothing concrete.
            if self.suffix_segments.is_empty() {
                return false;
            }
            let tail = &candidate[candidate.len() - self.suffix_segments.len()..];
            self.suffix_segments
                .iter()
                .zip(tail)
                .all(|(pat, seg)| pat == seg)
        } else {
            self.suffix_segments.len() == candidate.len()
                && self
                    .suffix_segments
                    .iter()
                    .zip(&candidate)
                    .all(|(pat, seg)| pat == seg)
        }
    }
}

/// Parse a raw pattern string into its segmented form. Returns `None` for an
/// empty or whitespace-only pattern (rejected at parse time).
fn parse_callee_pattern(raw: &str) -> Option<CalleePattern> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut segments: Vec<&str> = raw.split('.').collect();
    let leading_wildcard = segments.first() == Some(&"*");
    if leading_wildcard {
        segments.remove(0);
    }
    Some(CalleePattern {
        raw: raw.to_string(),
        suffix_segments: segments.into_iter().map(str::to_string).collect(),
        leading_wildcard,
    })
}

/// A parsed, validated matcher with the sink shape resolved to the typed enum
/// and callee patterns pre-segmented for O(1)-ish matching.
#[derive(Debug, Clone)]
pub struct Matcher {
    pub id: String,
    pub cwe: u32,
    pub title: String,
    pub sink_shape: SinkShape,
    pub callee_patterns: Vec<CalleePattern>,
    pub arg_index: u32,
    pub evidence_template: String,
    pub import_provenance: Option<String>,
    /// Framework enabler package gate (issue #861). `None` = global row.
    /// `Some("pkg")` requires an exact dependency match; `Some("@scope/")`
    /// (trailing slash) requires any dependency under that prefix.
    pub enabler: Option<String>,
    /// Resolved allowlist of admitted argument shapes. `None` admits any
    /// non-literal shape; `Some` requires the captured `arg_kind` to be listed.
    pub arg_kinds: Option<Vec<SinkArgKind>>,
}

/// The parsed catalogue: an ordered list of matchers. Order is preserved from
/// the TOML so the detector can break on the first match deterministically.
#[derive(Debug)]
pub struct Catalogue {
    matchers: Vec<Matcher>,
}

impl Matcher {
    /// The first callee pattern that matches the given path, if any. The first
    /// match wins, matching the deterministic declaration order.
    #[must_use]
    pub fn first_matching_pattern(&self, callee_path: &str) -> Option<&CalleePattern> {
        self.callee_patterns.iter().find(|p| p.matches(callee_path))
    }

    /// Whether a captured argument shape is admitted by this matcher. `None`
    /// `arg_kinds` admits any shape; `Some` requires the kind to be listed.
    #[must_use]
    pub fn admits_arg_kind(&self, arg_kind: SinkArgKind) -> bool {
        self.arg_kinds
            .as_ref()
            .is_none_or(|kinds| kinds.contains(&arg_kind))
    }

    /// Whether this matcher's framework enabler is satisfied by the project's
    /// declared dependency set (issue #861). `None` enabler is always satisfied
    /// (a global row). A `Some` enabler matches by exact package name, or, when
    /// it ends with `/`, by prefix (`@angular/` matches `@angular/platform-browser`),
    /// mirroring the plugin-system `enablers()` semantics so framework rows
    /// activate on exactly the dependency universe the plugins do.
    #[must_use]
    pub fn enabler_satisfied(&self, declared_deps: &rustc_hash::FxHashSet<String>) -> bool {
        let Some(enabler) = &self.enabler else {
            return true;
        };
        if let Some(prefix) = enabler.strip_suffix('/') {
            // Trailing-slash prefix match, e.g. `@fastify/` -> `@fastify/static`.
            // Also admit the bare scope name itself (`@fastify`).
            declared_deps
                .iter()
                .any(|d| d == prefix || d.starts_with(enabler))
        } else {
            declared_deps.contains(enabler)
        }
    }
}

impl Catalogue {
    /// All matchers in declaration order.
    #[must_use]
    pub fn matchers(&self) -> &[Matcher] {
        &self.matchers
    }

    /// The human-readable title for a category id, if any matcher declares it.
    #[must_use]
    pub fn title_for(&self, id: &str) -> Option<&str> {
        self.matchers
            .iter()
            .find(|m| m.id == id)
            .map(|m| m.title.as_str())
    }
}

/// The human-readable title for a category id, used by the CLI renderer.
#[must_use]
pub fn catalogue_title(id: &str) -> Option<&'static str> {
    catalogue().title_for(id)
}

/// Resolve a kebab-case sink-shape string into the typed [`SinkShape`].
fn parse_sink_shape(s: &str) -> Option<SinkShape> {
    match s {
        "call" => Some(SinkShape::Call),
        "member-call" => Some(SinkShape::MemberCall),
        "member-assign" => Some(SinkShape::MemberAssign),
        "tagged-template" => Some(SinkShape::TaggedTemplate),
        "jsx-attr" => Some(SinkShape::JsxAttr),
        _ => None,
    }
}

/// Resolve a kebab-case arg-kind string into the typed [`SinkArgKind`].
fn parse_arg_kind(s: &str) -> Option<SinkArgKind> {
    match s {
        "template-with-subst" => Some(SinkArgKind::TemplateWithSubst),
        "concat" => Some(SinkArgKind::Concat),
        "object" => Some(SinkArgKind::Object),
        "call" => Some(SinkArgKind::Call),
        "other" => Some(SinkArgKind::Other),
        _ => None,
    }
}

/// Parse + validate the catalogue source. Returns a `Result` (NOT a panic) so
/// the validation tests can assert on error messages; `catalogue()` unwraps it.
///
/// Validates: non-empty id; cwe > 0; sink_shape resolves; callee_patterns
/// non-empty and every pattern non-empty/non-whitespace; non-empty
/// evidence_template.
fn parse_catalogue(src: &str) -> Result<Catalogue, String> {
    let raw: RawCatalogue =
        toml::from_str(src).map_err(|e| format!("security_matchers.toml parse error: {e}"))?;

    let mut matchers = Vec::with_capacity(raw.matcher.len());
    for entry in raw.matcher {
        if entry.id.trim().is_empty() {
            return Err("matcher id must be non-empty / non-whitespace".to_string());
        }
        if entry.cwe == 0 {
            return Err(format!("matcher {:?} has cwe 0; cwe must be > 0", entry.id));
        }
        let sink_shape = parse_sink_shape(&entry.sink_shape).ok_or_else(|| {
            format!(
                "matcher {:?} has unknown sink_shape {:?}; expected one of \
                 call | member-call | member-assign | tagged-template | jsx-attr",
                entry.id, entry.sink_shape
            )
        })?;
        if entry.callee_patterns.is_empty() {
            return Err(format!(
                "matcher {:?} has no callee_patterns; at least one is required",
                entry.id
            ));
        }
        if entry.evidence_template.trim().is_empty() {
            return Err(format!(
                "matcher {:?} has an empty evidence_template",
                entry.id
            ));
        }
        let mut callee_patterns = Vec::with_capacity(entry.callee_patterns.len());
        for pat in &entry.callee_patterns {
            let parsed = parse_callee_pattern(pat).ok_or_else(|| {
                format!(
                    "matcher {:?} has an empty / whitespace callee_pattern {pat:?}",
                    entry.id
                )
            })?;
            callee_patterns.push(parsed);
        }
        let arg_kinds = match &entry.arg_kinds {
            None => None,
            Some(raw_kinds) => {
                if raw_kinds.is_empty() {
                    return Err(format!(
                        "matcher {:?} has an empty arg_kinds list; omit the key to admit any shape",
                        entry.id
                    ));
                }
                let mut kinds = Vec::with_capacity(raw_kinds.len());
                for raw in raw_kinds {
                    let kind = parse_arg_kind(raw).ok_or_else(|| {
                        format!(
                            "matcher {:?} has unknown arg_kind {raw:?}; expected one of \
                             template-with-subst | concat | object | call | other",
                            entry.id
                        )
                    })?;
                    kinds.push(kind);
                }
                Some(kinds)
            }
        };
        let enabler = match entry.enabler {
            Some(e) if e.trim().is_empty() => {
                return Err(format!(
                    "matcher {:?} has an empty / whitespace enabler; omit the key for a global row",
                    entry.id
                ));
            }
            other => other,
        };
        matchers.push(Matcher {
            id: entry.id,
            cwe: entry.cwe,
            title: entry.title,
            sink_shape,
            callee_patterns,
            arg_index: entry.arg_index,
            evidence_template: entry.evidence_template,
            import_provenance: entry.import_provenance,
            enabler,
            arg_kinds,
        });
    }

    if matchers.is_empty() {
        return Err("security_matchers.toml has no [[matcher]] entries".to_string());
    }

    Ok(Catalogue { matchers })
}

/// Parse and cache the embedded catalogue once. Unwraps the parse `Result`; in
/// a released binary this is unreachable because the bytes are compile-time
/// embedded and gated by `security_catalogue_parses`.
#[expect(
    clippy::expect_used,
    reason = "compile-time-embedded catalogue pinned by security_catalogue_parses"
)]
pub fn catalogue() -> &'static Catalogue {
    static CATALOGUE: std::sync::OnceLock<Catalogue> = std::sync::OnceLock::new();
    CATALOGUE.get_or_init(|| {
        parse_catalogue(CATALOGUE_TOML).expect(
            "embedded crates/core/data/security_matchers.toml must parse; run \
             `cargo test -p fallow-core security_catalogue_parses` to see the error",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashSet;

    #[test]
    fn security_catalogue_parses() {
        let cat = catalogue();
        assert!(!cat.matchers().is_empty(), "catalogue must have matchers");
        assert!(
            cat.matchers().iter().any(|m| m.id == "dangerous-html"),
            "catalogue must contain the dangerous-html seed"
        );
    }

    #[test]
    fn catalogue_rows_are_unique() {
        // Multiple rows legitimately share an `id` (dangerous-html spans three
        // shapes), so uniqueness is keyed on the FULL row: id + sink_shape +
        // callee_patterns. No two identical matcher rows. Keyed off the raw
        // source so the test does not require `SinkShape: Hash`.
        let raw: RawCatalogue = toml::from_str(CATALOGUE_TOML).unwrap();
        let mut seen = FxHashSet::default();
        for m in &raw.matcher {
            let pats = m.callee_patterns.join("|");
            // Uniqueness includes the enabler: framework-scoped rows (#861) may
            // legitimately share id + shape + patterns and differ only by their
            // framework gate (e.g. one `route-send-file` row per framework).
            let enabler = m.enabler.as_deref().unwrap_or("");
            let key = format!("{}::{}::{pats}::{enabler}", m.id, m.sink_shape);
            assert!(seen.insert(key.clone()), "duplicate matcher row: {key}");
        }
    }

    #[test]
    fn catalogue_ids_non_empty() {
        for m in catalogue().matchers() {
            assert!(
                !m.id.trim().is_empty(),
                "matcher id must be non-empty / non-whitespace"
            );
        }
    }

    #[test]
    fn catalogue_cwe_valid() {
        for m in catalogue().matchers() {
            assert!(m.cwe > 0, "matcher {:?} has cwe 0", m.id);
        }
    }

    #[test]
    fn catalogue_sink_shapes_known() {
        // Every parsed matcher already carries a typed SinkShape, so re-parse
        // the raw source to assert the kebab strings all resolve.
        let raw: RawCatalogue = toml::from_str(CATALOGUE_TOML).unwrap();
        for m in &raw.matcher {
            assert!(
                parse_sink_shape(&m.sink_shape).is_some(),
                "matcher {:?} has unknown sink_shape {:?}",
                m.id,
                m.sink_shape
            );
        }
    }

    #[test]
    fn catalogue_callee_patterns_non_empty() {
        for m in catalogue().matchers() {
            assert!(
                !m.callee_patterns.is_empty(),
                "matcher {:?} has no callee_patterns",
                m.id
            );
            for p in &m.callee_patterns {
                assert!(
                    !p.raw().trim().is_empty(),
                    "matcher {:?} has an empty callee_pattern",
                    m.id
                );
            }
        }
    }

    #[test]
    fn catalogue_evidence_templates_non_empty() {
        for m in catalogue().matchers() {
            assert!(
                !m.evidence_template.trim().is_empty(),
                "matcher {:?} has an empty evidence_template",
                m.id
            );
        }
    }

    #[test]
    fn parse_rejects_empty_id() {
        let toml = r#"
[[matcher]]
id = ""
cwe = 79
title = "x"
sink_shape = "member-assign"
callee_patterns = ["*.innerHTML"]
arg_index = 0
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("id must be non-empty"), "got: {err}");
    }

    #[test]
    fn parse_rejects_zero_cwe() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 0
title = "x"
sink_shape = "member-assign"
callee_patterns = ["*.innerHTML"]
arg_index = 0
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("cwe"), "got: {err}");
    }

    #[test]
    fn parse_rejects_unknown_sink_shape() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 79
title = "x"
sink_shape = "not-a-shape"
callee_patterns = ["*.innerHTML"]
arg_index = 0
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("unknown sink_shape"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_callee_patterns() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 79
title = "x"
sink_shape = "member-assign"
callee_patterns = []
arg_index = 0
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("callee_patterns"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_pattern_string() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 79
title = "x"
sink_shape = "member-assign"
callee_patterns = ["   "]
arg_index = 0
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_evidence_template() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 79
title = "x"
sink_shape = "member-assign"
callee_patterns = ["*.innerHTML"]
arg_index = 0
evidence_template = "   "
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("evidence_template"), "got: {err}");
    }

    #[test]
    fn parse_rejects_no_matchers() {
        let err = parse_catalogue("").unwrap_err();
        assert!(err.contains("no [[matcher]]"), "got: {err}");
    }

    #[test]
    fn segment_match_is_not_substring() {
        let bare = parse_callee_pattern("fetch").unwrap();
        assert!(bare.matches("fetch"));
        assert!(!bare.matches("myfetch"));
        assert!(!bare.matches("fetcher"));

        let wildcard = parse_callee_pattern("*.innerHTML").unwrap();
        assert!(wildcard.matches("el.innerHTML"));
        assert!(wildcard.matches("this.node.innerHTML"));
        assert!(!wildcard.matches("el.innerHTMLFoo"));
        assert!(!wildcard.matches("innerHTML")); // wildcard requires an object

        let dotted = parse_callee_pattern("child_process.exec").unwrap();
        assert!(dotted.matches("child_process.exec"));
        assert!(!dotted.matches("exec"));
        assert!(!dotted.matches("child_process.execSync"));
        assert!(!dotted.matches("my_child_process.exec"));
    }

    #[test]
    fn wildcard_only_pattern_matches_nothing() {
        // Guard against a degenerate `*` pattern matching every callee.
        let star = parse_callee_pattern("*").unwrap();
        assert!(!star.matches("el.innerHTML"));
        assert!(!star.matches("anything"));
    }

    #[test]
    fn arg_kinds_unset_admits_any_shape() {
        // A matcher with no arg_kinds (e.g. dangerous-html) admits every shape.
        let html = catalogue()
            .matchers()
            .iter()
            .find(|m| m.id == "dangerous-html")
            .expect("dangerous-html present");
        for kind in [
            SinkArgKind::TemplateWithSubst,
            SinkArgKind::Concat,
            SinkArgKind::Object,
            SinkArgKind::Call,
            SinkArgKind::Other,
        ] {
            assert!(html.admits_arg_kind(kind), "html admits {kind:?}");
        }
    }

    #[test]
    fn sql_injection_query_execute_excludes_object_arg_kind() {
        // The `.query` / `.execute` matchers must require unsafe shapes (concat /
        // interpolated template) and reject the parameterized object-literal form
        // (`.execute({ sql, args })`). The separate `sql.raw` escape-hatch row is
        // intentionally shape-agnostic and is excluded from this check.
        let query_matchers: Vec<&Matcher> = catalogue()
            .matchers()
            .iter()
            .filter(|m| {
                m.id == "sql-injection"
                    && m.callee_patterns
                        .iter()
                        .any(|p| p.raw() == "*.query" || p.raw() == "*.execute")
            })
            .collect();
        assert!(
            !query_matchers.is_empty(),
            "sql-injection .query/.execute rows present"
        );
        for m in query_matchers {
            let kinds = m
                .arg_kinds
                .as_ref()
                .unwrap_or_else(|| panic!("sql-injection query/execute must constrain arg_kinds"));
            assert!(
                !kinds.contains(&SinkArgKind::Object),
                "sql-injection .query/.execute must not admit the object (parameterized) form"
            );
            assert!(
                !m.admits_arg_kind(SinkArgKind::Object),
                "admits_arg_kind agrees: object excluded"
            );
            assert!(
                m.admits_arg_kind(SinkArgKind::Concat),
                "sql-injection .query/.execute admits the concat (unsafe) form"
            );
        }
    }

    #[test]
    fn parse_rejects_unknown_arg_kind() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 89
title = "x"
sink_shape = "member-call"
callee_patterns = ["*.query"]
arg_index = 0
arg_kinds = ["not-a-kind"]
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("unknown arg_kind"), "got: {err}");
    }

    #[test]
    fn enabler_unset_is_global() {
        // A matcher with no enabler is satisfied by ANY (even empty) dep set.
        let html = catalogue()
            .matchers()
            .iter()
            .find(|m| m.id == "dangerous-html")
            .expect("dangerous-html present");
        assert!(html.enabler.is_none(), "dangerous-html is a global row");
        assert!(html.enabler_satisfied(&FxHashSet::default()));
    }

    #[test]
    fn enabler_satisfied_exact_and_prefix() {
        let mut m = catalogue()
            .matchers()
            .iter()
            .find(|m| m.id == "dangerous-html")
            .cloned()
            .expect("dangerous-html present");

        // Exact match.
        m.enabler = Some("jquery".to_string());
        let mut deps = FxHashSet::default();
        assert!(!m.enabler_satisfied(&deps), "absent dep is not satisfied");
        deps.insert("jquery".to_string());
        assert!(m.enabler_satisfied(&deps), "present exact dep satisfies");

        // Trailing-slash prefix match, plus the bare scope name.
        m.enabler = Some("@angular/".to_string());
        let mut scoped = FxHashSet::default();
        assert!(!m.enabler_satisfied(&scoped));
        scoped.insert("@angular/platform-browser".to_string());
        assert!(m.enabler_satisfied(&scoped), "prefix dep satisfies");
        let mut bare_scope = FxHashSet::default();
        bare_scope.insert("@angular".to_string());
        assert!(
            m.enabler_satisfied(&bare_scope),
            "bare scope name satisfies the prefix form"
        );

        // A near-miss exact name does not satisfy a prefix-less enabler.
        m.enabler = Some("react".to_string());
        let mut reactish = FxHashSet::default();
        reactish.insert("react-dom".to_string());
        assert!(
            !m.enabler_satisfied(&reactish),
            "exact enabler must not prefix-match"
        );
    }

    #[test]
    fn framework_scoped_rows_are_present() {
        // The framework-scoped rows added in #861 carry an enabler.
        let cat = catalogue();
        let angular = cat
            .matchers()
            .iter()
            .find(|m| m.id == "angular-trusted-html")
            .expect("angular-trusted-html present");
        assert_eq!(
            angular.enabler.as_deref(),
            Some("@angular/platform-browser")
        );
        assert!(
            cat.matchers().iter().any(|m| m.id == "jquery-html"),
            "jquery-html present"
        );
        assert!(
            cat.matchers().iter().any(|m| m.id == "dom-document-write"),
            "dom-document-write present"
        );
    }

    #[test]
    fn parse_rejects_empty_enabler() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 79
title = "x"
sink_shape = "member-call"
callee_patterns = ["*.html"]
arg_index = 0
enabler = "   "
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("empty / whitespace enabler"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_arg_kinds() {
        let toml = r#"
[[matcher]]
id = "x"
cwe = 89
title = "x"
sink_shape = "member-call"
callee_patterns = ["*.query"]
arg_index = 0
arg_kinds = []
evidence_template = "x"
"#;
        let err = parse_catalogue(toml).unwrap_err();
        assert!(err.contains("empty arg_kinds"), "got: {err}");
    }
}
