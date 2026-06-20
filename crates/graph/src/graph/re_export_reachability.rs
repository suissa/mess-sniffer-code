use rustc_hash::FxHashSet;

use fallow_types::discover::FileId;

use super::ModuleGraph;

/// Walk forward through named re-export edges from `(seed_file, seed_name)`.
/// Returns every reachable `(barrel_file_id, exported_name_at_barrel)` pair,
/// including the seed. Star namespace re-exports are intentionally not followed
/// because they hide the original identifier behind a namespace object.
pub(super) fn enumerate_reachable_barrels(
    graph: &ModuleGraph,
    seed_file: FileId,
    seed_name: &str,
) -> FxHashSet<(FileId, String)> {
    let mut reachable: FxHashSet<(FileId, String)> = FxHashSet::default();
    reachable.insert((seed_file, seed_name.to_string()));
    let mut frontier: Vec<(FileId, String)> = vec![(seed_file, seed_name.to_string())];

    while let Some((source_file, source_name)) = frontier.pop() {
        for (idx, module) in graph.modules.iter().enumerate() {
            for edge in &module.re_exports {
                if edge.source_file != source_file {
                    continue;
                }
                let exported_name = if edge.imported_name == source_name {
                    edge.exported_name.clone()
                } else if edge.imported_name == "*" && edge.exported_name == "*" {
                    source_name.clone()
                } else {
                    continue;
                };
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "file count is bounded by project size, well under u32::MAX"
                )]
                let barrel_file = FileId(idx as u32);
                let pair = (barrel_file, exported_name);
                if reachable.insert(pair.clone()) {
                    frontier.push(pair);
                }
            }
        }
    }

    reachable
}
