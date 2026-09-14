//! The jailed local `ToolExecutor`, ported from
//! `vvaharness/backends/localtools.py`. `Read`/`Glob`/`Grep` are always
//! available; `Edit`/`Write` are offered only when constructed via
//! [`SandboxTools::new_with_write`] (Phase 2's S10 remediation stage) —
//! every other consumer in this workspace gets the read-only
//! construction and structurally never sees a mutating tool in
//! `available_tools()` at all. `Bash` is never offered either way; a host
//! shell would defeat the `root` jail on prompt-injected/untrusted
//! targets.
//!
//! A write-capable executor additionally keeps a [`WriteJournal`]: a
//! copy-on-first-write ledger of every path it mutated and what that path
//! contained beforehand. That ledger is what makes S10's safety gates able
//! to put the working tree back exactly as they found it — see the
//! journal's own module doc comment for why the pre-agent snapshot alone
//! was never enough.

//! On top of those generic readers, [`FactTools`] wraps any read-only
//! executor with the five deterministic **fact tools** the Python
//! original's validation personas get (`DiffTouched`, `ChangedLines`,
//! `DiffImpactMap`, `PatternScan`, `TestInventory` — see [`facts`]).
//! Nothing outside `bc_stage_s11` constructs it, so an S1/S6/S10 session's
//! tool list is unchanged.

mod control_path;
mod edit;
mod executor;
mod facts;
mod glob;
mod grep;
mod journal;
mod read;
mod schema;
mod walk;
mod write;

pub use executor::SandboxTools;
pub use facts::{
    changed_lines, diff_impact_map, diff_touched, parse_diff_patch, pattern_scan, test_inventory,
    FactTools, FileChange, FACT_TOOL_NAMES,
};
pub use journal::WriteJournal;
