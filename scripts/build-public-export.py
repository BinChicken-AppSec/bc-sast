#!/usr/bin/env python3
"""Build the public export tree from this repository.

The private repository is the source of truth and correctly describes
itself, including the internal deployment infrastructure it carries. The
public repository ships the scanner only, so a handful of passages that
are accurate here are wrong there, and a handful of documents must not
travel at all.

Doing that by hand does not survive: the same corrections were applied
once by hand and reappeared on the next export, because nothing recorded
them. This script is that record. Every exclusion and every rewrite below
is a decision, not a detail, so change it deliberately.

Usage: python3 scripts/build-public-export.py <destination>
"""
import pathlib
import shutil
import subprocess
import sys

# Paths that must never reach the public repository.
EXCLUDE = [
    "terraform",                                  # our own AWS infrastructure
    ".github/workflows/deploy-dev-aws.yml",       # our deploy pipeline
    ".github/workflows/terraform-apply.yml",      # our infrastructure pipeline
    "docs/discovered-execution-verification.md",  # internal verification record
    "docs/provider-writeback-plan.md",            # internal roadmap and pilots
    # Raw image-generation prompt transcripts. Kept here as provenance for the
    # artwork, but a published repository has no use for the prompts that made
    # its diagrams, and README discloses that they are AI-generated anyway.
    "docs/infographics/prompts.json",
    "docs/infographics/edit-prompts.json",
    "TODO.md",                                    # internal follow-ups; names the
                                                  # private demo repo, and the public
                                                  # statement of limits is README's
                                                  # Status section
]

# Passages that are true in the private repository and false in the public
# one, each as (file, old, new). An exact single match is required, so a
# reword upstream fails the export loudly instead of silently skipping.
REWRITES = [
    ("README.md",
     "`terraform/` is an **optional internal example** of the registry half of",
     "Deployment infrastructure is not published here. The registry half of"),
    ("docs/solution-design.md",
     "`terraform/` in this repo is an optional internal example of the registry",
     "Deployment infrastructure is not published here; the guide covers the registry"),
    ("docs/deployment.md",
     "`terraform/` directory in this repo is an **optional internal example** of",
     "deployment infrastructure behind it is yours to choose. This repository covers"),
    ("docs/deployment.md",
     "ships code only: no `terraform/`, no deploy/apply workflows.",
     "ships the scanner only: no deploy or apply workflows."),
    ("action.yml",
     "  # CI does push a built image to AWS ECR (see terraform/README.md), but\n"
     "  # ECR is private/authenticated, so it can't serve as this action's\n"
     "  # default image reference for arbitrary external consumers either.",
     "  # A private authenticated registry cannot serve as a default image\n"
     "  # reference for arbitrary consumers either. Publish your own image and\n"
     "  # pin it by digest if you would rather not build on the runner."),
    ("docs/target-testing.md",
     "See the [verification record](discovered-execution-verification.md) for\n"
     "executed checks, coverage results, and unverified operational scope.",
     "Note the operational scope: the authorization, refusal and classification\n"
     "paths are covered by tests, while the container execution path itself has\n"
     "not yet been observed running against a live engine."),
    ("docs/provider-writeback.md",
     "native scan findings. See the [research and rollout plan](provider-writeback-plan.md)\n"
     "for API sources, scope details, and empirical evaluation criteria.",
     "native scan findings."),
]

# Whole lines to drop, matched by a unique substring.
DROP_LINES = [
    ("docs/README.md", "- [`provider-writeback-plan.md`](provider-writeback-plan.md)", 2),
    ("docs/README.md", "- `../terraform/`, an **optional internal example**", 4),
]


# Commit-author addresses that may appear in a history this repository could
# ever publish. The export itself never carries history (see `git archive`
# below), so an address outside this set is not a leak in the exported tree;
# it is a warning that publishing this repository's *history* instead of an
# export would de-anonymize the maintainer.
ANONYMOUS_AUTHORS = {
    "189714617+BinChickens@users.noreply.github.com",
    "BinChickens69@users.noreply.github.com",
    "noreply@anthropic.com",
}


def audit_commit_authors(repo: pathlib.Path) -> list[str]:
    """Addresses in this repository's history that are not anonymous.

    Reported, not fatal. The export is a tree snapshot, so these never reach
    the exported files; the check exists because the one publish path that
    *would* carry them is a plain `git push` of this repository, and a
    warning here is where someone about to publish will actually see it.
    """
    log = subprocess.run(
        ["git", "-C", str(repo), "log", "--all", "--format=%ae"],
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted({a for a in log.stdout.split() if a and a not in ANONYMOUS_AUTHORS})


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    dest = pathlib.Path(sys.argv[1]).resolve()
    repo = pathlib.Path(__file__).resolve().parent.parent

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    # Tracked files only. rsync would copy ignored build output and local
    # virtualenvs, which is how a Python venv full of compiled objects once
    # ended up staged for publication.
    archive = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=repo, check=True, capture_output=True).stdout
    subprocess.run(["tar", "xf", "-"], cwd=dest, input=archive, check=True)

    for rel in EXCLUDE:
        target = dest / rel
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        else:
            print(f"note: nothing to exclude at {rel}")

    for rel, old, new in REWRITES:
        path = dest / rel
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            print(f"ERROR: {rel}: expected exactly one match, found {text.count(old)}")
            print("       The upstream text changed. Update this script rather than")
            print("       letting an inaccurate passage reach the public repository.")
            return 1
        path.write_text(text.replace(old, new), encoding="utf-8")

    for rel, needle, count in DROP_LINES:
        path = dest / rel
        lines = path.read_text(encoding="utf-8").split("\n")
        hits = [i for i, line in enumerate(lines) if needle in line]
        if len(hits) != 1:
            print(f"ERROR: {rel}: expected one line containing {needle!r}, found {len(hits)}")
            return 1
        del lines[hits[0]:hits[0] + count]
        path.write_text("\n".join(lines), encoding="utf-8")

    print(f"exported {sum(1 for _ in dest.rglob('*') if _.is_file())} files to {dest}")

    leaks = audit_commit_authors(repo)
    if leaks:
        print(
            "\nNOTE: this repository's history carries commit authors that are not\n"
            "anonymous. The exported tree above does NOT contain them, because the\n"
            "export is a tree snapshot. Publish the export, never this repository's\n"
            "history, and keep this repository private:",
            file=sys.stderr,
        )
        for address in leaks:
            print(f"  {address}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
