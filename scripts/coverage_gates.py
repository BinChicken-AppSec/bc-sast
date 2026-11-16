"""Run every coverage gate CI runs, locally, in one pass.

Known local-only failure: the workspace gate wants 100% functions and reports
slightly fewer on macOS than on Linux, because some generic instantiations
differ by platform -- the same reason `appsec-enrich/src/cmdb.rs` has a
documented macOS-only gap. CI is the authority on that one gate; a function
shortfall there of one or two instantiations, with no per-file gap that
`coverage_gaps.py` can name, is this, not a regression.

CI has thirteen separate llvm-cov gates: one for the workspace minus the
excluded crates, and one per excluded crate with its own thresholds. Running
only the workspace gate locally and pushing has failed CI twice, because a
crate excluded from the workspace gate still has a gate of its own.

The gate commands are read out of .github/workflows/ci.yml rather than copied
here, so this cannot drift from what CI actually enforces. The one thing it
changes is the output: --lcov is swapped for --summary-only, because the
thresholds are what matters locally and the lcov files are for the runner.

Usage:
    python3 scripts/coverage_gates.py            # every gate
    python3 scripts/coverage_gates.py mcp orch   # gates whose command matches
"""

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
CI = REPO / ".github" / "workflows" / "ci.yml"


def gate_commands() -> list[tuple[str, str]]:
    text = CI.read_text(encoding="utf-8")

    env = {}
    for name, value in re.findall(r'echo "(BC_COV_[A-Z]+)=(.*?)" >> "\$GITHUB_ENV"', text):
        env[name] = value

    gates = []
    for name, body in re.findall(
        r"- name: (cargo llvm-cov [^\n]*)\n(.*?)(?=\n      - name:|\n  [a-z-]+:|\Z)",
        text,
        re.S,
    ):
        run = re.search(r"\n        run: \|\n(.*?)(?=\n      -|\Z)", body, re.S)
        if not run:
            continue
        lines = [line.strip() for line in run.group(1).split("\n")]
        joined = " ".join(line for line in lines if line and not line.startswith("#"))
        joined = joined.replace("\\", " ")
        start = joined.find("cargo llvm-cov")
        if start == -1:
            continue
        command = joined[start:]
        for key, value in env.items():
            command = command.replace(f"${key}", value).replace(f'"${key}"', value)
        if "$" in command:
            print(f"SKIP  {name}\n      unexpanded variable in: {command}")
            continue
        command = re.sub(r"--lcov --output-path \S+", "--summary-only", command)
        command = re.sub(r"--json --output-path \S+", "--summary-only", command)
        if "--summary-only" not in command:
            command += " --summary-only"
        gates.append((name, command))
    return gates


def main() -> int:
    wanted = [a.lower() for a in sys.argv[1:]]
    gates = gate_commands()
    if not gates:
        print("ERROR: no gates parsed from ci.yml; the workflow shape changed")
        return 2

    # Matched against the gate NAME only. The workspace gate's command lists
    # every excluded crate, so matching the command made "orchestrator" select
    # the workspace gate too.
    selected = [
        (name, cmd)
        for name, cmd in gates
        if not wanted or any(w in name.lower() for w in wanted)
    ]
    if not selected:
        print(f"no gate matched {wanted}; {len(gates)} available:")
        for name, _ in gates:
            print(f"  {name}")
        return 2

    print(f"running {len(selected)} of {len(gates)} gate(s)\n")
    failures = []
    for name, command in selected:
        print(f"--- {name}")
        # Each gate starts from no profdata. `cargo llvm-cov clean` does not
        # remove all of it, and profdata left by a previous gate attributes
        # coverage to files this gate measures -- which inflates the number and
        # can turn a real shortfall into a pass.
        for stale in ("target/llvm-cov-target", "target/llvm-cov"):
            subprocess.run(["rm", "-rf", stale], cwd=REPO, check=True)
        result = subprocess.run(
            command, shell=True, cwd=REPO, capture_output=True, text=True
        )
        total = [l for l in result.stdout.split("\n") if l.startswith("TOTAL")]
        if total:
            print("    " + re.sub(r"\s+", " ", total[0]).strip())
        if result.returncode != 0:
            failures.append(name)
            print(f"    FAILED (exit {result.returncode})")
            for line in (result.stdout + result.stderr).split("\n"):
                if "error" in line.lower() or "uncovered" in line.lower():
                    print(f"    {line.strip()}")
        else:
            print("    ok")

    print()
    if failures:
        print(f"{len(failures)} gate(s) failed:")
        for name in failures:
            print(f"  {name}")
        return 1
    print(f"all {len(selected)} gate(s) pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
