"""Run every policy against every fixture and compare with what is expected.

Terraform -> JSON with hcl2json, then `opa eval` on data.gcp.terraform.deny. The set of rule IDs found must equal the
expected set EXACTLY: a missed violation fails, and so does a rule that fires on something it should leave alone.
Any tool failure (HCL that will not parse, OPA erroring) is an ERROR, never "no violations": an unreadable file must not
look compliant.

    python tools/run_matrix.py        (exit 1 on any mismatch)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID = re.compile(r"^\[([A-Z]+-\d+)\]")


class ToolError(Exception):
    pass


def to_json(tf: Path) -> str:
    p = subprocess.run(["hcl2json", str(tf)], capture_output=True, text=True)
    if p.returncode != 0:
        raise ToolError(f"hcl2json failed on {tf.name}: {p.stderr.strip()[:200]}")
    return p.stdout


def evaluate(doc: str, query: str = "data.gcp.terraform.deny") -> list[str]:
    p = subprocess.run(["opa", "eval", "-d", str(ROOT / "policy"), "--stdin-input", "--format", "json", query],
                       input=doc, capture_output=True, text=True)
    if p.returncode != 0:
        raise ToolError(f"opa failed: {p.stderr.strip()[:300] or p.stdout[:300]}")
    result = json.loads(p.stdout).get("result")
    if not result:
        return []  # the rule produced no set: nothing was denied
    return sorted(result[0]["expressions"][0]["value"])


def rule_ids(messages: list[str]) -> list[str]:
    ids = []
    for m in messages:
        found = ID.match(m)
        if not found:
            raise ToolError(f"a message without a rule id: {m!r}")
        ids.append(found.group(1))
    return sorted(set(ids))


def check_file(tf: Path) -> list[str]:
    return rule_ids(evaluate(to_json(tf)))


def run(root: Path = ROOT) -> list[str]:
    """Return a list of mismatch descriptions; empty means every fixture behaved as expected."""
    expected = json.loads((root / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    problems = []
    for tf in sorted((root / "fixtures" / "good").glob("*.tf")):
        try:
            got = check_file(tf)
        except ToolError as e:
            problems.append(f"ERROR {tf.name}: {e}")
            continue
        if got:
            problems.append(f"UNEXPECTED good/{tf.name}: {got}")
    seen = set()
    for tf in sorted((root / "fixtures" / "bad").glob("*.tf")):
        seen.add(tf.stem)
        want = expected.get(tf.stem)
        if want is None:
            problems.append(f"NO EXPECTATION for bad/{tf.name}")
            continue
        try:
            got = check_file(tf)
        except ToolError as e:
            problems.append(f"ERROR {tf.name}: {e}")
            continue
        if got != sorted(want):
            problems.append(f"WRONG bad/{tf.name}: got {got}, expected {sorted(want)}")
    for name in sorted(set(expected) - seen):
        problems.append(f"MISSING fixture for expectation {name}")
    return problems


if __name__ == "__main__":
    issues = run()
    for line in issues:
        print(line)
    n_good = len(list((ROOT / "fixtures" / "good").glob("*.tf")))
    n_bad = len(list((ROOT / "fixtures" / "bad").glob("*.tf")))
    print(f"{n_good} good and {n_bad} bad fixtures checked: {len(issues)} problem(s)")
    sys.exit(1 if issues else 0)
