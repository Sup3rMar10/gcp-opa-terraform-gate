"""The step a pipeline runs: python tools/gate.py DIR [--recursive]

Merges the .tf files of a directory into one configuration (so a rule can see a bucket in one file and its IAM binding in
another), converts it to JSON, evaluates the policies, prints every denial and warning, and exits 1 if anything is denied.
Warnings print but never fail the gate.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from run_matrix import ToolError, evaluate, to_json


def merged_json(directory: Path, recursive: bool = False) -> str:
    files = sorted(directory.rglob("*.tf") if recursive else directory.glob("*.tf"))
    if not files:
        raise ToolError(f"no .tf files in {directory}")
    text = "\n".join(f.read_text(encoding="utf-8") for f in files)
    with tempfile.TemporaryDirectory() as tmp:
        merged = Path(tmp) / "merged.tf"
        merged.write_text(text, encoding="utf-8")
        return to_json(merged)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gate")
    p.add_argument("directory", type=Path)
    p.add_argument("--recursive", action="store_true")
    a = p.parse_args(argv)
    try:
        doc = merged_json(a.directory, a.recursive)
        denied = evaluate(doc, "data.gcp.terraform.deny")
        warned = evaluate(doc, "data.gcp.terraform.warn")
    except ToolError as e:
        print(f"ERROR: {e}")
        return 2  # a gate that could not run is not a gate that passed
    for m in warned:
        print(f"warn  {m}")
    for m in denied:
        print(f"DENY  {m}")
    print(f"{len(denied)} denial(s), {len(warned)} warning(s)")
    return 1 if denied else 0


if __name__ == "__main__":
    sys.exit(main())
