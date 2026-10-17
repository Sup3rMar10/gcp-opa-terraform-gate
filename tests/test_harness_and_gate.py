"""Tests of the test machinery itself: the matrix must be able to fail, and the gate must fail closed."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import gate  # noqa: E402
import run_matrix  # noqa: E402

needs_tools = pytest.mark.skipif(not (shutil.which("opa") and shutil.which("hcl2json")), reason="needs the opa and hcl2json binaries")

# Rules whose findings are warnings: covered by the Rego unit tests, not by a failing fixture.
WARN_ONLY = {"GCS-004", "IAM-004"}


@needs_tools
def test_every_fixture_behaves_as_expected():
    assert run_matrix.run() == []


def test_every_deny_rule_has_a_bad_fixture_and_every_expectation_names_a_real_rule():
    policy_text = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "policy").glob("*.rego") if not p.name.endswith("_test.rego"))
    rule_ids = set(re.findall(r'"\[([A-Z]+-\d{3})\]', policy_text))
    expected = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    covered = {i for ids in expected.values() for i in ids}
    assert rule_ids - WARN_ONLY <= covered, f"rules with no failing fixture: {sorted(rule_ids - WARN_ONLY - covered)}"
    assert covered <= rule_ids, f"expectations for rules that do not exist: {sorted(covered - rule_ids)}"


def test_each_rule_has_at_least_two_different_ways_to_trigger_it_or_a_documented_reason():
    expected = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    from collections import Counter
    counts = Counter(i for ids in expected.values() for i in ids)
    single = {i for i, n in counts.items() if n < 2}
    assert single <= {"IAM-003", "GKE-001", "GKE-002", "GKE-003", "SQL-002"}, f"thinly tested rules: {sorted(single)}"


# --- the matrix can fail ---------------------------------------------------------------------------------------


def make_root(tmp_path, good=None, bad=None, expected=None):
    (tmp_path / "fixtures" / "good").mkdir(parents=True)
    (tmp_path / "fixtures" / "bad").mkdir(parents=True)
    for name, text in (good or {}).items():
        (tmp_path / "fixtures" / "good" / f"{name}.tf").write_text(text, encoding="utf-8")
    for name, text in (bad or {}).items():
        (tmp_path / "fixtures" / "bad" / f"{name}.tf").write_text(text, encoding="utf-8")
    (tmp_path / "fixtures" / "expected.json").write_text(json.dumps(expected or {}), encoding="utf-8")
    return tmp_path


OPEN_BUCKET = 'resource "google_storage_bucket" "b" {\n  name = "x"\n}\n'


@needs_tools
def test_an_unparseable_fixture_is_an_error_not_a_pass(tmp_path):
    root = make_root(tmp_path, good={"broken": 'resource "google_storage_bucket" "x" {\n  name = \n'})
    problems = run_matrix.run(root)
    assert problems and problems[0].startswith("ERROR")


@needs_tools
def test_a_violation_in_a_good_fixture_is_reported(tmp_path):
    root = make_root(tmp_path, good={"oops": OPEN_BUCKET})
    assert any(p.startswith("UNEXPECTED") for p in run_matrix.run(root))


@needs_tools
def test_a_wrong_expectation_is_reported(tmp_path):
    root = make_root(tmp_path, bad={"b": OPEN_BUCKET}, expected={"b": ["SQL-001"]})
    assert any(p.startswith("WRONG") for p in run_matrix.run(root))


@needs_tools
def test_a_bad_fixture_with_no_expectation_and_an_expectation_with_no_fixture_are_both_reported(tmp_path):
    root = make_root(tmp_path, bad={"b": OPEN_BUCKET}, expected={"ghost": ["GCS-001"]})
    problems = run_matrix.run(root)
    assert any(p.startswith("NO EXPECTATION") for p in problems) and any(p.startswith("MISSING") for p in problems)


def test_a_message_without_a_rule_id_is_refused():
    with pytest.raises(run_matrix.ToolError):
        run_matrix.rule_ids(["something is wrong"])


# --- the gate command ------------------------------------------------------------------------------------------


def run_gate(*args):
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "gate.py"), *args], capture_output=True, text=True)
    return p.returncode, p.stdout


@needs_tools
def test_the_gate_passes_the_compliant_configuration():
    code, out = run_gate(str(ROOT / "fixtures" / "good"))
    assert code == 0 and "0 denial(s)" in out


@needs_tools
def test_the_gate_fails_a_bad_configuration_and_names_the_rule(tmp_path):
    (tmp_path / "main.tf").write_text((ROOT / "fixtures" / "bad" / "net-ssh-world.tf").read_text(encoding="utf-8"), encoding="utf-8")
    code, out = run_gate(str(tmp_path))
    assert code == 1 and "DENY  [NET-001]" in out


@needs_tools
def test_the_gate_merges_files_so_a_rule_can_see_the_whole_configuration(tmp_path):
    (tmp_path / "bucket.tf").write_text(OPEN_BUCKET, encoding="utf-8")
    (tmp_path / "iam.tf").write_text('resource "google_storage_bucket_iam_member" "p" {\n  bucket = "x"\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n', encoding="utf-8")
    code, out = run_gate(str(tmp_path))
    assert code == 1 and "[GCS-001]" in out and "[IAM-001]" in out


@needs_tools
def test_warnings_are_shown_but_do_not_fail_the_gate(tmp_path):
    good_bucket = (ROOT / "fixtures" / "good" / "platform.tf").read_text(encoding="utf-8").split("resource \"google_compute_instance\"")[0]
    (tmp_path / "main.tf").write_text(good_bucket.replace("labels = {", "force_destroy = true\n  labels = {", 1), encoding="utf-8")
    code, out = run_gate(str(tmp_path))
    assert code == 0 and "warn  [GCS-004]" in out


@needs_tools
def test_a_gate_that_cannot_run_exits_2_never_0(tmp_path):
    assert run_gate(str(tmp_path))[0] == 2  # no .tf files at all
    (tmp_path / "broken.tf").write_text("resource {", encoding="utf-8")
    assert run_gate(str(tmp_path))[0] == 2


@needs_tools
def test_the_recursive_flag_finds_nested_modules(tmp_path):
    (tmp_path / "mod").mkdir()
    (tmp_path / "mod" / "main.tf").write_text(OPEN_BUCKET, encoding="utf-8")
    assert run_gate(str(tmp_path))[0] == 2
    code, out = run_gate(str(tmp_path), "--recursive")
    assert code == 1 and "[GCS-001]" in out
