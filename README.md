# gcp-opa-terraform-gate

![ci](https://github.com/Sup3rMar10/gcp-opa-terraform-gate/actions/workflows/ci.yml/badge.svg)

**Policy-as-code for Terraform on Google Cloud, with the policies themselves tested.** 19 deny rules and 2 warnings written in Rego for [Open Policy Agent](https://www.openpolicyagent.org/), a `gate` command a pipeline runs on a Terraform directory, and the part most policy repos skip: proof that every rule fires when it should, stays quiet when it should, and that the test harness itself can fail.

> **What is verified, and what is not.** With OPA 1.21.2: **63 Rego unit tests** pass, a matrix of **every rule against 46 fixture Terraform files** (44 deliberately non-compliant, 2 compliant) returns exactly the expected rule ids, 14 pytest tests cover the harness and the gate command, and the compliant fixtures pass `terraform validate` against the **real `google` provider schema**. GitHub Actions on Linux ran all of it too, with OPA and hcl2json pinned (2026-10-17). I broke the code on purpose several times (below) to confirm the tests can fail. **No Google Cloud project is involved**: the policies read Terraform *text*, so they say nothing about what is actually deployed.

## The rules (`policy/`)

| ID | What it denies |
|---|---|
| `GCS-001/002/003` | a bucket without uniform bucket-level access, without `public_access_prevention = "enforced"`, or without versioning |
| `IAM-001` | a role granted to `allUsers` or `allAuthenticatedUsers`, on any `*_iam_member` or `*_iam_binding` resource, including inside a `members` list |
| `IAM-002` / `IAM-003` | the primitive roles `owner` and `editor`; a `google_service_account_key` (a long-lived secret) |
| `NET-001` | a firewall rule open to the world on SSH (22) or RDP (3389), directly **or inside a port range** (`20-25`, `0-65535`), over IPv4 or IPv6 |
| `NET-002` | a firewall rule open to the world on every port (protocol `all`, or tcp with no ports) |
| `CMP-001/002/003` | a VM on the default compute service account (including having no `service_account` block at all), with an external IP, or without OS Login |
| `SQL-001/002/003/004` | a Cloud SQL instance with a public IP, authorising `0.0.0.0/0`, without backups, or without deletion protection |
| `GKE-001/002/003` | legacy ABAC, a control plane open to `0.0.0.0/0`, or no Workload Identity |
| `LBL-001` | a bucket or VM without non-empty `owner` and `env` labels |
| warnings | `GCS-004` (`force_destroy = true`), `IAM-004` (project-wide `serviceAccountUser` / `TokenCreator`, an escalation path). They print but never fail the gate |

## Four layers of checks

1. **`opa fmt` and `opa check --strict`** on the policies themselves.
2. **63 Rego unit tests** (`opa test`): each rule in isolation, with inline inputs, including the cases that are easy to get wrong (below).
3. **`tools/run_matrix.py`**: every rule against every fixture; the set of rule ids must equal the expected set **exactly**, so a missed violation fails *and* so does a rule that flags something extra. A test also requires that **every deny rule has a failing fixture** and that every expectation names a real rule.
4. **`terraform validate`** on the compliant fixtures with the real provider: compliant is a different question from valid.

## What the checks found while building it

- **An off-by-one in the port-range check survived my first test suite.** Changing `<=` to `<` in the range comparison passed all 59 Rego tests and all fixtures, because none of my ranges *started or ended exactly on* 22 or 3389. A firewall policy cannot have that bug. I added boundary tests (`22-30`, `10-22`, `3389-3389`, near-misses like `23-3388`) and fixtures, and **both** bounds' mutations are now caught by both layers.
- **A recursive `object.union` made a Rego test pass for the wrong reason**: "labels with only `owner`" silently kept the original `env` label (the union merges nested objects), so the case was compliant and the test failed. Cases that must *replace* a nested object now remove it first, with a comment.
- **`terraform validate` caught mistakes in my fixtures** that the policies could not: bucket IAM resources take `bucket`, not `project`, and the two compliant files reused resource names, so they are validated one at a time.
- **A harness that treats errors as success is worse than none.** `run_matrix.py` and `gate.py` treat HCL that will not parse, an OPA error, or a message with no rule id as an **ERROR** (exit 2 for the gate), never "no violations". Tests prove this: an unparseable fixture, a violation in a "good" fixture and a wrong expectation are each reported.

## The gate (`tools/gate.py`)

```
python tools/gate.py path/to/terraform            # exit 0 clean, 1 denials, 2 could not run
python tools/gate.py path/to/terraform --recursive
```

It merges a directory's `.tf` files into one configuration first (a bucket in one file and its public IAM binding in another are still seen together), prints `warn` and `DENY` lines with the rule id and resource address, and exits 1 on any denial. Warnings never fail it. An empty directory or broken HCL exits **2**: a gate that could not run is not a gate that passed.

## Honest limits

- **It reads configuration, not the plan.** `hcl2json` converts the HCL as written, so values Terraform has not resolved appear as `${var.x}` and **cannot be judged** (a firewall port or CIDR that is a variable is not flagged; a test pins that behaviour). Module expansion, `count`, and `for_each` are not evaluated. Policies on `terraform show -json` plan output would see resolved values; I did not build or test that.
- **`dynamic` blocks are invisible to these rules.** A rule that looks for an `allow` or `access_config` block does not look inside a `dynamic "allow" { ... }`, so a violation written that way would pass. That is a real false-negative class, not covered here.
- **Nineteen rules are a sample, not a benchmark.** This is not the CIS Google Cloud benchmark or Google's own Config Validator, and it does not cover networking beyond firewalls, encryption keys, logging, VPC Service Controls or organisation policy. It complements Organization Policy constraints and runtime checks (Security Command Center, Cloud Asset Inventory), which see what is actually deployed.
- The IAM rules only look at `_iam_member` and `_iam_binding` resources; `_iam_policy` and authoritative `_iam_policy` documents are not parsed.
- Rules check what the resource says, not what the organisation inherits: a bucket can be made public by an inherited policy these rules cannot see.
- The fixtures are generated by `tools/make_fixtures.py` and committed; the generated files and `expected.json` are the source of truth.
- Tested with OPA 1.21.2, hcl2json 0.6.9 and Terraform 1.16 with `google ~> 6.0`; other versions may behave differently (notably Rego v1 syntax needs OPA 1.x).

## Run it

```
# needs: opa, hcl2json, python, terraform
opa fmt --fail policy/ && opa check --strict policy/ && opa test policy/
python tools/run_matrix.py
python -m pip install pytest pyyaml && python -m pytest
bash tools/validate_good.sh
python tools/gate.py fixtures/good
python tools/gate.py fixtures/bad --recursive    # exits 1, lists the denials
```
