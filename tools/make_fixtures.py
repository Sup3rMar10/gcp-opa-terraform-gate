"""Regenerate fixtures/: a compliant baseline per resource type, and one bad variant per rule (plus tricky forms).

Run:  python tools/make_fixtures.py
The generated .tf files and fixtures/expected.json are committed; this script is how they were made and how to extend them.
"""

from __future__ import annotations

import json
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


def bucket(name="b", ubla='true', pap='"enforced"', versioning=True, labels='{ owner = "platform", env = "prod" }', extra=""):
    lines = [f'resource "google_storage_bucket" "{name}" {{', f'  name     = "acme-{name}"', '  location = "US"']
    if ubla is not None:
        lines.append(f"  uniform_bucket_level_access = {ubla}")
    if pap is not None:
        lines.append(f"  public_access_prevention    = {pap}")
    if versioning is True:
        lines += ["  versioning {", "    enabled = true", "  }"]
    elif versioning is False:
        lines += ["  versioning {", "    enabled = false", "  }"]
    if labels is not None:
        lines.append(f"  labels = {labels}")
    if extra:
        lines.append(extra)
    return "\n".join(lines + ["}", ""])


def instance(name="vm", sa='email = "app@acme-prod.iam.gserviceaccount.com"', external_ip=False, oslogin='"TRUE"',
             labels='{ owner = "platform", env = "prod" }'):
    lines = [f'resource "google_compute_instance" "{name}" {{', f'  name         = "{name}"', '  machine_type = "e2-small"', '  zone         = "us-central1-a"',
             "  boot_disk {", "    initialize_params {", '      image = "debian-cloud/debian-12"', "    }", "  }",
             "  network_interface {", '    network = "default"']
    if external_ip == "static":
        lines += ["    access_config {", '      nat_ip = "203.0.113.10"', "    }"]
    elif external_ip:
        lines += ["    access_config {", "    }"]
    lines.append("  }")
    if sa is not None:
        lines += ["  service_account {", f"    {sa}", '    scopes = ["cloud-platform"]', "  }"]
    if oslogin is not None:
        lines.append(f'  metadata = {{ "enable-oslogin" = {oslogin} }}')
    if labels is not None:
        lines.append(f"  labels = {labels}")
    return "\n".join(lines + ["}", ""])


def firewall(name="fw", ranges='["35.235.240.0/20"]', allow='allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }', extra=""):
    return (f'resource "google_compute_firewall" "{name}" {{\n  name          = "{name}"\n  network       = "default"\n'
            f"  source_ranges = {ranges}\n  {allow}\n{extra}}}\n")


def sql(name="db", ip='ip_configuration {\n      ipv4_enabled    = false\n      private_network = "projects/p/global/networks/n"\n    }',
        backup="backup_configuration {\n      enabled = true\n    }", deletion="true"):
    lines = [f'resource "google_sql_database_instance" "{name}" {{', f'  name             = "{name}"', '  database_version = "POSTGRES_15"']
    if deletion is not None:
        lines.append(f"  deletion_protection = {deletion}")
    lines += ["  settings {", '    tier = "db-f1-micro"']
    if ip:
        lines.append("    " + ip)
    if backup:
        lines.append("    " + backup)
    return "\n".join(lines + ["  }", "}", ""])


def cluster(name="gke", abac=None, master="", wi='workload_identity_config {\n    workload_pool = "acme-prod.svc.id.goog"\n  }'):
    lines = [f'resource "google_container_cluster" "{name}" {{', f'  name     = "{name}"', '  location = "us-central1"']
    if abac is not None:
        lines.append(f"  enable_legacy_abac = {abac}")
    if master:
        lines.append("  " + master)
    if wi:
        lines.append("  " + wi)
    return "\n".join(lines + ["}", ""])


def iam(kind="member", rtype="google_project_iam_member", role="roles/viewer", member="serviceAccount:ci@acme-prod.iam.gserviceaccount.com"):
    # Bucket-scoped IAM resources take `bucket`, not `project`: the real provider schema rejects anything else.
    scope = 'bucket  = "acme-b"' if "storage_bucket" in rtype else 'project = "acme-prod"'
    head = f'resource "{rtype}" "x" {{'
    if kind == "binding":
        return "\n".join([head, f"  {scope}", f'  role    = "{role}"', f'  members = ["{member}"]', "}", ""])
    return "\n".join([head, f"  {scope}", f'  role    = "{role}"', f'  member  = "{member}"', "}", ""])


SA_KEY = 'resource "google_service_account_key" "k" {\n  service_account_id = "ci@acme-prod.iam.gserviceaccount.com"\n}\n'
SSH_ALLOW = 'allow {\n    protocol = "tcp"\n    ports    = ["22"]\n  }'


def tcp_allow(ports):
    """An allow block for tcp with the given already-quoted, comma-separated port specs, e.g. '"22-30"'."""
    return 'allow {\n    protocol = "tcp"\n    ports    = [' + ports + "]\n  }"

GOOD = {
    "platform": "\n".join([
        bucket(), instance(), firewall(), sql(), cluster(),
        iam(), iam("binding", "google_storage_bucket_iam_binding", "roles/storage.objectViewer", "group:data@acme.example"),
    ]),
    "edge-cases": "\n".join([
        # world-open is fine for HTTPS, for ingress that is disabled, and for egress
        firewall("https", '["0.0.0.0/0"]', 'allow {\n    protocol = "tcp"\n    ports    = ["443", "8443"]\n  }'),
        firewall("ssh-from-office", '["203.0.113.0/24"]'),
        firewall("ssh-disabled", '["0.0.0.0/0"]', SSH_ALLOW, "  disabled = true\n"),
        firewall("egress-all", '["0.0.0.0/0"]', 'allow {\n    protocol = "all"\n  }', '  direction = "EGRESS"\n'),
        firewall("near-miss-ranges", '["0.0.0.0/0"]', tcp_allow('"1-21", "23-3388", "3390-9000"')),
        firewall("high-ports", '["0.0.0.0/0"]', 'allow {\n    protocol = "tcp"\n    ports    = ["8000-9000"]\n  }'),
        firewall("udp-all", '["0.0.0.0/0"]', 'allow {\n    protocol = "udp"\n    ports    = ["53"]\n  }'),
        bucket("logs", labels='{ owner = "sre", env = "stage", cost-centre = "42" }'),
        iam(role="roles/storage.objectViewer", member="allUsers").replace("allUsers", "user:alice@acme.example"),
        instance("batch", oslogin="true"),
    ]),
}

# name -> (terraform text, the exact rule ids it must trigger)
BAD = {
    "gcs-no-ubla": (bucket(ubla=None), ["GCS-001"]),
    "gcs-ubla-false": (bucket(ubla="false"), ["GCS-001"]),
    "gcs-ubla-as-string": (bucket(ubla='"true"'), ["GCS-001"]),
    "gcs-no-pap": (bucket(pap=None), ["GCS-002"]),
    "gcs-pap-inherited": (bucket(pap='"inherited"'), ["GCS-002"]),
    "gcs-no-versioning": (bucket(versioning=None), ["GCS-003"]),
    "gcs-versioning-off": (bucket(versioning=False), ["GCS-003"]),
    "gcs-no-labels": (bucket(labels=None), ["LBL-001"]),
    "gcs-missing-env-label": (bucket(labels='{ owner = "platform" }'), ["LBL-001"]),
    "gcs-empty-owner-label": (bucket(labels='{ owner = "", env = "prod" }'), ["LBL-001"]),
    "gcs-two-buckets-one-bad": (bucket("good") + "\n" + bucket("bad", ubla=None), ["GCS-001"]),
    "iam-public-member": (iam(rtype="google_storage_bucket_iam_member", role="roles/storage.objectViewer", member="allUsers"), ["IAM-001"]),
    "iam-all-authenticated": (iam(rtype="google_storage_bucket_iam_member", role="roles/storage.objectViewer", member="allAuthenticatedUsers"), ["IAM-001"]),
    "iam-public-in-binding": (iam("binding", "google_storage_bucket_iam_binding", "roles/storage.objectViewer", "allUsers"), ["IAM-001"]),
    "iam-owner": (iam(role="roles/owner"), ["IAM-002"]),
    "iam-editor-binding": (iam("binding", "google_project_iam_binding", "roles/editor", "group:devs@acme.example"), ["IAM-002"]),
    "iam-sa-key": (SA_KEY, ["IAM-003"]),
    "net-ssh-world": (firewall(ranges='["0.0.0.0/0"]'), ["NET-001"]),
    "net-rdp-world": (firewall(ranges='["0.0.0.0/0"]', allow='allow {\n    protocol = "tcp"\n    ports    = ["3389"]\n  }'), ["NET-001"]),
    "net-port-range": (firewall(ranges='["0.0.0.0/0"]', allow='allow {\n    protocol = "tcp"\n    ports    = ["0-65535"]\n  }'), ["NET-001"]),
    "net-ssh-in-range": (firewall(ranges='["0.0.0.0/0"]', allow='allow {\n    protocol = "tcp"\n    ports    = ["20-25"]\n  }'), ["NET-001"]),
    "net-range-starts-at-ssh": (firewall(ranges='["0.0.0.0/0"]', allow=tcp_allow('"22-30"')), ["NET-001"]),
    "net-range-ends-at-rdp": (firewall(ranges='["0.0.0.0/0"]', allow=tcp_allow('"1000-3389"')), ["NET-001"]),
    "net-ipv6-ssh": (firewall(ranges='["::/0"]'), ["NET-001"]),
    "net-all-protocols": (firewall(ranges='["0.0.0.0/0"]', allow='allow {\n    protocol = "all"\n  }'), ["NET-002"]),
    "net-tcp-no-ports": (firewall(ranges='["0.0.0.0/0"]', allow='allow {\n    protocol = "tcp"\n  }'), ["NET-002"]),
    "net-world-among-others": (firewall(ranges='["10.0.0.0/8", "0.0.0.0/0"]'), ["NET-001"]),
    "cmp-no-service-account": (instance(sa=None), ["CMP-001"]),
    "cmp-default-service-account": (instance(sa='email = "123456789-compute@developer.gserviceaccount.com"'), ["CMP-001"]),
    "cmp-external-ip": (instance(external_ip=True), ["CMP-002"]),
    "cmp-external-static-ip": (instance(external_ip="static"), ["CMP-002"]),
    "cmp-no-oslogin": (instance(oslogin=None), ["CMP-003"]),
    "cmp-oslogin-false": (instance(oslogin='"FALSE"'), ["CMP-003"]),
    "cmp-no-labels": (instance(labels=None), ["LBL-001"]),
    "sql-no-ip-config": (sql(ip=""), ["SQL-001"]),
    "sql-public-ipv4": (sql(ip="ip_configuration {\n      ipv4_enabled = true\n    }"), ["SQL-001"]),
    "sql-open-to-world": (sql(ip='ip_configuration {\n      ipv4_enabled = true\n      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n    }'),
                          ["SQL-001", "SQL-002"]),
    "sql-no-backups": (sql(backup=""), ["SQL-003"]),
    "sql-backups-disabled": (sql(backup="backup_configuration {\n      enabled = false\n    }"), ["SQL-003"]),
    "sql-no-deletion-protection": (sql(deletion=None), ["SQL-004"]),
    "sql-deletion-protection-false": (sql(deletion="false"), ["SQL-004"]),
    "gke-legacy-abac": (cluster(abac="true"), ["GKE-001"]),
    "gke-open-control-plane": (cluster(master='master_authorized_networks_config {\n    cidr_blocks {\n      cidr_block = "0.0.0.0/0"\n    }\n  }'), ["GKE-002"]),
    "gke-no-workload-identity": (cluster(wi=""), ["GKE-003"]),
}


def main() -> None:
    for sub in ("good", "bad"):
        os.makedirs(os.path.join(ROOT, sub), exist_ok=True)
    for name, text in GOOD.items():
        open(os.path.join(ROOT, "good", f"{name}.tf"), "w", encoding="utf-8", newline="\n").write(text)
    for name, (text, _) in BAD.items():
        open(os.path.join(ROOT, "bad", f"{name}.tf"), "w", encoding="utf-8", newline="\n").write(text)
    expected = {name: sorted(ids) for name, (_, ids) in BAD.items()}
    open(os.path.join(ROOT, "expected.json"), "w", encoding="utf-8", newline="\n").write(json.dumps(expected, indent=2) + "\n")
    print(f"{len(GOOD)} good and {len(BAD)} bad fixtures written")


if __name__ == "__main__":
    main()
