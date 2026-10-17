#!/usr/bin/env bash
# The compliant fixtures must also be valid Terraform for the real google provider schema. Compliant is a different
# question from valid. Each file is validated on its own (they reuse resource names). Needs terraform; no credentials
# are used, because validate never calls Google.
set -euo pipefail
cd "$(dirname "$0")/.."

for f in fixtures/good/*.tf; do
  work="$(mktemp -d)"
  cp "$f" "$work/main.tf"
  cat > "$work/versions.tf" <<'TF'
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = "acme-prod"
  region  = "us-central1"
}
TF
  terraform -chdir="$work" init -backend=false -input=false >/dev/null
  echo "== $f"
  terraform -chdir="$work" validate
  rm -rf "$work"
done
