package gcp.terraform

import data.gcp.rules.compute
import data.gcp.rules.gke
import data.gcp.rules.iam
import data.gcp.rules.network
import data.gcp.rules.sql
import data.gcp.rules.storage
import rego.v1

# Everything that must be fixed before this configuration is merged.
deny := ((((storage.deny | iam.deny) | network.deny) | compute.deny) | sql.deny) | gke.deny

# Everything worth a look that does not block.
warn := storage.warn | iam.warn
