package gcp.rules.storage

import data.gcp.lib
import rego.v1

buckets := lib.resources("google_storage_bucket")

# A missing attribute makes `b.x == true` undefined, and `not` of undefined is true: so "absent" and "false" both fail.
deny contains msg if {
	some name, b in buckets
	not b.uniform_bucket_level_access == true
	msg := sprintf("[GCS-001] google_storage_bucket.%s must set uniform_bucket_level_access = true (no per-object ACLs)", [name])
}

deny contains msg if {
	some name, b in buckets
	not b.public_access_prevention == "enforced"
	msg := sprintf("[GCS-002] google_storage_bucket.%s must set public_access_prevention = \"enforced\"", [name])
}

deny contains msg if {
	some name, b in buckets
	not versioning_enabled(b)
	msg := sprintf("[GCS-003] google_storage_bucket.%s must enable versioning so an overwrite or delete can be undone", [name])
}

versioning_enabled(b) if {
	some v in lib.blocks(b, "versioning")
	v.enabled == true
}

deny contains msg if {
	some name, b in buckets
	not lib.labels_ok(b)
	msg := sprintf("[LBL-001] google_storage_bucket.%s needs non-empty owner and env labels", [name])
}

warn contains msg if {
	some name, b in buckets
	b.force_destroy == true
	msg := sprintf("[GCS-004] google_storage_bucket.%s has force_destroy = true: destroying it deletes every object", [name])
}
