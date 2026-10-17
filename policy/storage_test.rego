package gcp.rules.storage_test

import data.gcp.rules.storage
import rego.v1

good := {
	"uniform_bucket_level_access": true,
	"public_access_prevention": "enforced",
	"versioning": [{"enabled": true}],
	"labels": {"owner": "platform", "env": "prod"},
}

doc(attrs) := {"resource": {"google_storage_bucket": {"b": [attrs]}}}

# NOTE: object.union merges nested objects recursively, so a case that must REPLACE a nested object removes it first.
# "[GCS-001] message" -> "GCS-001"
ids(msgs) := {substring(m, 1, 7) | some m in msgs}

test_a_compliant_bucket_is_clean if {
	count(storage.deny) == 0 with input as doc(good)
	count(storage.warn) == 0 with input as doc(good)
}

test_no_buckets_means_nothing_to_deny if {
	count(storage.deny) == 0 with input as {}
	count(storage.deny) == 0 with input as {"resource": {}}
}

test_missing_uniform_access_is_denied if {
	ids(storage.deny) == {"GCS-001"} with input as doc(object.remove(good, ["uniform_bucket_level_access"]))
}

test_uniform_access_false_is_denied if {
	ids(storage.deny) == {"GCS-001"} with input as doc(object.union(good, {"uniform_bucket_level_access": false}))
}

test_the_string_true_is_not_the_boolean_true if {
	ids(storage.deny) == {"GCS-001"} with input as doc(object.union(good, {"uniform_bucket_level_access": "true"}))
}

test_public_access_prevention_must_be_enforced if {
	ids(storage.deny) == {"GCS-002"} with input as doc(object.remove(good, ["public_access_prevention"]))
	ids(storage.deny) == {"GCS-002"} with input as doc(object.union(good, {"public_access_prevention": "inherited"}))
}

test_versioning_must_be_on if {
	ids(storage.deny) == {"GCS-003"} with input as doc(object.remove(good, ["versioning"]))
	ids(storage.deny) == {"GCS-003"} with input as doc(object.union(good, {"versioning": [{"enabled": false}]}))
}

test_both_labels_are_required_and_must_not_be_empty if {
	ids(storage.deny) == {"LBL-001"} with input as doc(object.remove(good, ["labels"]))
	ids(storage.deny) == {"LBL-001"} with input as doc(object.union(object.remove(good, ["labels"]), {"labels": {"owner": "x"}}))
	ids(storage.deny) == {"LBL-001"} with input as doc(object.union(object.remove(good, ["labels"]), {"labels": {"owner": "", "env": "prod"}}))
}

test_force_destroy_warns_but_does_not_deny if {
	count(storage.deny) == 0 with input as doc(object.union(good, {"force_destroy": true}))
	ids(storage.warn) == {"GCS-004"} with input as doc(object.union(good, {"force_destroy": true}))
}

test_every_bucket_is_judged_on_its_own if {
	two := {"resource": {"google_storage_bucket": {"ok": [good], "bad": [object.remove(good, ["public_access_prevention"])]}}}
	msgs := storage.deny with input as two
	count(msgs) == 1
	some m in msgs
	contains(m, "google_storage_bucket.bad")
}

test_several_problems_on_one_bucket_are_all_reported if {
	ids(storage.deny) == {"GCS-001", "GCS-002", "GCS-003", "LBL-001"} with input as doc({})
}
