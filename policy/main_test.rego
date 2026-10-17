package gcp.terraform_test

import data.gcp.terraform
import rego.v1

ids(msgs) := {substring(m, 1, 7) | some m in msgs}

test_an_empty_configuration_is_clean if {
	count(terraform.deny) == 0 with input as {}
	count(terraform.warn) == 0 with input as {}
}

test_findings_from_different_rule_files_are_combined if {
	input_doc := {"resource": {
		"google_storage_bucket": {"b": [{}]},
		"google_project_iam_member": {"x": [{"role": "roles/owner", "member": "allUsers"}]},
		"google_sql_database_instance": {"db": [{}]},
	}}
	got := ids(terraform.deny) with input as input_doc
	{"GCS-001", "GCS-002", "GCS-003", "LBL-001", "IAM-001", "IAM-002", "SQL-001", "SQL-003", "SQL-004"} == got
}

test_every_message_starts_with_a_rule_id if {
	input_doc := {"resource": {"google_storage_bucket": {"b": [{}]}, "google_compute_instance": {"vm": [{}]}}}
	msgs := terraform.deny with input as input_doc
	count(msgs) > 0
	every m in msgs {
		regex.match(`^\[[A-Z]+-[0-9]{3}\] `, m)
	}
}

test_warnings_never_block if {
	input_doc := {"resource": {"google_storage_bucket": {"b": [{"force_destroy": true, "uniform_bucket_level_access": true, "public_access_prevention": "enforced", "versioning": [{"enabled": true}], "labels": {"owner": "a", "env": "b"}}]}}}
	count(terraform.deny) == 0 with input as input_doc
	count(terraform.warn) == 1 with input as input_doc
}
