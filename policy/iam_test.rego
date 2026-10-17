package gcp.rules.iam_test

import data.gcp.rules.iam
import rego.v1

member(rtype, attrs) := {"resource": {rtype: {"x": [attrs]}}}

ids(msgs) := {substring(m, 1, 7) | some m in msgs}

test_a_scoped_member_is_clean if {
	count(iam.deny) == 0 with input as member("google_project_iam_member", {"role": "roles/viewer", "member": "user:a@acme.example"})
}

test_all_users_and_all_authenticated_users_are_denied_on_any_resource_type if {
	ids(iam.deny) == {"IAM-001"} with input as member("google_storage_bucket_iam_member", {"role": "roles/storage.objectViewer", "member": "allUsers"})
	ids(iam.deny) == {"IAM-001"} with input as member("google_bigquery_dataset_iam_member", {"role": "roles/bigquery.dataViewer", "member": "allAuthenticatedUsers"})
}

test_a_public_member_hidden_in_a_binding_list_is_denied if {
	ids(iam.deny) == {"IAM-001"} with input as member("google_storage_bucket_iam_binding", {"role": "roles/storage.objectViewer", "members": ["group:a@acme.example", "allUsers"]})
}

test_primitive_roles_are_denied_in_members_and_bindings if {
	ids(iam.deny) == {"IAM-002"} with input as member("google_project_iam_member", {"role": "roles/owner", "member": "user:a@acme.example"})
	ids(iam.deny) == {"IAM-002"} with input as member("google_project_iam_binding", {"role": "roles/editor", "members": ["group:a@acme.example"]})
}

test_a_viewer_role_is_not_a_primitive_role_denial if {
	count(iam.deny) == 0 with input as member("google_project_iam_member", {"role": "roles/viewer", "member": "user:a@acme.example"})
}

test_a_service_account_key_is_denied if {
	ids(iam.deny) == {"IAM-003"} with input as member("google_service_account_key", {"service_account_id": "x"})
}

test_project_wide_impersonation_roles_warn_but_do_not_deny if {
	i := member("google_project_iam_member", {"role": "roles/iam.serviceAccountTokenCreator", "member": "user:a@acme.example"})
	count(iam.deny) == 0 with input as i
	ids(iam.warn) == {"IAM-004"} with input as i
}

test_the_same_role_on_one_service_account_does_not_warn if {
	i := member("google_service_account_iam_member", {"role": "roles/iam.serviceAccountUser", "member": "user:a@acme.example"})
	count(iam.warn) == 0 with input as i
}

test_resources_that_are_not_iam_bindings_are_ignored if {
	count(iam.deny) == 0 with input as member("google_storage_bucket", {"member": "allUsers", "role": "roles/owner"})
}

test_a_missing_member_does_not_crash if {
	count(iam.deny) == 0 with input as member("google_project_iam_member", {"role": "roles/viewer"})
}
