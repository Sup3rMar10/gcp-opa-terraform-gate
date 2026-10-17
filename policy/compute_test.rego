package gcp.rules.compute_test

import data.gcp.rules.compute
import rego.v1

good := {
	"service_account": [{"email": "app@acme-prod.iam.gserviceaccount.com", "scopes": ["cloud-platform"]}],
	"network_interface": [{"network": "default"}],
	"metadata": {"enable-oslogin": "TRUE"},
	"labels": {"owner": "platform", "env": "prod"},
}

doc(attrs) := {"resource": {"google_compute_instance": {"vm": [attrs]}}}

ids(msgs) := {substring(m, 1, 7) | some m in msgs}

test_a_compliant_instance_is_clean if {
	count(compute.deny) == 0 with input as doc(good)
}

test_no_service_account_block_means_the_default_account if {
	ids(compute.deny) == {"CMP-001"} with input as doc(object.remove(good, ["service_account"]))
}

test_the_default_compute_account_by_email_is_denied if {
	ids(compute.deny) == {"CMP-001"} with input as doc(object.union(object.remove(good, ["service_account"]), {"service_account": [{"email": "123456789-compute@developer.gserviceaccount.com"}]}))
}

test_a_service_account_block_with_no_email_is_the_default_account if {
	ids(compute.deny) == {"CMP-001"} with input as doc(object.union(object.remove(good, ["service_account"]), {"service_account": [{"scopes": ["cloud-platform"]}]}))
}

test_a_reference_to_a_dedicated_account_is_accepted if {
	count(compute.deny) == 0 with input as doc(object.union(object.remove(good, ["service_account"]), {"service_account": [{"email": "${google_service_account.app.email}"}]}))
}

test_an_external_ip_is_denied if {
	ids(compute.deny) == {"CMP-002"} with input as doc(object.union(object.remove(good, ["network_interface"]), {"network_interface": [{"network": "default", "access_config": [{}]}]}))
}

test_os_login_must_be_on if {
	ids(compute.deny) == {"CMP-003"} with input as doc(object.remove(good, ["metadata"]))
	ids(compute.deny) == {"CMP-003"} with input as doc(object.union(object.remove(good, ["metadata"]), {"metadata": {"enable-oslogin": "FALSE"}}))
	ids(compute.deny) == {"CMP-003"} with input as doc(object.union(object.remove(good, ["metadata"]), {"metadata": {"other": "x"}}))
}

test_os_login_accepts_either_case_or_a_boolean if {
	count(compute.deny) == 0 with input as doc(object.union(object.remove(good, ["metadata"]), {"metadata": {"enable-oslogin": "true"}}))
	count(compute.deny) == 0 with input as doc(object.union(object.remove(good, ["metadata"]), {"metadata": {"enable-oslogin": true}}))
}

test_labels_are_required if {
	ids(compute.deny) == {"LBL-001"} with input as doc(object.remove(good, ["labels"]))
}
