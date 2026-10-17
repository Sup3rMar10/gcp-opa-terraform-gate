package gcp.rules.sql_gke_test

import data.gcp.rules.gke
import data.gcp.rules.sql
import rego.v1

ids(msgs) := {substring(m, 1, 7) | some m in msgs}

good_sql := {
	"deletion_protection": true,
	"settings": [{
		"ip_configuration": [{"ipv4_enabled": false, "private_network": "n"}],
		"backup_configuration": [{"enabled": true}],
	}],
}

sdoc(attrs) := {"resource": {"google_sql_database_instance": {"db": [attrs]}}}

with_settings(s) := object.union(object.remove(good_sql, ["settings"]), {"settings": [s]})

test_a_private_backed_up_protected_instance_is_clean if {
	count(sql.deny) == 0 with input as sdoc(good_sql)
}

test_an_instance_with_no_ip_configuration_has_a_public_ip if {
	ids(sql.deny) == {"SQL-001"} with input as sdoc(with_settings({"backup_configuration": [{"enabled": true}]}))
}

test_ipv4_enabled_true_is_public if {
	ids(sql.deny) == {"SQL-001"} with input as sdoc(with_settings({"ip_configuration": [{"ipv4_enabled": true}], "backup_configuration": [{"enabled": true}]}))
}

test_authorising_the_whole_internet_is_a_second_finding if {
	s := {"ip_configuration": [{"ipv4_enabled": true, "authorized_networks": [{"value": "0.0.0.0/0"}]}], "backup_configuration": [{"enabled": true}]}
	ids(sql.deny) == {"SQL-001", "SQL-002"} with input as sdoc(with_settings(s))
}

test_a_narrow_authorized_network_is_not_the_whole_internet if {
	s := {"ip_configuration": [{"ipv4_enabled": true, "authorized_networks": [{"value": "203.0.113.7/32"}]}], "backup_configuration": [{"enabled": true}]}
	ids(sql.deny) == {"SQL-001"} with input as sdoc(with_settings(s))
}

test_backups_must_be_enabled if {
	ids(sql.deny) == {"SQL-003"} with input as sdoc(with_settings({"ip_configuration": [{"ipv4_enabled": false}]}))
	ids(sql.deny) == {"SQL-003"} with input as sdoc(with_settings({"ip_configuration": [{"ipv4_enabled": false}], "backup_configuration": [{"enabled": false}]}))
}

test_deletion_protection_must_be_true if {
	ids(sql.deny) == {"SQL-004"} with input as sdoc(object.remove(good_sql, ["deletion_protection"]))
	ids(sql.deny) == {"SQL-004"} with input as sdoc(object.union(good_sql, {"deletion_protection": false}))
}

# --- GKE ---

good_gke := {"workload_identity_config": [{"workload_pool": "acme-prod.svc.id.goog"}]}

gdoc(attrs) := {"resource": {"google_container_cluster": {"c": [attrs]}}}

test_a_cluster_with_workload_identity_is_clean if {
	count(gke.deny) == 0 with input as gdoc(good_gke)
}

test_legacy_abac_is_denied if {
	ids(gke.deny) == {"GKE-001"} with input as gdoc(object.union(good_gke, {"enable_legacy_abac": true}))
}

test_abac_explicitly_off_is_fine if {
	count(gke.deny) == 0 with input as gdoc(object.union(good_gke, {"enable_legacy_abac": false}))
}

test_an_open_control_plane_is_denied_and_a_narrow_one_is_not if {
	open := {"master_authorized_networks_config": [{"cidr_blocks": [{"cidr_block": "0.0.0.0/0"}]}]}
	narrow := {"master_authorized_networks_config": [{"cidr_blocks": [{"cidr_block": "203.0.113.0/24"}]}]}
	ids(gke.deny) == {"GKE-002"} with input as gdoc(object.union(good_gke, open))
	count(gke.deny) == 0 with input as gdoc(object.union(good_gke, narrow))
}

test_no_workload_identity_is_denied if {
	ids(gke.deny) == {"GKE-003"} with input as gdoc({})
	ids(gke.deny) == {"GKE-003"} with input as gdoc({"workload_identity_config": [{"workload_pool": ""}]})
}
