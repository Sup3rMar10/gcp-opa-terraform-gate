package gcp.rules.gke

import data.gcp.lib
import rego.v1

clusters := lib.resources("google_container_cluster")

workload_identity(c) if {
	some w in lib.blocks(c, "workload_identity_config")
	is_string(w.workload_pool)
	w.workload_pool != ""
}

deny contains msg if {
	some name, c in clusters
	c.enable_legacy_abac == true
	msg := sprintf("[GKE-001] google_container_cluster.%s enables legacy ABAC, which bypasses RBAC", [name])
}

deny contains msg if {
	some name, c in clusters
	some m in lib.blocks(c, "master_authorized_networks_config")
	some cb in lib.blocks(m, "cidr_blocks")
	cb.cidr_block == "0.0.0.0/0"
	msg := sprintf("[GKE-002] google_container_cluster.%s lets the whole internet reach the control plane (authorized network 0.0.0.0/0)", [name])
}

deny contains msg if {
	some name, c in clusters
	not workload_identity(c)
	msg := sprintf("[GKE-003] google_container_cluster.%s has no workload_identity_config, so pods fall back to node credentials", [name])
}
