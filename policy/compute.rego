package gcp.rules.compute

import data.gcp.lib
import rego.v1

instances := lib.resources("google_compute_instance")

default_sa_suffix := "-compute@developer.gserviceaccount.com"

# A dedicated service account: a service_account block with an email that is not the project's default compute account.
# With no block at all, Compute Engine silently uses the default account, which is usually an Editor on the project.
dedicated_sa(i) if {
	some sa in lib.blocks(i, "service_account")
	is_string(sa.email)
	not endswith(sa.email, default_sa_suffix)
}

oslogin_on(i) if lower(sprintf("%v", [i.metadata["enable-oslogin"]])) == "true"

deny contains msg if {
	some name, i in instances
	not dedicated_sa(i)
	msg := sprintf("[CMP-001] google_compute_instance.%s runs as the default compute service account; give it a dedicated one", [name])
}

deny contains msg if {
	some name, i in instances
	some ni in lib.blocks(i, "network_interface")
	count(lib.blocks(ni, "access_config")) > 0
	msg := sprintf("[CMP-002] google_compute_instance.%s has an external IP (access_config); reach it through IAP or a load balancer", [name])
}

deny contains msg if {
	some name, i in instances
	not oslogin_on(i)
	msg := sprintf("[CMP-003] google_compute_instance.%s must set metadata enable-oslogin = \"TRUE\" so SSH access follows IAM", [name])
}

deny contains msg if {
	some name, i in instances
	not lib.labels_ok(i)
	msg := sprintf("[LBL-001] google_compute_instance.%s needs non-empty owner and env labels", [name])
}
