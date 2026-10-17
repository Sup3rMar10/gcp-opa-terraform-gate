package gcp.rules.iam

import data.gcp.lib
import rego.v1

primitive_roles := {"roles/owner", "roles/editor"}

public_members := {"allUsers", "allAuthenticatedUsers"}

escalation_roles := {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}

# Every *_iam_member and *_iam_binding resource, whatever it binds to, keyed by [type, name].
bindings[[rtype, name]] := attrs if {
	some rtype, byname in input.resource
	regex.match(`_iam_(member|binding)$`, rtype)
	some name, defs in byname
	attrs := defs[0]
}

single_member(attrs) := [attrs.member] if is_string(attrs.member)

else := []

many_members(attrs) := attrs.members if is_array(attrs.members)

else := []

members_of(attrs) := array.concat(single_member(attrs), many_members(attrs))

deny contains msg if {
	some [rtype, name], attrs in bindings
	some m in members_of(attrs)
	m in public_members
	msg := sprintf("[IAM-001] %s.%s grants a role to %s, i.e. the public internet", [rtype, name, m])
}

deny contains msg if {
	some [rtype, name], attrs in bindings
	attrs.role in primitive_roles
	msg := sprintf("[IAM-002] %s.%s grants the primitive role %s; use a predefined or custom role", [rtype, name, attrs.role])
}

deny contains msg if {
	some name, _ in lib.resources("google_service_account_key")
	msg := sprintf("[IAM-003] google_service_account_key.%s creates a long-lived key; use Workload Identity Federation or attached service accounts", [name])
}

warn contains msg if {
	some [rtype, name], attrs in bindings
	startswith(rtype, "google_project_iam_")
	attrs.role in escalation_roles
	msg := sprintf("[IAM-004] %s.%s grants %s on the whole project, a privilege-escalation path; scope it to one service account", [rtype, name, attrs.role])
}
