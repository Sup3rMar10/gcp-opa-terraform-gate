package gcp.rules.network

import data.gcp.lib
import rego.v1

firewalls := lib.resources("google_compute_firewall")

admin_ports := {22, 3389}

world_open(fw) if "0.0.0.0/0" in object.get(fw, "source_ranges", [])

world_open(fw) if "::/0" in object.get(fw, "source_ranges", [])

# Terraform's default direction is INGRESS, and a disabled rule does nothing.
active_ingress(fw) if {
	object.get(fw, "direction", "INGRESS") == "INGRESS"
	not fw.disabled == true
}

# "22" or "20-25" or "0-65535"
covers(spec, port) if {
	not contains(spec, "-")
	to_number(spec) == port
}

covers(spec, port) if {
	contains(spec, "-")
	parts := split(spec, "-")
	to_number(parts[0]) <= port
	port <= to_number(parts[1])
}

protocol(allow) := lower(object.get(allow, "protocol", ""))

# An allow block that means every port: protocol "all", or tcp with no port list.
every_port(allow) if protocol(allow) == "all"

every_port(allow) if {
	protocol(allow) == "tcp"
	not allow.ports
}

deny contains msg if {
	some name, fw in firewalls
	active_ingress(fw)
	world_open(fw)
	some allow in lib.blocks(fw, "allow")
	protocol(allow) == "tcp"
	some spec in allow.ports
	some port in admin_ports
	covers(spec, port)
	msg := sprintf("[NET-001] google_compute_firewall.%s allows port %d (via %q) from the whole internet", [name, port, spec])
}

deny contains msg if {
	some name, fw in firewalls
	active_ingress(fw)
	world_open(fw)
	some allow in lib.blocks(fw, "allow")
	every_port(allow)
	msg := sprintf("[NET-002] google_compute_firewall.%s allows every port from the whole internet", [name])
}
