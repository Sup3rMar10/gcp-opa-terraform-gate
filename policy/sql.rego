package gcp.rules.sql

import data.gcp.lib
import rego.v1

instances := lib.resources("google_sql_database_instance")

ip_configs(i) := [ip |
	some s in lib.blocks(i, "settings")
	some ip in lib.blocks(s, "ip_configuration")
]

# Private only means ipv4_enabled is explicitly false. Leaving it out gives the instance a public IPv4 address.
private_only(i) if {
	some ip in ip_configs(i)
	ip.ipv4_enabled == false
}

backups_on(i) if {
	some s in lib.blocks(i, "settings")
	some b in lib.blocks(s, "backup_configuration")
	b.enabled == true
}

deny contains msg if {
	some name, i in instances
	not private_only(i)
	msg := sprintf("[SQL-001] google_sql_database_instance.%s has a public IP (set ip_configuration.ipv4_enabled = false and use a private network)", [name])
}

deny contains msg if {
	some name, i in instances
	some ip in ip_configs(i)
	some an in lib.blocks(ip, "authorized_networks")
	an.value == "0.0.0.0/0"
	msg := sprintf("[SQL-002] google_sql_database_instance.%s authorises 0.0.0.0/0, i.e. the whole internet", [name])
}

deny contains msg if {
	some name, i in instances
	not backups_on(i)
	msg := sprintf("[SQL-003] google_sql_database_instance.%s must enable backup_configuration", [name])
}

deny contains msg if {
	some name, i in instances
	not i.deletion_protection == true
	msg := sprintf("[SQL-004] google_sql_database_instance.%s must set deletion_protection = true", [name])
}
