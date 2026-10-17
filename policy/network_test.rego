package gcp.rules.network_test

import data.gcp.rules.network
import rego.v1

fw(attrs) := {"resource": {"google_compute_firewall": {"f": [attrs]}}}

world := ["0.0.0.0/0"]

tcp(ports) := [{"protocol": "tcp", "ports": ports}]

ids(msgs) := {substring(m, 1, 7) | some m in msgs}

test_https_from_the_world_is_fine if {
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["443"])})
}

test_ssh_from_the_world_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["22"])})
}

test_rdp_from_the_world_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["3389"])})
}

test_ssh_hidden_inside_a_range_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["20-25"])})
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["0-65535"])})
}

test_a_range_next_to_but_not_covering_ssh_is_fine if {
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["23-100"])})
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["8000-9000"])})
}

test_ipv6_anywhere_counts_as_the_world if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": ["::/0"], "allow": tcp(["22"])})
}

test_the_world_hidden_among_other_ranges_is_still_the_world if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": ["10.0.0.0/8", "0.0.0.0/0"], "allow": tcp(["22"])})
}

test_every_port_is_denied_as_all_protocols_or_tcp_without_ports if {
	ids(network.deny) == {"NET-002"} with input as fw({"source_ranges": world, "allow": [{"protocol": "all"}]})
	ids(network.deny) == {"NET-002"} with input as fw({"source_ranges": world, "allow": [{"protocol": "ALL"}]})
	ids(network.deny) == {"NET-002"} with input as fw({"source_ranges": world, "allow": [{"protocol": "tcp"}]})
}

test_private_and_iap_ranges_are_fine if {
	count(network.deny) == 0 with input as fw({"source_ranges": ["35.235.240.0/20"], "allow": tcp(["22"])})
	count(network.deny) == 0 with input as fw({"source_ranges": ["10.0.0.0/8"], "allow": [{"protocol": "all"}]})
}

test_egress_rules_are_not_this_policys_concern if {
	count(network.deny) == 0 with input as fw({"direction": "EGRESS", "source_ranges": world, "allow": [{"protocol": "all"}]})
}

test_a_disabled_rule_does_nothing if {
	count(network.deny) == 0 with input as fw({"disabled": true, "source_ranges": world, "allow": tcp(["22"])})
}

test_udp_and_icmp_are_not_flagged_for_admin_ports if {
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": [{"protocol": "udp", "ports": ["22"]}, {"protocol": "icmp"}]})
}

test_a_port_that_is_an_unresolved_variable_does_not_crash_and_is_not_guessed_at if {
	# Known limit: a value Terraform has not resolved cannot be judged from the configuration alone.
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["${var.port}"])})
}

# Boundaries are inclusive on both ends: a range that merely STARTS or ENDS on an admin port still opens it.
test_a_range_starting_exactly_at_ssh_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["22-30"])})
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["3389-4000"])})
}

test_a_range_ending_exactly_at_ssh_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["10-22"])})
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["1000-3389"])})
}

test_a_single_port_range_on_an_admin_port_is_denied if {
	ids(network.deny) == {"NET-001"} with input as fw({"source_ranges": world, "allow": tcp(["22-22"])})
}

test_ranges_that_stop_just_short_of_or_start_just_after_the_admin_ports_are_fine if {
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["1-21"])})
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["23-3388"])})
	count(network.deny) == 0 with input as fw({"source_ranges": world, "allow": tcp(["3390-9000"])})
}
