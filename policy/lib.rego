package gcp.lib

import rego.v1

# All resources of one type as {name: attributes}. hcl2json wraps every resource in a one-item list.
resources(rtype) := {name: defs[0] |
	some name, defs in object.get(object.get(input, "resource", {}), rtype, {})
}

# Nested blocks (versioning { ... }, allow { ... }) are lists in hcl2json; a missing block is an empty list.
blocks(attrs, key) := object.get(attrs, key, [])

# Both labels the organisation requires, present and non-empty. `labels` is an attribute (an object), not a block.
labels_ok(attrs) if {
	is_object(attrs.labels)
	is_string(attrs.labels.owner)
	attrs.labels.owner != ""
	is_string(attrs.labels.env)
	attrs.labels.env != ""
}
