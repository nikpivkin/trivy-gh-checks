# METADATA
# custom:
#   library: true
#   input:
#     selector:
#       - type: yaml
package github.lib.dependabot

import rego.v1

is_dependabot_config if {
	input.version
	input.updates
}

config := object.union(input, {"kind": "dependabot"}) if {
	is_dependabot_config
}

updates contains object.union(update, {
	"kind": "dependabot_update",
	"ecosystem_name": update["package-ecosystem"],
	"ecosystem_index": update_index,
}) if {
	is_dependabot_config
	some update_index, update in input.updates
}
