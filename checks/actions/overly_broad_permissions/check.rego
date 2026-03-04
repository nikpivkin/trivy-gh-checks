# METADATA
# title: Disallow overly broad write-all permissions (workflow and job level)
# description: |
#   Using write-all permissions grants excessive repository access to GitHub Actions workflows and jobs.
#   Prefer defining fine-grained permission scopes at workflow or job level to reduce blast radius
#   in case of workflow or action compromise.
#
# scope: package
# custom:
#   id: GHA-0011
#   provider: github-actions
#   severity: MEDIUM
#   short_code: overly-broad-permissions
#   recommended_action: Specify minimal required permissions instead of using write-all at workflow or job level.
#   input:
#     selector:
#       - type: yaml
package github.actions.overly_broad_permissions

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, actions.workflow) if {
	is_write_all_permissions(actions.workflow)
}

deny contains common.report(metadata, job) if {
	some job in actions.jobs

	is_write_all_permissions(job)
}

is_write_all_permissions(node) if {
	node.permissions == "write-all"
}
