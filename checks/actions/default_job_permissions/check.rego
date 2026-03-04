# METADATA
# title: Require explicit job-level permissions declaration
# description: |
#   Jobs should explicitly define permission scopes instead of relying on
#   workflow default permissions. Explicitly limiting token permissions reduces
#   risk of unauthorized repository access in GitHub Actions workflows.
#
# scope: package
# custom:
#   id: GHA-0002
#   provider: github-actions
#   severity: MEDIUM
#   short_code: default-job-permissions
#   recommended_action: Define minimal required permissions inside each job using the permissions field.
#   input:
#     selector:
#       - type: yaml
package github.actions.default_job_permissions

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, job) if {
	some job in actions.jobs

	not is_permissions_defined(job)
}

is_permissions_defined(job) if {
	count(object.keys(object.get(job, "permissions", {}))) > 0
}
