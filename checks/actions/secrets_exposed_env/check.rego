# METADATA
# title: Avoid exporting full secrets context into environment variables
# description: |
#   Exporting the entire secrets context (for example using serialization such as
#   toJson(secrets)) into workflow, job or step environment variables exposes repository
#   secrets during runtime execution.
#
#   This approach makes auditing secret usage more difficult and complicates secret
#   lifecycle management.
#
#   Secrets should be passed individually by name following the principle of least privilege.
#
# scope: package
# custom:
#   id: GHA-0003
#   provider: github-actions
#   severity: CRITICAL
#   short_code: secrets-exposed-env
#   recommended_action: |
#     Pass secrets individually using ${{ secrets.NAME }} instead of exporting
#     the full secrets context object.
#   input:
#     selector:
#       - type: yaml
package github.actions.secrets_exposed_env

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, actions.workflow) if {
	some value in actions.workflow.env
	actions.secrets_reference(value)
}

deny contains common.report(metadata, job) if {
	some job in actions.jobs
	some value in job.env
	actions.secrets_reference(value)
}

deny contains common.report(metadata, step) if {
	some step in actions.steps
	some value in step.env
	actions.secrets_reference(value)
}

deny contains common.report(metadata, step) if {
	some step in actions.composite_steps
	some value in step.env
	actions.secrets_reference(value)
}
