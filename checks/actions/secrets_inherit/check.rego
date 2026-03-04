# METADATA
# title: Avoid using "secrets inherit" in reusable workflows
# description: |
#   Using secrets: inherit in reusable workflows automatically passes all repository
#   secrets to the called workflow, which may expose more data than necessary.
#
#   Instead, explicitly define only the secrets required by the reusable workflow
#   to follow the principle of least privilege.
#
# scope: package
# custom:
#   id: GHA-0005
#   provider: github-actions
#   severity: HIGH
#   short_code: secrets-inherit
#   recommended_action: |
#     Avoid using secrets: inherit and explicitly pass only the required secrets
#     to reusable workflows.
#   input:
#     selector:
#       - type: yaml
package github.actions.secrets_inherit

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, job) if {
	some job in actions.jobs

	reusable_workflow_call(job)
	job.secrets == "inherit"
}

reusable_workflow_call(job) if job.uses != ""
