# METADATA
# title: Require GitHub Actions and Workflows to be pinned by commit SHA
# description: |
#   Referencing GitHub Actions and Workflows using mutable references such as tags or branch names
#   (for example @v3 or @main) introduces supply chain risk.
#
#   Pinning actions to a full commit SHA ensures dependency immutability and prevents
#   unexpected code changes from being executed during workflow runs.
#
# scope: package
# custom:
#   id: GHA-0001
#   provider: github-actions
#   severity: HIGH
#   short_code: unpinned-dependency
#   recommended_action: Pin external or third-party GitHub Actions and reusable workflows to a full commit SHA.
#   input:
#     selector:
#       - type: yaml
package github.actions.unpinned_dependency

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, job) if {
	some job in actions.jobs

	actions.reusable_workflow_call(job)
	not actions.is_pinned_to_full_sha(job.uses)
}

deny contains common.report(metadata, step) if {
	some step in actions.steps
	is_untrusted_external_dependency(step.uses)
}

deny contains common.report(metadata, step) if {
	some step in actions.composite_steps
	is_untrusted_external_dependency(step.uses)
}

is_untrusted_external_dependency(uses) if {
	not actions.is_local_action(uses)
	not actions.is_docker_action(uses)
	not actions.is_pinned_to_full_sha(uses)
}
