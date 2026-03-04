# METADATA
# title: Require actions, composite actions, and reusable workflows to originate from trusted sources
# description: |
#   References using the uses keyword should point to actions, composite actions,
#   or reusable workflows that originate from trusted organizations or repositories.
#
#   Using workflow execution components from untrusted sources may introduce supply
#   chain risks in workflow automation systems such as
#   GitHub Actions.
#
# scope: package
# custom:
#   id: GHA-0008
#   provider: github-actions
#   severity: MEDIUM
#   short_code: trusted-dependency-sources
#   recommended_action: |
#     Reference actions, composite actions, and reusable workflows only from
#     trusted sources defined in policy configuration data.
#   input:
#     selector:
#       - type: yaml
package github.actions.trusted_sources

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

default trusted_sources := {}

trusted_sources := data.github.actions.config.trusted_sources

deny contains common.report(metadata, job) if {
	some job in actions.jobs
	count(trusted_sources) > 0
	artifact_from_untrusted_source(job.uses)
}

deny contains common.report(metadata, step) if {
	some step in actions.steps
	count(trusted_sources) > 0
	artifact_from_untrusted_source(step.uses)
}

deny contains common.report(metadata, step) if {
	some step in actions.composite_steps
	count(trusted_sources) > 0
	artifact_from_untrusted_source(step.uses)
}

artifact_from_untrusted_source(uses) if {
	not actions.is_local_action(uses)
	not actions.is_docker_action(uses)
	ref := split(uses, "@")[0]
	some trusted_source in trusted_sources
	not startswith(ref, trusted_source)
}
