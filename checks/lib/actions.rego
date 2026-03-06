# METADATA
# custom:
#   library: true
#   input:
#     selector:
#       - type: yaml
package github.lib.actions

import rego.v1

# https://github.com/SchemaStore/schemastore/blob/50c67fbe14831dedee0fbf4215623021152abc8f/src/schemas/json/github-workflow.json#L1838
is_workflow if {
	input.on
	input.jobs
}

workflow := object.union(input, {
	"kind": "workflow",
	"workflow_name": object.get(input, "name", ""),
}) if {
	is_workflow
}

jobs contains enrich_job(job, job_key) if {
	is_workflow
	some job_key, job in input.jobs
}

enrich_job(job, job_key) := object.union(job, {
	"kind": "job",
	"workflow_name": object.get(input, "name", ""),
	"job_key": job_key,
	"job_name": object.get(job, "name", ""),
})

steps contains enrich_step(enrich_job(job, job_key), step, step_index) if {
	is_workflow
	some job_key, job in input.jobs
	some step_index, step in job.steps
}

enrich_step(job, step, step_index) := object.union(step, {
	"kind": "step",
	"workflow_name": object.get(input, "name", ""),
	"job_key": object.get(job, "job_key", ""),
	"job_name": object.get(job, "name", ""),
	"step_index": step_index,
	"step_name": object.get(step, "name", ""),
})

default is_composite_action := false

is_composite_action if {
	input.runs.using == "composite"
}

composite_action contains object.union(input, {
	"kind": "composite_action",
	"action_name": object.get(input, "name", ""),
}) if {
	is_composite_action
}

composite_steps contains object.union(raw_step, {
	"kind": "composite_step",
	"action_name": object.get(input, "name", ""),
	"step_index": step_index,
	"step_name": object.get(raw_step, "name", ""),
}) if {
	is_composite_action
	some step_index, raw_step in input.runs.steps
}

secrets_reference(expr) if {
	startswith(expr, "${{")

	not contains(expr, "secrets.")
	not contains(expr, "secrets[")
	contains(expr, "secrets")
}

is_pinned_to_full_sha(uses) if {
	parts := split(uses, "@")
	count(parts) == 2

	ref := parts[1]
	regex.match("^[a-f0-9]{40}$", ref)
}

reusable_workflow_call(job) if {
	contains(job.uses, ".github/workflows/")
	contains(job.uses, "@")
}

is_local_action(uses) if {
	startswith(uses, "./")
}

is_docker_action(uses) if {
	startswith(uses, "docker://")
}

workflow_has_trigger(trigger) if {
	is_array(workflow.on)
	some t in workflow.on
	t == trigger
}

workflow_has_trigger(trigger) if {
	is_object(workflow.on)
	some t, _ in workflow.on
	t == trigger
}
