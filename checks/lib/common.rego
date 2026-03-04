# METADATA
# custom:
#   library: true
#   input:
#     selector:
#       - type: yaml
package github.lib.common

import rego.v1

checks_config := data.github.actions.config

check_config(metadata) := object.get(
	checks_config,
	metadata.annotations.custom.id,
	object.get(
		checks_config,
		metadata.annotations.custom.short_code,
		{},
	),
)

package_metadata(chain) := metadata if {
	some metadata in chain
	metadata.annotations.scope == "package"
}

title(metadata) := object.get(metadata.annotations, ["title"], "<no_title>")

is_check_disabled(cfg) if {
	cfg.disabled == true
} else := false

report(metadata, ctx) := res if {
	not is_check_disabled(check_config(metadata))
	res := result.new(sprintf("%s\n%s", [title(metadata), build_evidence_string(ctx)]), {})
}

build_evidence_string(ctx) := evidence if {
	ctx.kind == "workflow"
	evidence := concat("\n", [sprintf("Workflow: %v", [object.get(ctx, "workflow_name", "-")])])
}

build_evidence_string(ctx) := evidence if {
	ctx.kind == "job"
	evidence := concat("\n", [
		sprintf("Workflow: %v", [object.get(ctx, "workflow_name", "-")]),
		sprintf("Job: %v (key %v)", [
			object.get(ctx, "job_name", "-"),
			object.get(ctx, "job_key", "-"),
		]),
	])
}

build_evidence_string(ctx) := evidence if {
	ctx.kind == "step"
	evidence := concat("\n", [
		sprintf("Workflow: %v", [object.get(ctx, "workflow_name", "-")]),
		sprintf("Job: %v (key %v)", [
			object.get(ctx, "job_name", "-"),
			object.get(ctx, "job_key", "-"),
		]),
		sprintf("Step: %v (index %v)", [
			object.get(ctx, "step_name", "-"),
			object.get(ctx, "step_index", "-"),
		]),
		sprintf("Uses: %v", [object.get(ctx, "uses", "-")]),
	])
}

build_evidence_string(ctx) := evidence if {
	ctx.kind == "composite_action"
	evidence := concat("\n", [sprintf("Composite action: %v", [object.get(ctx, "action_name", "-")])])
}

build_evidence_string(ctx) := evidence if {
	ctx.kind == "composite_step"
	evidence := concat("\n", [
		sprintf("Composite action: %v", [object.get(ctx, "action_name", "-")]),
		sprintf("Step: %v (index %v)", [
			object.get(ctx, "step_name", "-"),
			object.get(ctx, "step_index", "-"),
		]),
	])
}

build_evidence_string(ctx) := "-" if {
	not ctx.kind in {"workflow", "job", "step", "composite_action", "composite_step"}
}
