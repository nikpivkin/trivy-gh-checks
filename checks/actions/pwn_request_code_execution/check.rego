# METADATA
# title: Possible Pwn Request via code execution in pull_request_target workflow
# description: |
#   Workflows triggered by pull_request_target run with repository privileges
#   and access to secrets. If the workflow checks out code from the pull request
#   and executes code from the repository (for example via build tools or scripts),
#   an attacker can modify those files in a fork and execute arbitrary code.
#
#   This vulnerability is commonly known as a "Pwn Request".
#
#   Avoid executing repository code in pull_request_target workflows or ensure
#   that untrusted pull request code is never checked out.
#
# scope: package
# custom:
#   id: GHA-0020
#   provider: github-actions
#   severity: CRITICAL
#   short_code: pwn-request
#   recommended_action: |
#     Do not execute repository code in pull_request_target workflows.
#
#     Use pull_request instead, or avoid checking out and running code from
#     the pull request before validating it.
#   input:
#     selector:
#       - type: yaml
package github.actions.pwn_request_code_execution

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(
	metadata,
	ctx,
) if {
	actions.workflow_has_trigger("pull_request_target")

	some job in actions.jobs
	some checkout in fork_checkout_steps(job)

	some step_index, step in job.steps
	step_index > checkout.step_index
	some execution_detail in pr_code_execution_details(step)
	ctx := object.union(
		actions.enrich_step(job, step, step_index),
		{"message": sprintf("Workflow step executes pull request code via %v", [execution_detail])},
	)
}

# steps_after(step_list, base_step) := [s |
# 	some s in step_list
# 	s.step_index > base_step.step_index
# ]

fork_checkout_steps(job) := [actions.enrich_step(job, step, step_index) |
	some step_index, step in job.steps
	is_checkout_step(step)
	is_checkout_ref(step.with.ref)
]

pr_code_execution_details(step) := [sprintf("executes code via action %v", [step.uses])] if {
	actions.is_local_action(step.uses)
}

pr_code_execution_details(step) := [sprintf("executes repository code via %v", [execution_source])] if {
	execution_source := executes_repo_code(step)
}

fork_checkout_ref_patterns := {
	`github\.event\.pull_request\.(head|merge_commit_sha)`,
	`github\.head_ref`,
	`refs/pull/.*/(head|merge)`,
}

is_checkout_ref(ref) if {
	some pattern in fork_checkout_ref_patterns
	regex.match(pattern, ref)
}

is_checkout_step(step) if startswith(step.uses, "actions/checkout@")

executes_repo_code(step) := source if {
	run := lower(step.run)
	some pattern, source in repo_code_command_hooks

	# TODO: use regex.find_all and return multiple sources
	regex.match(pattern, run)
}

# TODO: consider using mvdan.cc/sh/v3
repo_code_command_hooks := {
	`bash\s`: "shell script file",
	`sh\s`: "shell script file",
	`(^|\s)\./[^\s]+`: "executable script in repository",
	`source\s`: "shell script file",
	`python3?\s`: "Python scripts in repo",
	`node\s`: "JavaScript entry scripts",
	`make\s`: "Makefile targets",
	`npm\s+install`: "package.json lifecycle hooks (preinstall, postinstall, prepare)",
	`npm\s+ci`: "package.json lifecycle hooks (prepare)",
	`yarn\s+install`: "package.json lifecycle scripts",
	`pnpm\s+install`: "package.json lifecycle scripts",
	`pip\s+install\s+\.`: "Python build hooks (setup.py, pyproject.toml)",
	`go\s+run`: "Go project sources",
	`cargo\s+(run|build)`: "Rust project build scripts",
}
