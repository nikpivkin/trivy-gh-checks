package github.actions.unpinned_dependency_test

import data.github.actions.unpinned_dependency as check

test_action_not_pinned_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{
		"name": "Checkout",
		"uses": "actions/checkout@v4",
	}]}}}

	count(result) > 0
}

test_action_pinned_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{
		"name": "Checkout",
		"uses": "actions/checkout@3df4f2c5b4c2c3a6b6c5a4e3f2d1c0b9a8e7d6c5",
	}]}}}

	count(result) == 0
}

test_local_action_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{
		"name": "Local action",
		"uses": "./.github/actions/build",
	}]}}}

	count(result) == 0
}

test_docker_action_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{
		"name": "Docker action",
		"uses": "docker://alpine:3.19",
	}]}}}

	count(result) == 0
}

test_composite_action_pinned_allowed if {
	result := check.deny with input as {"runs": {
		"using": "composite",
		"steps": [{
			"name": "Composite step",
			"uses": "actions/checkout@3df4f2c5b4c2c3a6b6c5a4e3f2d1c0b9a8e7d6c5",
		}],
	}}

	count(result) == 0
}

test_composite_action_unpinned_disallowed if {
	result := check.deny with input as {"runs": {
		"using": "composite",
		"steps": [{
			"name": "Composite step",
			"uses": "actions/checkout@v4",
		}],
	}}

	count(result) > 0
}

test_workflow_ref_pinned_sha_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"uses": "org/reusable-workflow/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"}}}

	count(result) == 0
}

test_workflow_ref_branch_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"uses": "org/reusable-workflow/.github/workflows/build.yml@main"}}}

	count(result) > 0
}

test_workflow_ref_tag_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"uses": "org/reusable-workflow/.github/workflows/build.yml@v1"}}}

	count(result) > 0
}
