package github.actions.pwn_request_code_execution_test

import data.github.actions.pwn_request_code_execution as check

test_pwn_request_makefile_execution if {
	result := check.deny with input as {
		"on": {"pull_request_target": {}},
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.ref }}"}},
			{"run": "make build"},
		]}},
	}

	count(result) > 0
}

test_pwn_request_npm_install if {
	result := check.deny with input as {
		"on": {"pull_request_target": {}},
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}},
			{"run": "npm install"},
		]}},
	}

	count(result) > 0
}

test_pwn_request_bash_script if {
	result := check.deny with input as {
		"on": {"pull_request_target": {}},
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}},
			{"run": "./scripts/build.sh"},
		]}},
	}

	count(result) > 0
}

test_pwn_request_local_action if {
	result := check.deny with input as {
		"on": ["pull_request_target"],
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4", "with": {"ref": "refs/pull/${{ github.event.pull_request.number }}/merge"}},
			{"uses": "./.github/actions/build"},
		]}},
	}

	count(result) > 0
}

test_safe_pull_request_workflow if {
	result := check.deny with input as {
		"on": {"pull_request": {}},
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4"},
			{"run": "make build"},
		]}},
	}

	count(result) == 0
}

test_safe_pull_request_target_without_fork_checkout if {
	result := check.deny with input as {
		"on": {"pull_request_target": {}},
		"jobs": {"build": {"steps": [
			{"uses": "actions/checkout@v4", "with": {"ref": "refs/heads/main"}},
			{"uses": "./.github/actions/build"},
		]}},
	}

	count(result) == 0
}
