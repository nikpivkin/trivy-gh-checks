package github.actions.default_job_permissions_test

import data.github.actions.default_job_permissions as check

test_job_permissions_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"permissions": {}}}}

	count(result) > 0
}

test_job_permissions_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"permissions": {"contents": "read"}}}}

	count(result) == 0
}
