package github.actions.overly_broad_permissions_test

import data.github.actions.overly_broad_permissions as check

test_workflow_permissions_write_all_disallowed if {
	result := check.deny with input as {"permissions": "write-all"}

	count(result) > 0
}

test_workflow_permissions_fine_grained_allowed if {
	result := check.deny with input as {"permissions": {"contents": "read"}}

	count(result) == 0
}

test_mixed_permissions_write_all_disallowed if {
	result := check.deny with input as {
		"permissions": {"contents": "read"},
		"jobs": {"build": {"permissions": "write-all"}},
	}

	count(result) > 0
}

test_job_permissions_write_all_disallowed if {
	result := check.deny with input as {"jobs": {"build": {"permissions": "write-all"}}}

	count(result) > 0
}

test_job_permissions_write_all_allowed if {
	result := check.deny with input as {"jobs": {"build": {"permissions": {"contents": "read"}}}}

	count(result) == 0
}
