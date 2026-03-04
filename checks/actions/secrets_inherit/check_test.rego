package github.actions.secrets_inherit_test

import data.github.actions.secrets_inherit as check

test_secrets_inherit_disallowed if {
	result := check.deny with input as {"jobs": {"build": {
		"uses": "org/reusable-workflow/.github/workflows/build.yml",
		"secrets": "inherit",
	}}}

	count(result) > 0
}

test_secrets_inherit_allowed if {
	result := check.deny with input as {"jobs": {"build": {"uses": "org/reusable-workflow/.github/workflows/build.yml"}}}

	count(result) == 0
}
