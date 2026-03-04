package github.actions.checkout_persist_credentials_test

import data.github.actions.checkout_persist_credentials as check

test_checkout_without_persist_credentials_allowed if {
	result := check.deny with input as {"jobs": {"build": {"steps": [{
		"uses": "actions/checkout@v4",
		"with": {"persist-credentials": false},
	}]}}}

	count(result) == 0
}

test_checkout_with_default_persist_credentials_denied if {
	result := check.deny with input as {"jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}}}

	count(result) > 0
}

test_checkout_with_persist_credentials_denied if {
	result := check.deny with input as {"jobs": {"build": {"steps": [{
		"uses": "actions/checkout@v4",
		"with": {"persist-credentials": true},
	}]}}}

	count(result) > 0
}
