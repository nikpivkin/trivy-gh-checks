package github.dependabot.cooldown_test

import data.github.dependabot.cooldown as check

import rego.v1

test_deny_when_cooldown_missing if {
	results := check.deny with input as {
		"version": 2,
		"updates": [{
			"package-ecosystem": "gomod",
			"directory": "/",
			"schedule": {"interval": "daily"},
		}],
	}

	count(results) > 0
}

test_deny_when_cooldown_too_low if {
	results := check.deny with input as {
		"version": 2,
		"updates": [{
			"package-ecosystem": "gomod",
			"directory": "/",
			"schedule": {"interval": "daily"},
			"cooldown": {"default-days": 3},
		}],
	}

	count(results) > 0
}

test_allow_when_cooldown_valid if {
	results := check.deny with input as {
		"version": 2,
		"updates": [{
			"package-ecosystem": "gomod",
			"directory": "/",
			"schedule": {"interval": "daily"},
			"cooldown": {"default-days": 7},
		}],
	}

	count(results) == 0
}
