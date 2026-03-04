package github.actions.trusted_sources_test

import data.github.actions.trusted_sources as check

test_workflow_call_trusted_org_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"uses": "trusted-owner/reusable-workflow/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"}}}
		with data.github.actions.config.trusted_sources.patterns as ["trusted-owner"]

	count(result) == 0
}

test_workflow_call_untrusted_org_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"uses": "evil-org/reusable-workflow/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567"}}}
		with data.github.actions.config.trusted_sources.patterns as ["trusted-owner"]

	count(result) > 0
}

test_action_trusted_action_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{"uses": "trusted-owner/action-name@0123456789abcdef0123456789abcdef01234567"}]}}}
		with data.github.actions.config.trusted_sources.patterns as ["trusted-owner"]

	count(result) == 0
}

test_action_local_action_allowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{"uses": "./actions/my-action"}]}}}
		with data.github.actions.config.trusted_sources.patterns as ["trusted-owner"]

	count(result) == 0
}

test_action_untrusted_action_disallowed if {
	result := check.deny with input as {"on": {"workflow_dispatch": {}}, "jobs": {"build": {"steps": [{"uses": "evil-org/evil-action@0123456789abcdef0123456789abcdef01234567"}]}}}
		with data.github.actions.config.trusted_sources.patterns as ["trusted-owner"]

	count(result) > 0
}
