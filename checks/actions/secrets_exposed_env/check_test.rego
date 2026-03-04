package github.actions.secrets_exposed_env_test

import data.github.actions.secrets_exposed_env as check

test_secret_context_leak_disallowed if {
	result := check.deny with input as {"env": {"SECRETS": "${{ toJson(secrets) }}"}}

	count(result) > 0
}

test_secret_context_safe_secret_access_allowed if {
	result := check.deny with input as {"env": {"API_KEY": "${{ secrets.API_KEY }}"}}

	count(result) == 0
}

test_secret_context_raw_secrets_export_disallowed if {
	result := check.deny with input as {"env": {"CTX": "${{ secrets }}"}}

	count(result) > 0
}

test_secret_context_array_env_scan if {
	result := check.deny with input as {"env": {"CTX": "${{ base64(secrets) }}"}}

	count(result) > 0
}
