# METADATA
# title: Disable 'persist-credentials' for 'actions/checkout' when not required
# description: |
#   The 'actions/checkout' action stores the GITHUB_TOKEN in '.git/config' by default
#   (persist-credentials: true). This allows any subsequent step in the workflow
#   to access the token, even if it does not require repository write access.
#
#   Setting 'persist-credentials: false' for checkout steps that do not need
#   git push capabilities reduces the attack surface and mitigates the risk
#   of credential theft through compromised dependencies or scripts.
#
# scope: package
# custom:
#   id: GHA-0010
#   provider: github-actions
#   severity: MEDIUM
#   short_code: checkout-persist-credentials
#   recommended_action: Set 'persist-credentials' to false on 'actions/checkout' steps unless git push access is explicitly required.
#   input:
#     selector:
#       - type: yaml
package github.actions.checkout_persist_credentials

import rego.v1

import data.github.lib.actions
import data.github.lib.common

metadata := common.package_metadata(rego.metadata.chain())

deny contains common.report(metadata, step) if {
	some step in actions.steps

	is_checkout(step)
	not persist_credentials_disabled(step)
}

is_checkout(step) if {
	startswith(step.uses, "actions/checkout@")
}

persist_credentials_disabled(step) if {
	step.with["persist-credentials"] == false
}
