# METADATA
# title: Require Dependabot dependency cooldown configuration
# description: |
#   Dependabot can be configured with a cooldown period to delay automatic dependency
#   update pull requests for a defined number of days (for example, 7 days).
#
#   Dependency cooldowns reduce the risk of open-source supply chain attacks by
#   avoiding immediate adoption of newly released versions. Newly released packages
#   may be compromised before community vetting is completed, so introducing a waiting
#   period helps reduce exposure to supply chain threats by allowing time for issue
#   detection and remediation in upstream ecosystems.
#
#   By default, the cooldown period is 7 days.
#
# scope: package
# custom:
#   id: GHD-0001
#   provider: github-actions
#   severity: MEDIUM
#   short_code: dependabot-cooldown
#   recommended_action: |
#     Define a dependency cooldown period (for example, 7 days) in your
#     `.github/dependabot.yml` configuration to delay automatic dependency
#     update pull requests. Ensure the cooldown period is at least 7 days to
#     reduce exposure to newly published but potentially risky releases.
#   input:
#     selector:
#       - type: yaml
package github.dependabot.cooldown

import rego.v1

import data.github.lib.common
import data.github.lib.dependabot

metadata := common.package_metadata(rego.metadata.chain())

default minimum_days := 7

config := common.check_config(metadata)

minimum_days := config.minimum_days

deny contains common.report(metadata, object.union(
	update,
	{"message": "Dependabot update does not define cooldown."},
)) if {
	some update in dependabot.updates
	not has_cooldown(update)
}

deny contains common.report(metadata, object.union(
	update,
	{"message": sprintf(
		"Dependabot cooldown is too low (%d days). Minimum recommended is %d days.",
		[days, minimum_days],
	)},
)) if {
	some update in dependabot.updates
	days := update.cooldown["default-days"]
	days < minimum_days
}

has_cooldown(update) if {
	update.cooldown["default-days"]
}
