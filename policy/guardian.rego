# Guardian supply-chain policy (starter, UNTESTED - see policy/README.md).
#
# The gate judges what a change INTRODUCES. Violations that already exist at the baseline
# (new == false) are warnings, otherwise no build of a legacy application could ever pass.
# Open critical findings and KEV entries block regardless of age.
package main

import rego.v1

deny contains msg if {
	some f in input.findings
	f.status == "open"
	f.band == "critical"
	f.scope == "prod"
	msg := sprintf("critical finding %s open on production component %s", [f.id, f.component])
}

deny contains msg if {
	some f in input.findings
	f.status == "open"
	f.kev == true
	msg := sprintf("finding %s is in the CISA KEV catalogue", [f.id])
}

deny contains msg if {
	some c in input.components
	c.new == true
	c.has_install_script == true
	not c.name in input.config.allowed_install_scripts
	msg := sprintf("new component %s runs an install script that is not on the reviewed allow-list", [c.purl])
}

warn contains msg if {
	some c in input.components
	c.new == false
	c.has_install_script == true
	not c.name in input.config.allowed_install_scripts
	msg := sprintf("existing component %s runs an unreviewed install script", [c.purl])
}

deny contains msg if {
	some c in input.components
	c.new == true
	c.origin_trusted == false
	msg := sprintf("new component %s does not come from a trusted registry", [c.purl])
}

deny contains msg if {
	some i in input.images
	i.new == true
	i.digest == null
	msg := sprintf("changed image reference %s is not pinned by digest", [i.ref])
}

warn contains msg if {
	some i in input.images
	i.new == false
	i.digest == null
	msg := sprintf("image %s is not pinned by digest", [i.ref])
}

deny contains msg if {
	some a in input.actions
	a.new == true
	a.first_party == false
	a.pinned_sha == false
	msg := sprintf("new third-party action %s is not pinned to a commit SHA", [a.uses])
}

warn contains msg if {
	some a in input.actions
	a.new == false
	a.first_party == false
	a.pinned_sha == false
	msg := sprintf("existing third-party action %s is not pinned to a commit SHA", [a.uses])
}

warn contains msg if {
	some c in input.components
	c.origin_trusted == null
	msg := sprintf("origin of %s could not be determined (unknown is not trusted)", [c.purl])
}
