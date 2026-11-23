# Policy tests (starter, UNTESTED). Run: conftest verify --policy policy
package main

import rego.v1

base := {"findings": [], "components": [], "images": [], "actions": [], "config": {"allowed_install_scripts": []}}

test_clean_input_passes if {
	count(deny) == 0 with input as base
}

test_new_unpinned_image_denied if {
	inp := object.union(base, {"images": [{"ref": "node:18", "digest": null, "tag": "18", "new": true}]})
	count(deny) == 1 with input as inp
}

test_unreviewed_install_script_denied if {
	inp := object.union(base, {"components": [{"purl": "pkg:npm/x@1.0.0", "name": "x", "has_install_script": true, "origin_trusted": true, "new": true}]})
	count(deny) == 1 with input as inp
}

test_reviewed_install_script_allowed if {
	inp := object.union(base, {
		"components": [{"purl": "pkg:npm/x@1.0.0", "name": "x", "has_install_script": true, "origin_trusted": true, "new": true}],
		"config": {"allowed_install_scripts": ["x"]},
	})
	count(deny) == 0 with input as inp
}

test_unpinned_third_party_action_denied if {
	inp := object.union(base, {"actions": [{"uses": "someone/thing@v1", "pinned_sha": false, "first_party": false, "new": true}]})
	count(deny) == 1 with input as inp
}

test_existing_violations_only_warn if {
	inp := object.union(base, {
		"components": [{"purl": "pkg:npm/old@1.0.0", "name": "old", "has_install_script": true, "origin_trusted": true, "new": false}],
		"actions": [{"uses": "someone/thing@master", "pinned_sha": false, "first_party": false, "new": false}],
	})
	count(deny) == 0 with input as inp
	count(warn) == 2 with input as inp
}
