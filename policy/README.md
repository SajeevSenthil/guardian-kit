# Sample policies (policy-as-code)

Starter Rego for Conftest / OPA. **Untested**: written without conftest available. In phase 10,
run `conftest verify --policy policy` and fix syntax for the installed OPA version (Rego v1
needs `if` and `contains`), then keep the tests green.

Input document (`runs/<id>/policy-input.json`, built by `guardian/tools/policy.py`):

```json
{
  "findings":   [{"id": "F-0001", "type": "typosquat", "band": "critical", "kev": false,
                  "scope": "prod", "status": "open", "component": "pkg:npm/..."}],
  "components": [{"purl": "pkg:npm/...", "has_install_script": true, "origin_trusted": false,
                  "name": "...", "new": true}],
  "images":     [{"ref": "node:18", "digest": null, "tag": "18", "new": true}],
  "actions":    [{"uses": "owner/repo@v1", "pinned_sha": false, "first_party": false, "new": true}],
  "config":     {"allowed_install_scripts": []}
}
```

`new` means introduced since the baseline ref. The gate blocks what a change introduces and
warns about what was already there. `deny` fails the gate; `warn` is shown but does not block.
More rule ideas with sketches: `docs/research/04-prioritise-remediate-validate-stretch.md` §6.4.
