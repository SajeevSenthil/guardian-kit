"""Data contracts for the Supply Chain Guardian.

This file is the single source of truth for every object that crosses a stage boundary,
is shown in the UI, or is written to the report. It is starter code shipped with the kit:
extend it, but keep the three rules below true, because the whole product rests on them.

RULE 1  Evidence is minted only by tools.
        An Evidence record is created by `guardian.ledger` when a tool wrapper runs.
        No LLM output may create, edit or invent an evidence id.

RULE 2  Every claim is typed, and only code may write facts.
        VERIFIED  a fact rendered BY CODE from structured tool output (a template filled with
                  fields of one evidence record). Agents can never produce a VERIFIED claim.
        DERIVED   computed by deterministic code from verified facts (a diff, a score).
        INFERRED  a model judgement. Always shown as inference, always carries the model name.
                  It may cite evidence ids and literal `quotes` as support; the ledger checks
                  that the ids exist and the quotes really occur in that evidence, and marks
                  the claim `support_checked`. Anything an agent labels "verified" is coerced
                  to INFERRED.

RULE 3  Unknown is never zero.
        A missing signal is `None` + grade UNKNOWN. It takes a stated prior, lowers
        confidence and is displayed as "unknown", never as "safe".
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "1.0"


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- evidence


class EvidenceKind(str, Enum):
    TOOL_OUTPUT = "tool_output"  # stdout/JSON of a scanner or CLI
    FILE_EXCERPT = "file_excerpt"  # lines from a file in the target repo or a package tarball
    API_RESPONSE = "api_response"  # OSV, EPSS, KEV, registry, deps.dev ...
    GIT_DIFF = "git_diff"
    BUILD_LOG = "build_log"
    TEST_RESULT = "test_result"


class Evidence(BaseModel):
    """One reproducible observation. Immutable once written to the ledger."""

    id: str = Field(pattern=r"^E-\d{4,}$")
    kind: EvidenceKind
    source: str  # tool name or API host, e.g. "grype", "api.osv.dev"
    source_version: str | None = None
    command: str | None = None  # exact command line or request, secrets redacted
    locator: str | None = None  # file:line, JSON pointer or URL that pins the excerpt
    excerpt: str = Field(max_length=4000)  # smallest self-contained piece that supports a claim:
    # one finding object, one lockfile entry, a few source lines.
    # Mint ONE evidence record per fact, not one per tool run.
    raw_path: str | None = None  # runs/<run>/evidence/E-0001.json (full raw output)
    sha256: str  # hash of the raw output as stored (after redaction)
    captured_at: datetime = Field(default_factory=utcnow)
    synthetic: bool = False  # True for replayed fixtures; shown as "SYNTHETIC" in the UI


class ClaimStatus(str, Enum):
    VERIFIED = "verified"
    DERIVED = "derived"
    INFERRED = "inferred"


class Claim(BaseModel):
    text: str
    status: ClaimStatus
    evidence_ids: list[str] = Field(default_factory=list)
    quotes: list[str] = Field(default_factory=list)  # literal substrings of the cited evidence
    support_checked: bool | None = None  # set by ledger.check_claim: True = every cited id exists
    # and every quote was found; False = some support was
    # dropped; None = nothing cited
    derived_by: str | None = None  # function name, for VERIFIED (the renderer) and DERIVED
    model: str | None = None  # model name, for INFERRED
    agent: str | None = None  # which agent wrote it

    @model_validator(mode="after")
    def _typed_claims_are_backed(self) -> Claim:
        if self.status is ClaimStatus.VERIFIED and not (self.derived_by and self.evidence_ids):
            raise ValueError("a VERIFIED claim is rendered by code: it needs derived_by and evidence ids")
        if self.status is ClaimStatus.VERIFIED and (self.model or self.agent):
            raise ValueError("an agent cannot author a VERIFIED claim")
        if self.status is ClaimStatus.DERIVED and not (self.derived_by and self.evidence_ids):
            raise ValueError("a DERIVED claim needs derived_by and the evidence it was computed from")
        if self.status is ClaimStatus.INFERRED and not self.model:
            raise ValueError("an INFERRED claim must name the model that produced it")
        return self


class NotEvaluated(BaseModel):
    """Rule 3 made concrete: something we could not check. Listed in the UI and the report."""

    what: str  # "EPSS enrichment", "image SBOM", "zizmor workflow audit"
    reason: str  # "tool not installed", "no network and no cache", "timeout"
    stage: str
    affects: list[str] = Field(default_factory=list)  # finding ids or requirement ids


# --------------------------------------------------------------------------- inventory


class Scope(str, Enum):
    PROD = "prod"
    DEV = "dev"
    BUILD = "build"  # CI actions, base images, build tools
    UNKNOWN = "unknown"


class Component(BaseModel):
    purl: str  # canonical id from ONE function (guardian.tools.purl). A package
    # resolved from file:/git/another host must not collide with the
    # registry package of the same name: add a qualifier for those.
    lock_path: str | None = None  # lockfile key, e.g. "node_modules/a/node_modules/ms" (the same
    # name@version can be installed at several paths)
    name: str
    version: str | None = None
    ecosystem: Literal["npm", "docker", "github-actions", "os", "other"] = "npm"
    direct: bool = False
    scope: Scope = Scope.UNKNOWN
    origin: str | None = None  # lockfile `resolved` URL, image registry, action repo
    origin_trusted: bool | None = None  # None = not checked (unknown is never "trusted")
    integrity: str | None = None
    has_install_script: bool | None = None
    license: str | None = None
    paths: list[list[str]] = Field(default_factory=list)  # each path: root -> ... -> this component
    evidence_ids: list[str] = Field(default_factory=list)


class Inventory(BaseModel):
    schema_version: str = SCHEMA_VERSION
    target: str
    git_ref: str
    git_commit: str
    components: list[Component]
    sbom_path: str  # CycloneDX JSON
    sbom_generator: str
    edges: list[list[str]] = Field(default_factory=list)  # [parent purl, child purl] pairs
    not_evaluated: list[NotEvaluated] = Field(default_factory=list)


# --------------------------------------------------------------------------- findings


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    KNOWN_MALICIOUS = "known_malicious"
    TYPOSQUAT = "typosquat"
    UNEXPECTED_DEPENDENCY = "unexpected_dependency"
    SUSPICIOUS_UPDATE = "suspicious_update"
    UNSAFE_INSTALL_SCRIPT = "unsafe_install_script"
    UNTRUSTED_SOURCE = "untrusted_source"  # non-registry resolved URL, file:, git:
    INTEGRITY_CHANGE = "integrity_change"
    LOCKFILE_DRIFT = "lockfile_drift"
    UNTRUSTED_IMAGE = "untrusted_image"
    UNPINNED_CI = "unpinned_ci_component"
    UNSAFE_CI = "unsafe_ci_pattern"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    PROVENANCE_GAP = "provenance_gap"
    POLICY_VIOLATION = "policy_violation"


class Grade(str, Enum):
    VERIFIED = "verified"
    HEURISTIC = "heuristic"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class Factor(BaseModel):
    """One named input to the risk score. See docs/ARCHITECTURE.md section 6."""

    name: Literal["severity", "exploitability", "reachability", "exposure", "fix_availability"]
    value: float | None = Field(default=None, ge=0, le=1)  # None = unknown
    prior_used: float | None = None  # set when value is None
    weight: int
    grade: Grade
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    band: Literal["critical", "high", "medium", "low", "info"]
    low: int = Field(ge=0, le=100)  # range when unknown factors take best / worst case
    high: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    factors: list[Factor]
    guardrails_fired: list[str] = Field(default_factory=list)
    explanation: str  # one paragraph, generated from the factors by code


class RefuterVerdict(BaseModel):
    verdict: Literal["upheld", "downgraded", "refuted", "inconclusive"]
    reasons: list[Claim]
    model: str


class Investigation(BaseModel):
    """Day 2 item 2: a non-CVE risk looked at in depth, facts and AI assessment kept apart."""

    timeline: list[Claim] = Field(default_factory=list)  # which commit, what else changed
    version_comparison: list[Claim] = Field(default_factory=list)  # capability diff old -> new
    provenance: list[Claim] = Field(default_factory=list)  # origin, integrity, signatures
    verified_facts: list[Claim] = Field(default_factory=list)  # left column in the UI
    ai_assessment: list[Claim] = Field(default_factory=list)  # right column, all INFERRED
    resembles: str | None = None  # real incident pattern, if any


class Finding(BaseModel):
    id: str = Field(pattern=r"^F-\d{4,}$")
    type: FindingType
    title: str
    component_purl: str
    dependency_paths: list[list[str]] = Field(default_factory=list)
    advisory_ids: list[str] = Field(default_factory=list)  # CVE-..., GHSA-..., MAL-...
    fixed_versions: list[str] = Field(default_factory=list)
    new_in_head: bool | None = None  # True = not present at the base ref
    introduced_by_commit: str | None = None  # for change findings
    scope: Scope = Scope.UNKNOWN
    cvss: float | None = None
    epss: float | None = None  # probability; None = unknown
    epss_percentile: float | None = None
    kev: bool | None = None  # None = unknown, never False by default
    sources: list[str] = Field(default_factory=list)  # scanners/detectors that reported it
    investigation: Investigation | None = None  # non-CVE findings, Day 2
    mirrors_incident: str | None = None  # e.g. "tj-actions/changed-files, Mar 2025"
    claims: list[Claim]
    initial_severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    risk: RiskScore | None = None  # filled on Day 2
    refuter: RefuterVerdict | None = None
    status: Literal["open", "accepted_risk", "not_affected", "remediated", "escalated"] = "open"
    detector: str  # code path or agent that raised it

    @property
    def verified_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.status is not ClaimStatus.INFERRED]


# --------------------------------------------------------------------------- remediation


class ActionKind(str, Enum):
    UPGRADE = "upgrade"
    OVERRIDE = "override"  # npm overrides for a transitive dependency
    REPLACE = "replace"
    REMOVE = "remove"
    PIN = "pin"  # image digest, action SHA, exact version
    UPDATE_BASE_IMAGE = "update_base_image"
    BLOCK = "block"  # policy rule
    MITIGATE = "mitigate"
    ESCALATE = "escalate"  # hand to a human security reviewer


class Prediction(BaseModel):
    findings_resolved: list[str]
    components_added: int | None = None
    components_removed: int | None = None
    new_vulnerabilities: list[str] = Field(default_factory=list)  # advisory ids the change adds
    semver_distance: Literal["patch", "minor", "major", "n/a", "unknown"] = "unknown"
    compatibility_notes: list[Claim] = Field(default_factory=list)


class RemediationAction(BaseModel):
    kind: ActionKind
    target_purl: str
    from_version: str | None = None
    to_version: str | None = None
    patch: str | None = None  # `git format-patch --binary` text (a plain unified diff cannot
    # add or delete the vendored tarballs)
    rationale: list[Claim]


class FixCandidate(BaseModel):
    """One option considered for a finding, with its dry-run prediction."""

    id: str  # "C1", "C2", ...
    summary: str  # "remove dependency and its require() line"
    actions: list[RemediationAction]
    prediction: Prediction | None = None  # None = dry run could not be done
    risk_after: int | None = None
    rank: int | None = None
    rejected_reason: str | None = None  # set when validation or policy turned it down


class RemediationPlan(BaseModel):
    id: str = Field(pattern=r"^P-\d{4,}$")
    finding_ids: list[str]
    actions: list[RemediationAction]
    prediction: Prediction
    expected_risk_before: int
    expected_risk_after: int
    rollback: str  # exact command(s)
    policy_result: Literal["pass", "warn", "fail", "not_evaluated"] = "not_evaluated"
    policy_messages: list[str] = Field(default_factory=list)
    plan_hash: str  # sha256 over actions + patch; approvals bind to this
    candidate_id: str | None = None  # which FixCandidate this plan applies
    alternatives_considered: list[FixCandidate] = Field(default_factory=list)
    supersedes: str | None = None  # earlier plan id that failed validation
    state: Literal[
        "proposed",
        "pending_approval",
        "approved",
        "rejected",
        "applied",
        "validated",
        "validation_failed",
        "rolled_back",
    ] = "proposed"


class Approval(BaseModel):
    plan_id: str
    plan_hash: str  # must equal the plan's current hash or the approval is void
    decision: Literal["approve", "reject", "request_changes"]
    approver: str  # a human name. Never an agent.
    comment: str | None = None
    at: datetime = Field(default_factory=utcnow)


class Check(BaseModel):
    name: str  # "baseline_tests", "build", "tests", "rescan", "sbom_diff", "policy"
    passed: bool | None  # None = could not run (reported as such, never as passed)
    detail: str
    evidence_ids: list[str] = Field(default_factory=list)
    duration_s: float | None = None


class ValidationResult(BaseModel):
    plan_id: str
    work_branch: str  # branch inside the throwaway clone under runs/<id>/work/
    checks: list[Check]
    findings_resolved: list[str]
    findings_remaining: list[str]
    findings_new: list[str]  # anything the fix introduced
    components_added: list[str]
    components_removed: list[str]
    risk_before: int
    risk_after: int
    prediction_matched: bool | None = None
    verdict: Literal["verified", "failed", "partial", "not_run"]


# --------------------------------------------------------------------------- audit + events


class AuditEvent(BaseModel):
    """Append-only, hash-chained. One JSON line per event in runs/<run>/audit.jsonl."""

    seq: int
    at: datetime = Field(default_factory=utcnow)
    actor: str  # "human:<name>", "agent:<name>", "code:<module>"
    action: str  # "tool_run", "finding_raised", "plan_proposed", "approved", ...
    subject: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str  # hash of the previous event; 64 zeros for the first
    hash: str = ""  # sha256 of this event's canonical JSON without `hash`
    # (sorted keys, compact separators); set by guardian.audit


class StageEvent(BaseModel):
    """Progress events streamed to the UI and saved to runs/<run>/events.jsonl for replay."""

    run_id: str
    seq: int = 0  # set by the event bus
    at: datetime = Field(default_factory=utcnow)
    stage: str
    agent: str | None = None
    kind: Literal[
        "stage_start",
        "stage_end",
        "tool_call",
        "tool_result",
        "agent_text",
        "finding",
        "approval_needed",
        "error",
        "info",
    ]
    message: str
    duration_s: float | None = None
    data: dict[str, Any] = Field(default_factory=dict)
