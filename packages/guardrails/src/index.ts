export * from "./types.ts";
export { allRules, blocksDeploy, scan, type ScanResult } from "./engine.ts";
export { snapshotFromFiles } from "./snapshot.ts";
export { renderAuto, renderSupervise } from "./report.ts";
export { redact } from "./util.ts";

// Phase 1: attack-surface inventory.
export {
  type Door,
  type Inventory,
  type Sanitizer,
  type Sink,
  type SinkKind,
  type SourceKind,
  type TaintSource,
} from "./analysis/inventory.ts";

// Phase 2: deterministic oracle.
export {
  analyseTaint,
  type AttackProposal,
  type ConfirmedAttack,
  type TaintPath,
  type Verdict,
} from "./analysis/oracle.ts";

// The verifier: decides a claimed way in, using rules only.
export {
  verifyAll,
  verifyClaim,
  type Claim,
  type ClaimVerdict,
  type VerifiedClaim,
} from "./analysis/verify.ts";

// Phase 3: attack simulation (provider-agnostic).
export {
  createClaudeProposer,
  nullProposer,
  parseProposals,
  ProposerRefusedError,
  PROPOSAL_SCHEMA,
  type AnthropicLike,
  type AttackProposer,
  type ProposerContext,
} from "./analysis/proposer.ts";

// Phase 4: the ten-module review.
export {
  buildReview,
  moduleSkeleton,
  type ActionItem,
  type Grade,
  type ItemStatus,
  type ReviewModule,
  type Risk,
  type Unproven,
  type OwnershipGap,
  type SecurityReview,
} from "./review/modules.ts";

export {
  projectChecks,
  runProjectChecks,
  type CheckOutcome,
  type ProjectCheck,
} from "./review/checks.ts";

export { runSecurityReview, type ReviewOptions, type ReviewResult } from "./review/pipeline.ts";
export {
  checkKnownVulnerabilities,
  createOsvSource,
  installedDependencies,
  OSV_NOTICE,
  type Advisory,
  type Dependency,
  type VulnerabilitySource,
} from "./review/vulnerabilities.ts";
