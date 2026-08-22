/**
 * HaloMem HTTP transport (M1 module B).
 *
 * node:http only — no express. Every request except GET /healthz and
 * GET /healthz/mastra passes the Bearer-key middleware, which resolves the
 * credential to a server-side
 * Identity (D9). Callers NEVER assert namespace/actor: mem bodies containing
 * either field are rejected with 400 "namespace comes from your key".
 *
 * Denial paths (401 unknown/missing key, 403 role) each append an audit row
 * (D4): result 'denied', actor 'unknown' for 401s (no identity resolved) or
 * the resolved actor for 403s, op = the attempted route's op (mem routes map
 * to their own AuditOp; /metrics → 'stats'; admin GETs → 'read', admin
 * mutations → 'write'; /mcp and unknown paths → 'read').
 *
 * MCP Streamable HTTP lives at /mcp: auth happens BEFORE the SDK transport
 * sees the request, then the SDK v2 handler builds a fresh identity-bound
 * McpServer. The same route serves MCP 2026-07-28 and the stateless legacy
 * fallback; tool definitions stay with the integrator and are never duplicated.
 *
 * All error responses are JSON: { error, code }.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, type McpServer } from "@modelcontextprotocol/server";
import type {
  AuditEvent,
  AuditOp,
  Identity,
  Namespace,
  Session,
  SyscallContext,
} from "../types.js";
import { canHuman } from "../console/rbac.js";
import { effectiveAgentLevel } from "../auth/agent-scope.js";
// M10 (D41): the ONE product-role translation seam for the session payload.
import { toProductRole } from "../iam/product-roles.js";
// M10 (D43): preview credential header + the transport read-only predicate.
import {
  PREVIEW_TOKEN_HEADER,
  enforcePreviewReadOnly,
} from "../console/view-as.js";
import {
  httpRouteTemplate,
  type HttpTelemetry,
} from "../observability/http.js";
import {
  OAUTH_STATE_COOKIE,
  safeConsentReturn,
  SESSION_COOKIE,
  SIGNUP_COOKIE,
  clearOAuthStateCookie,
  clearSessionCookie,
  clearSignupCookie,
  parseCookies,
  serveStatic,
  setOAuthStateCookie,
  setSessionCookie,
  setSignupCookie,
} from "./console.js";
// Browser-facing failures render in the Halofy design language (pure renderer).
import { renderHaloStatusPage } from "../branding/halo-page.js";

/** Optional cross-product browser handoff supplied by a commercial host. */
export interface HaloAgentsHandoff {
  readonly issuer: string;
  readonly destination: string;
  createAssertion(identity: Identity): string;
}
// M6 (D13): header-token merge for POST /v1/mem/fault. adapter.ts imports only
// TYPES from this file, so this value import introduces no runtime cycle.
import { withSourceTokens } from "./adapter.js";
// M9 #6: query-param validation for GET /v1/mem/manifest (pure helpers).
import {
  ManifestArgsError,
  parseManifestArgs,
  type ParsedManifestRequest,
} from "../discovery/manifest.js";
// M9 #11a (E28–E30): pure path matcher for the unauthenticated public tier.
import {
  matchPublicDiscoveryPath,
  type PublicDiscoveryFormat,
  type PublicDiscoveryResponse,
} from "../discovery/public.js";
import { mcpChallengeHeader } from "../oauth/server.js";

// ---------------------------------------------------------------------------
// Structural dependency surface (hand-rollable in tests; the integrator wires
// the real kernel behind these shapes).
// ---------------------------------------------------------------------------

export interface HttpAuth {
  /** Plaintext bearer key (`hm_<40 hex>`) → Identity, or null if unknown/revoked. */
  resolve(plaintextKey: string): Promise<Identity | null>;
  /** Verified OIDC bearer JWT to server-mapped Identity. */
  resolveOidc?(token: string): Promise<Identity | null>;
  /**
   * M9 #11b (D29): opaque OAuth bearer (`hmt_<64 hex>`) → server-resolved
   * Identity (assistant → agent, read-only → auditor; never admin/owner), or
   * null on unknown / revoked / expired / transitively-revoked tokens. The
   * kernel token service audits every miss and denial. Optional so
   * hand-rolled/bearer-only deps stay valid — absent → hmt_ bearers 401.
   */
  resolveOauth?(token: string): Promise<Identity | null>;
  /** 60-second Copilot delegation accepted only on the /mcp endpoint. */
  resolveCopilotCapability?(token: string): Promise<Identity | null>;
  /**
   * M5: opaque session token (from the `halomem_session` cookie) → Identity,
   * or null if unknown/expired/disabled. Human callers authenticate by cookie
   * instead of a bearer key; the resolved Identity is the SAME shape syscalls
   * require (role ∈ owner|admin|auditor|member, never agent). Optional so
   * hand-rolled/bearer-only deps stay valid — absent → no cookie auth path.
   */
  resolveSession?(token: string): Promise<Identity | null>;
  /**
   * M5: email+password → { token, user } on success, null on any failure
   * (unknown email, wrong password, disabled user — all collapse to null so
   * login is not an account-enumeration oracle). `token` is the opaque session
   * token to hand back in the cookie; `user` is the public user record. NEVER
   * logs a password or a raw token. Optional so bearer-only deps stay valid.
   */
  login?(
    email: string,
    password: string,
  ): Promise<{ token: string; user: unknown } | null>;
  /**
   * R4B: a strong out-of-band token creates the first organization, its first
   * owner, and a session — once. `organization` is a display NAME; the server
   * derives the tenant id (D9). No product path creates a human at the
   * platform root.
   */
  bootstrap?(input: {
    token: string;
    email: string;
    displayName: string;
    password: string;
    organization: string;
  }): Promise<{ token: string; user: unknown } | null>;
  /** R4B: consume a pending invitation without accepting caller-owned scope. */
  acceptInvite?(token: string, password: string): Promise<unknown | null>;
  /** M5: invalidate the session behind an opaque token (idempotent). Optional. */
  logout?(token: string): Promise<void>;
  /**
   * SSO: public IdP config for the login page ({ enabled:false } when SSO is
   * not configured). Never contains a secret — the Supabase URL and anon key
   * ship in every client bundle by design.
   */
  ssoConfig?(): {
    enabled: boolean;
    url?: string;
    anonKey?: string;
    emailDeliveryReady?: boolean;
  };
  /**
   * SSO: exchange an IdP access token for a kernel session. `ok` mints the
   * cookie; `no_account` means the IdP authenticated the email but no kernel
   * user/invitation authorizes it; `unauthenticated` is any invalid token.
   */
  ssoExchange?(
    accessToken: string,
  ): Promise<
    | { status: "ok"; token: string; user: unknown }
    | { status: "onboarding_required"; signupToken: string; email: string }
    | { status: "no_account"; email: string }
    | { status: "unauthenticated" }
  >;
  /** Resolve a live signup cookie to its verified email, or null. */
  signupPending?(token: string): Promise<{ email: string } | null>;
  /** Atomically create a tenant + first owner and mint the normal session. */
  signupComplete?(
    token: string,
    organizationName: string,
    displayName: string,
  ): Promise<{ token: string; organization: unknown; user: unknown } | null>;
  /**
   * GitHub OAuth: true when HALOMEM_GITHUB_CLIENT_ID/SECRET are configured —
   * the login page shows the button only then. Never secret-bearing.
   */
  githubConfig?(): boolean;
  /** GitHub OAuth: authorization redirect URL for one state nonce. */
  githubAuthorize?(state: string, redirectUri: string): string;
  /**
   * GitHub OAuth login: exchange the callback code, read the profile
   * server-side, resolve the kernel user (linked identity → invitation →
   * auto-provision). `ok` mints the cookie.
   */
  githubLogin?(
    code: string,
    redirectUri: string,
  ): Promise<
    | { status: "ok"; token: string; user: unknown }
    | { status: "no_account" }
    | { status: "unauthenticated" }
  >;
  /**
   * GitHub OAuth link (Profile screen): exchange + profile, then link to the
   * signed-in user's account. `conflict` = the GitHub account belongs to a
   * different user (or the user already linked a different GitHub account).
   */
  githubLink?(
    code: string,
    redirectUri: string,
    identity: Identity,
  ): Promise<
    | { status: "linked"; login: string }
    | { status: "conflict" }
    | { status: "unauthenticated" }
  >;
  /**
   * Connect a Google account to the signed-in user (Profile screen). The
   * Supabase access token proves the Google side; the session cookie proves
   * the kernel side. `conflict` = that Google account belongs to a different
   * user (or another Google account is already connected).
   */
  ssoLinkGoogle?(
    accessToken: string,
    identity: Identity,
  ): Promise<
    | { status: "linked"; login: string }
    | { status: "conflict" }
    | { status: "unauthenticated" }
  >;
  /**
   * The session user's sign-in methods (Profile screen): linked external
   * identities plus whether a password is set, so the UI can render every
   * channel — connected or not — in one place.
   */
  listIdentities?(identity: Identity): Promise<unknown>;
  /**
   * Member operating profile: home team plus the authenticated session user's
   * additional memberships. The implementation resolves the subject only
   * from `identity.sessionUserId`; callers cannot select another user.
   */
  profile?(identity: Identity): Promise<unknown | null>;
  /**
   * S18 Settings → Profile: set the session user's own display name. Same
   * subject rule as `profile` — the session user, never a named one.
   */
  updateProfile?(
    identity: Identity,
    body: { displayName?: unknown; avatar?: unknown },
  ): Promise<unknown>;
  /**
   * Remove the session user's link for a provider. False when none existed;
   * `last_method` when removing it would leave no way to sign in.
   */
  unlinkIdentity?(
    identity: Identity,
    provider: string,
  ): Promise<boolean | "last_method">;
}

/**
 * Syscall surface: payload is the parsed JSON body (already guaranteed to be
 * a plain object WITHOUT `namespace`/`actor` keys); identity is the resolved
 * caller. The syscall layer owns validation of the payload fields.
 */
export interface HttpSyscalls {
  memRead(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  memSearch(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  memWrite(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  memFault(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  memStats(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  memAssemble(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  /** Guardrail lane: the governed directive set + digest for the caller. */
  memPolicy?(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  /** The caller echoes a directive digest back (acknowledged / applied). */
  memPolicyAck?(
    payload: Record<string, unknown>,
    identity: Identity,
    ctx?: SyscallContext,
  ): Promise<unknown>;
  memPin?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  memUnpin?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  memShare?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M8: grant-fenced direct backend projection for agents. */
  sourceRead?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Explicit session-completion observation; raw turns are summarized then discarded. */
  completeAgentSession?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M8A: create/list exact, badge-bound temporary access requests. */
  requestAgentAccess?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listAgentAccessRequests?(identity: Identity): Promise<unknown>;
  /** M8A addendum: badge-visible standing access description (`describe_access`). */
  describeAgentAccess?(identity: Identity): Promise<unknown>;
  /**
   * Status of an async write ticket (mem_write {async:true}). Resolves to
   * undefined for unknown, evicted, or FOREIGN-namespace tickets — the route
   * maps that to 404 so failed queued writes are discoverable but never leak
   * across tenants. Optional so hand-rolled test deps stay valid.
   */
  writeStatus?(ticket: string, identity: Identity): Promise<unknown>;
  /**
   * M9 #6 (E14): GET /v1/mem/manifest — audited, ACL-scoped llms.txt /
   * memory-index read syscall. Payload is the already-validated query args.
   */
  memManifest?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * M9 #7 (D28): POST /v1/mem/export — governed markdown egress. Role /
   * source / classification gating lives INSIDE the syscall; denied exports
   * still audit (E16).
   */
  memExport?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * M9 #18 (D31): POST /v1/mem/answer-outcome — per-turn outcome capture.
   * The kernel-side parser rejects identity-shaped body fields (D9).
   */
  recordAnswerOutcome?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * M9 #9 (E20/E22): POST /v1/skills/invoke — the audited skill gate for any
   * resolved identity. Unvetted/blocked skills deny unless an audited admin
   * override exists; every outcome (ok/denied/miss) audits `skill_invoke`.
   */
  invokeSkill?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * S16: GET /v1/skills — the member-visible library listing (approval
   * status, risk band, usage), ACL-filtered store-side.
   */
  listSkills?(identity: Identity): Promise<unknown>;
  /**
   * S16: POST /v1/skills — skill submission for any non-agent identity;
   * member submissions land `pending` until a team admin approves.
   */
  registerSkill?(
    payload: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S16: GET /v1/skills/:id/download — governed { filename, content }. */
  downloadSkill?(id: string, identity: Identity): Promise<unknown>;
}

export interface HttpAdmin {
  getPolicy(namespace: Namespace, identity: Identity): Promise<unknown>;
  setPolicy(
    namespace: Namespace,
    yamlText: string,
    identity: Identity,
  ): Promise<unknown>;
  /** Governed policy register metadata; owner/admin/auditor read within scope. */
  listPolicyDocuments?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Bounded canonical namespace directory for the policy scope typeahead. */
  listPolicyDocumentScopes?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Text policy upload; owner/admin only, with kernel-authoritative scope. */
  uploadPolicyDocument?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Per-agent guardrail compliance for one policy scope (owner/admin/auditor). */
  policyCompliance?(namespace: Namespace, identity: Identity): Promise<unknown>;
  /** Flip one governed document between advisory and required. */
  setPolicyEnforcement?(
    documentId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Permanently delete a governed policy document and its landed facts. */
  deletePolicyDocument?(
    documentId: string,
    identity: Identity,
  ): Promise<unknown>;
  /** Policy files already in memory that the register does not know about. */
  listPolicyAdoptionCandidates?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Promote an already-landed policy file into the register; owner/admin only. */
  adoptPolicyDocument?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listKeys(identity: Identity): Promise<unknown>;
  issueKey(
    params: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  revokeKey(keyId: string, identity: Identity): Promise<unknown>;
  revealKey?(keyId: string, identity: Identity): Promise<unknown>;
  listAgentConnections?(identity: Identity): Promise<unknown>;
  createAgentConnection?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  revokeAgentConnection?(id: string, identity: Identity): Promise<unknown>;
  issueAgentBadge?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listAgentAccessEvents?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listAgentAccessAlerts?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  acknowledgeAgentAccessAlert?(
    id: string,
    identity: Identity,
  ): Promise<unknown>;
  listAgentAccessRequests?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  approveAgentAccessRequest?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  denyAgentAccessRequest?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listPins?(namespace: Namespace, identity: Identity): Promise<unknown>;
  createPin?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  deletePin?(pinId: string, identity: Identity): Promise<unknown>;
  revokeMount?(mountId: string, identity: Identity): Promise<unknown>;
  forkMount?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  runMovement?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * M2: POST /v1/admin/scorecard {namespace} — referee run over every
   * mounted driver. Optional so hand-rolled test deps stay valid; absent →
   * the route 404s.
   */
  runScorecard?(namespace: Namespace, identity: Identity): Promise<unknown>;
  /**
   * M4: POST /v1/admin/forget {target} — owner/admin compliance erasure,
   * subtree-scoped. Optional so hand-rolled test deps stay valid; absent →
   * the route 404s.
   */
  forget?(body: Record<string, unknown>, identity: Identity): Promise<unknown>;
  /**
   * M4: GET /v1/admin/certificate/:id — read a persisted DeletionCertificate.
   * Owner OR auditor may read (a regulator reads, never mints). The route
   * enforces that role carve-out itself, so this is reachable by an auditor
   * even though the rest of /v1/admin/* is owner/admin-only.
   */
  getCertificate?(id: string, identity: Identity): Promise<unknown>;
  /** R6: GET /v1/admin/warmstores — per-store health + pending outbox (root owner). */
  warmStores?(identity: Identity): Promise<unknown>;
  /** R6: POST /v1/admin/warmstores/flush — retry the mirror outbox now (root owner). */
  warmFlush?(identity: Identity): Promise<unknown>;
  /** R6: POST /v1/admin/warmstores/:name/rebuild {namespace} — wipe + rebuild (root owner). */
  warmRebuild?(
    name: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M4: POST /v1/admin/tenants {id,name,...} — register a tenant (owner only). */
  registerTenant?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M4: GET /v1/admin/tenants — list tenants visible to the caller (ACL-scoped). */
  listTenants?(identity: Identity): Promise<unknown>;
  /** M4: POST /v1/admin/tenants/:id/suspend — suspend a tenant (bulk revoke). */
  suspendTenant?(id: string, identity: Identity): Promise<unknown>;
  /**
   * POST /v1/admin/org/adopt {tenant, namespaces[], dryRun?, rootSources?} —
   * re-root orphan top-level namespaces under a tenant (platform root only;
   * the kernel enforces it). The repair for pre-attachment deployments.
   */
  adoptOrganization?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;

  // --- M5 control-room management API (owner/admin, auditor read-only) ------
  // Every read handler is subtree-scoped inside the kernel. The mutating
  // handlers (invite/connect/sync/run/setup) additionally reject the auditor
  // role (the route enforces read-only for auditor). Optional so hand-rolled
  // and bearer-only deps stay valid; absent → the route 404s.
  /**
   * M5: GET /v1/admin/overview — S2 aggregate for the caller's subtree.
   * `?days=` is Home's reporting window; absent means the all-time view.
   */
  overview?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S18: GET /v1/admin/organization — the tenant's display name + mark. */
  organizationSettings?(identity: Identity): Promise<unknown>;
  /** S18: PATCH /v1/admin/organization {name?,icon?} — owner/admin only. */
  updateOrganizationSettings?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M5: GET /v1/admin/people — S3 roster (human users ∪ agent badges). */
  people?(identity: Identity): Promise<unknown>;
  /** GET /v1/admin/team-directory — human users + canonical human RBAC only. */
  teamDirectory?(identity: Identity): Promise<unknown>;
  /** M5: POST /v1/admin/people — invite a human user (owner/admin, not auditor). */
  invitePerson?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  personAccessImpact?(userId: string, identity: Identity): Promise<unknown>;
  changePersonAccessState?(
    userId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S13: GET /v1/admin/teams — subtree teams with member rosters. */
  listTeams?(identity: Identity): Promise<unknown>;
  /** S13: POST /v1/admin/teams — create a team under the caller's namespace. */
  createTeam?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateTeam?(
    teamId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S13: POST /v1/admin/teams/:id/members — add a visible person by email. */
  addTeamMember?(
    teamId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  changeTeamMemoryAccess?(
    teamId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Invite a human into a selected team; the kernel resolves its namespace. */
  inviteTeamMember?(
    teamId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  rotateTeamInvitation?(
    teamId: string,
    invitationId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  revokeTeamInvitation?(
    teamId: string,
    invitationId: string,
    identity: Identity,
  ): Promise<unknown>;
  /** Owner-only role change for an existing human team member. */
  changeTeamMemberRole?(
    teamId: string,
    userId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S13: DELETE /v1/admin/teams/:id/members/:userId — remove a member. */
  removeTeamMember?(
    teamId: string,
    userId: string,
    identity: Identity,
  ): Promise<unknown>;
  /** M5: GET /v1/admin/memory-map?namespace= — S5 map for one namespace. */
  memoryMap?(namespace: Namespace, identity: Identity): Promise<unknown>;
  /** M5: GET /v1/admin/audit?...filters — S8 audit search, subtree-scoped. */
  auditSearch?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  auditSummary?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** GET /v1/admin/audit/export.csv?...filters — the same trail, complete, as CSV. */
  auditExportCsv?(
    filters: Record<string, unknown>,
    identity: Identity,
  ): Promise<{
    csv: string;
    filename: string;
    rowCount: number;
    truncated: boolean;
    sha256: string;
  }>;
  /** M5: GET /v1/admin/sources — S6 sources view + latest fragmentation. */
  sourcesView?(identity: Identity): Promise<unknown>;
  /** GET /v1/admin/sources/:id/lineage — what one connection wrote to memory. */
  sourceLineage?(id: string, identity: Identity): Promise<unknown>;
  listKnowledgeBases?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  createKnowledgeBase?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listKnowledgeBaseSources?(
    id: string,
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  attachKnowledgeBaseSource?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  pauseKnowledgeBase?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  resumeKnowledgeBase?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  archiveKnowledgeBase?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listCompanyFiles?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  listEntityRelationships?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  uploadCompanyFile?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  companyFileUploadStatus?(
    id: string,
    identity: Identity,
  ): Promise<unknown>;
  archiveCompanyFile?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateSourceMetadata?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Platform-wide connector catalog; independent of customer connection state. */
  connectors?(identity: Identity): Promise<unknown>;
  /** Namespace-owned reusable connector credentials; summaries never include values. */
  listSourceCredentials?(identity: Identity): Promise<unknown>;
  createSourceCredential?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  createNangoConnectSession?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  completeNangoConnectSession?(
    attemptId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M5: POST /v1/admin/sources — connect a source (registerSource). */
  connectSource?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Direct connector OAuth: mint the provider authorize URL (owner/admin). */
  startSourceOAuth?(
    provider: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<{ authorizeUrl: string }>;
  /** Create a local Obsidian plugin pairing; the signing secret is returned once. */
  pairObsidian?(body: Record<string, unknown>, identity: Identity): Promise<unknown>;
  /** Public direct-connector OAuth redirect target (single-use state). */
  sourceOAuthCallback?(input: {
    state: string | null;
    code: string | null;
    error: string | null;
  }): Promise<{ ok: boolean; redirect: string }>;
  /** M5: POST /v1/admin/sources/:id/sync — queue a registered source sync. */
  syncSource?(id: string, identity: Identity): Promise<unknown>;
  /** Authenticated bounded CSV snapshot for a csv_sheet_import source. */
  importCsvSource?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  testSource?(id: string, identity: Identity): Promise<unknown>;
  pauseSource?(id: string, identity: Identity): Promise<unknown>;
  resumeSource?(id: string, identity: Identity): Promise<unknown>;
  scheduleSource?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M5: GET /v1/admin/fragmentation?namespace= — latest fragmentation summary. */
  getFragmentation?(namespace: Namespace, identity: Identity): Promise<unknown>;
  /** M5: POST /v1/admin/fragmentation — run the fragmentation report. */
  runFragmentation?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** M5: POST /v1/admin/setup — orchestrate tenant → source → retriever → snippet. */
  setup?(body: Record<string, unknown>, identity: Identity): Promise<unknown>;
  setupCapabilities?(identity: Identity): Promise<unknown>;
  setupStatus?(operationId: string, identity: Identity): Promise<unknown>;
  setupRetry?(operationId: string, identity: Identity): Promise<unknown>;
  listProposals?(identity: Identity): Promise<unknown>;
  getProposal?(proposalId: string, identity: Identity): Promise<unknown>;
  proposalMetrics?(namespace: Namespace, identity: Identity): Promise<unknown>;
  runConsolidation?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  editProposal?(
    proposalId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  approveProposal?(
    proposalId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  rejectProposal?(
    proposalId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S11: GET /v1/admin/disputes — open trust disputes visible to the caller. */
  listDisputes?(identity: Identity): Promise<unknown>;
  listConflicts?(identity: Identity): Promise<unknown>;
  requestConflictScan?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  latestConflictScan?(identity: Identity): Promise<unknown>;
  getConflictScan?(scanId: string, identity: Identity): Promise<unknown>;
  reviewConflictFinding?(
    findingId: string,
    action: "acknowledge" | "dismiss",
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * S11: POST /v1/admin/conflict-findings/:id/resolve — keep one side of the
   * conflict; the other fact's validity is closed (never deleted).
   */
  resolveConflictFinding?(
    findingId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /**
   * S11: POST /v1/admin/conflict-findings/:id/overturn — reverse a decision the
   * autopilot made. The validity swap runs the other way; nothing is deleted.
   */
  overturnConflictFinding?(
    findingId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** S11: POST /v1/admin/disputes/:id/resolve — uphold-new | keep-old | edit. */
  resolveDispute?(
    disputeId: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  // --- M9 parity console read models + admin surfaces -----------------------
  /** #8 (E43): GET /v1/admin/readiness — composite banded memory-health score. */
  readiness?(identity: Identity): Promise<unknown>;
  /** #15 (E48–E50): GET /v1/admin/user-analytics — caller segmentation grid. */
  userAnalytics?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Usage analytics: GET /v1/admin/usage/queries — paginated query ledger. */
  usageQueries?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Usage analytics: GET /v1/admin/usage/queries/:traceId — null = 404. */
  usageQueryTrace?(traceId: string, identity: Identity): Promise<unknown>;
  /** Usage analytics: GET /v1/admin/usage/rollup — grouped traction rollup. */
  usageRollup?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Assistant analytics: metadata-only turn ledger and detail. */
  usageAiTurns?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  usageAiTurnDetail?(turnId: string, identity: Identity): Promise<unknown>;
  usageAiRollup?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** D57 reversible recycle lifecycle and explicit owner-only hard purge. */
  assistantRecycleBin?(identity: Identity): Promise<unknown>;
  recycleAssistantActor?(actor: string, identity: Identity): Promise<unknown>;
  restoreAssistantActor?(actor: string, identity: Identity): Promise<unknown>;
  purgeAssistantActor?(
    actor: string,
    confirmation: string,
    identity: Identity,
  ): Promise<unknown>;
  /** #16 (E51): GET /v1/admin/gaps — unified missing|wrong gap feed. */
  gapFeed?(identity: Identity): Promise<unknown>;
  /** #5 (E42): GET /v1/admin/setup-checklist — standing setup checklist. */
  setupChecklist?(identity: Identity): Promise<unknown>;
  /**
   * The mandatory-setup gate decision (CONTRACTS-SETUP-GATE.md): cheap read of
   * the persisted onboarding latch, surfaced on GET /auth/me for any human
   * role so the console shell can lock itself to the setup surface.
   */
  onboardingState?(identity: Identity): Promise<unknown>;
  /** #18 (E33): GET /v1/admin/accuracy — derived accuracy rollup. */
  accuracy?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** #19: GET /v1/admin/automations — template catalog merged with org rows. */
  listAutomations?(identity: Identity): Promise<unknown>;
  /** #19: PUT /v1/admin/automations — enable/disable/configure one template. */
  configureAutomation?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Read-only activity for Knowledge Review sync records. */
  knowledgeSyncStatus?(identity: Identity): Promise<unknown>;
  /** Owner-only, server-resolved team/company delta sync into Knowledge Review. */
  queueKnowledgeSync?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** #21 (E39): GET /v1/admin/credits — tenant-root credit summary. */
  credits?(
    query: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** W3 #22 (E56): GET /v1/admin/usage — cap/spend/balance/alerts summary. */
  usageSummary?(identity: Identity): Promise<unknown>;
  /** W3 #22 (E56): PUT /v1/admin/usage/cap {monthlyBudgetUsd} — audited edit. */
  setUsageCap?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** W3 #22 (E53): PUT /v1/admin/usage/alerts — customer-editable thresholds. */
  upsertUsageAlert?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** #23 (E52): POST /v1/admin/keys/:id/rotate — audited, scope-preserving. */
  rotateKey?(keyId: string, identity: Identity): Promise<unknown>;
  listKeyHandoffs?(identity: Identity): Promise<unknown>;
  claimKeyHandoff?(id: string, identity: Identity): Promise<unknown>;
  revokeKeyHandoff?(id: string, identity: Identity): Promise<unknown>;
  /** #1 (E1/E2): GitHub App installation brokerage (summaries only). */
  listGitHubInstallations?(identity: Identity): Promise<unknown>;
  startGitHubInstall?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  approveGitHubInstall?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  revokeGitHubInstall?(id: string, identity: Identity): Promise<unknown>;
  /** #11b (D29/E24): OAuth client registry — create/approve/revoke/list. */
  listOAuthClients?(identity: Identity): Promise<unknown>;
  createOAuthClient?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  approveOAuthClient?(id: string, identity: Identity): Promise<unknown>;
  revokeOAuthClient?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** #9 (E19–E22): company skill library — register/vet/override/retire. */
  listSkills?(identity: Identity): Promise<unknown>;
  registerSkill?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateSkill?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateSkillLabels?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  getSkill?(id: string, identity: Identity): Promise<unknown>;
  vetSkill?(id: string, identity: Identity): Promise<unknown>;
  overrideSkill?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  retireSkill?(id: string, identity: Identity): Promise<unknown>;
  /** S16: team-admin approval of a pending member submission. */
  approveSkill?(id: string, identity: Identity): Promise<unknown>;
  /** S16: team-admin rejection; body carries the mandatory reason. */
  rejectSkill?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  /** Model runtime: safe metadata only; credentials never leave the server. */
  listModelCatalog?(identity: Identity): Promise<unknown>;
  listModelConnections?(identity: Identity): Promise<unknown>;
  createModelConnection?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  revokeModelConnection?(id: string, identity: Identity): Promise<unknown>;
  listModelProfiles?(identity: Identity): Promise<unknown>;
  createModelProfile?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateModelProfile?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  deleteModelProfile?(id: string, identity: Identity): Promise<unknown>;
}

export interface HttpCopilot {
  /** Profile metadata visible through the caller's resolved namespace. */
  listProfiles(identity: Identity): Promise<unknown>;
  /** Governed retrieval + completion. Body never carries identity fields. */
  complete(body: Record<string, unknown>, identity: Identity): Promise<unknown>;
  /** Fixed-target readiness probe; returns no provider or credential detail. */
  probe?(): Promise<void>;
  listConversations?(
    identity: Identity,
    limit: number,
    offset: number,
  ): Promise<unknown>;
  createConversation?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  getConversation?(id: string, identity: Identity): Promise<unknown | null>;
  clearConversations?(identity: Identity): Promise<unknown>;
  listRoutines?(identity: Identity): Promise<unknown>;
  createRoutine?(
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown>;
  updateRoutine?(
    id: string,
    body: Record<string, unknown>,
    identity: Identity,
  ): Promise<unknown | null>;
  deleteRoutine?(id: string, identity: Identity): Promise<boolean>;
}

export interface HttpMetrics {
  snapshot(): unknown;
}

export interface HttpAuthThrottle {
  consume(bucket: string): Promise<{ allowed: boolean; retryAfterSec: number }>;
  reset?(bucket: string): Promise<void>;
}

export interface HttpAudit {
  append(event: AuditEvent): Promise<void>;
}

export interface HttpScimTenant {
  provisionUser(body: Record<string, unknown>): Promise<unknown>;
  provisionGroup(body: Record<string, unknown>): Promise<unknown>;
  getUser(id: string): Promise<unknown | null>;
  listUsers(filter?: string): Promise<unknown[]>;
  replaceUser(
    id: string,
    body: Record<string, unknown>,
  ): Promise<unknown | null>;
  patchUser(id: string, body: Record<string, unknown>): Promise<unknown | null>;
  deleteUser(id: string): Promise<boolean>;
  getGroup(id: string): Promise<unknown | null>;
  listGroups(filter?: string): Promise<unknown[]>;
  replaceGroup(
    id: string,
    body: Record<string, unknown>,
  ): Promise<unknown | null>;
  patchGroup(
    id: string,
    body: Record<string, unknown>,
  ): Promise<unknown | null>;
  deleteGroup(id: string): Promise<boolean>;
}

export interface HttpScim {
  /** Resolve a dedicated bearer to exactly one tenant-scoped SCIM service. */
  resolve(token: string): HttpScimTenant | null;
}

/** Transport-agnostic OAuth AS envelope (mirrors src/oauth/server.ts). */
export interface OAuthEnvelope {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/** Page/redirect envelope for the consent surface — body is HTML or empty. */
export interface OAuthPageEnvelope {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface OAuthEnvelopeRequest {
  body: Record<string, unknown>;
  authorization?: string;
  /** Caller address for rate-limit bucketing (open registration — OA2). */
  clientAddress?: string;
}

/**
 * M9 #11b (D29) + CONTRACTS-OAUTH-CONNECT: the hosted OAuth authorization-
 * server surface. token/introspect/revoke/register are client- or PKCE-
 * authenticated INTERNALLY (never by the Identity middleware); the authorize
 * pair takes the cookie-session Identity the transport resolved (or null);
 * metadata endpoints are public and pure.
 */
export interface HttpOAuth {
  token(req: OAuthEnvelopeRequest): Promise<OAuthEnvelope>;
  introspect(req: OAuthEnvelopeRequest): Promise<OAuthEnvelope>;
  revoke(req: OAuthEnvelopeRequest): Promise<OAuthEnvelope>;
  /** OA2 — RFC 7591 dynamic client registration. */
  register?(req: OAuthEnvelopeRequest): Promise<OAuthEnvelope>;
  /** OA8 — GET /oauth/authorize: login bounce | consent page | error page. */
  authorizePage?(
    query: Record<string, unknown>,
    rawQuery: string,
    identity: Identity | null,
    issuerBaseUrl: string,
  ): Promise<OAuthPageEnvelope>;
  /** OA8 — POST /oauth/authorize/decision: allow (mint code) or deny. */
  authorizeDecision?(
    body: Record<string, unknown>,
    identity: Identity | null,
    issuerBaseUrl: string,
  ): Promise<OAuthPageEnvelope>;
  metadata(issuerBaseUrl: string): OAuthEnvelope;
  /** OA7 — `resourceSuffix` "/mcp" serves the MCP-surface PRM document. */
  resourceMetadata(
    issuerBaseUrl: string,
    resourceSuffix?: string,
  ): OAuthEnvelope;
}

export interface HttpWebhooks {
  /** Verify the provider signature and ingest the untouched request body. */
  ingest(
    sourceId: string,
    rawBody: string,
    timestamp: string,
    signature: string,
  ): Promise<unknown>;
  /** Signed, sequence-fenced ingress for a paired local Obsidian vault. */
  obsidian?(
    sourceId: string,
    rawBody: string,
    timestamp: string,
    signature: string,
  ): Promise<unknown>;
  /**
   * M9 #1: GitHub App webhook ingress — the X-Hub-Signature-256 HMAC is the
   * credential; namespace resolves from the registered source row (D9).
   */
  github?(
    rawBody: string,
    signature: string | undefined,
    event: string | undefined,
  ): Promise<unknown>;
}

export interface HttpServerDeps {
  auth: HttpAuth;
  syscalls: HttpSyscalls;
  admin: HttpAdmin;
  /** Optional so memory-kernel-only deployments retain the existing surface. */
  copilot?: HttpCopilot;
  metrics: HttpMetrics;
  audit: HttpAudit;
  /**
   * Per-request MCP server factory — tools identical to stdio minus
   * namespace/actor params. `publicBaseUrl` is the origin the caller reached us
   * on; it makes the `initialize` icon/website URLs absolute so connector UIs
   * can brand the server.
   */
  buildMcpServer(
    identity: Identity,
    serverContext?: SyscallContext,
    publicBaseUrl?: string,
  ): McpServer;
  /**
   * M5: absolute path to the `console/` directory served (read-only) at
   * `GET /console/*`. Absent → the `/console/*` routes 404 (a deployment
   * without the control room). The integrator passes the packaged dir.
   */
  consoleDir?: string;
  /**
   * M5: whether to set the `Secure` attribute on the session cookie. The
   * integrator passes `false` on localhost (dev over http) and `true` behind
   * TLS. Absent → treated as `false`.
   */
  secureCookies?: boolean;
  /**
   * Validated canonical public origin. Reverse proxies may replace `Host`
   * with the upstream hostname, so origin-bound OAuth URLs must prefer this
   * deployment setting when it is available.
   */
  publicUrl?: string;
  /** Dedicated durable throttle for public credential-minting endpoints. */
  authThrottle?: HttpAuthThrottle;
  /** Durable per-IP and per-source limiter for public signed webhook ingress. */
  webhookThrottle?: HttpAuthThrottle;
  /**
   * How many trusted reverse proxies sit in front of this server. Absent or 0
   * → the socket peer IS the client (direct listen, tests, localhost). Behind
   * Container Apps ingress it is 1. Governs `clientAddress()`, which every
   * rate-limit bucket is keyed on — see that function for why the count
   * matters and why it must not be guessed from the header itself.
   */
  trustedProxyHops?: number;
  /** Bounded RED/trace observation sink; absent keeps transport behavior unchanged. */
  telemetry?: HttpTelemetry;
  /**
   * M9 #13 (E47): GET /v1/copilot/suggested-questions — chips derived for the
   * caller's namespace. Rides the copilot family (cookie/API-key auth), not
   * the admin gate — S10 reaches it from the same session as /profiles.
   */
  suggestedQuestions?(identity: Identity): Promise<unknown>;
  /** Optional SCIM 2.0 provisioning surface with a dedicated bearer token. */
  scim?: HttpScim;
  /** M9 #11b (D29): OAuth AS routes (/oauth/*, /.well-known/*). Absent → 404. */
  oauth?: HttpOAuth;
  /**
   * M9 #11a (E28–E30): unauthenticated public org discovery —
   * `GET /{orgSlug}` + `GET /{orgSlug}/llms.txt`. The module resolves the
   * slug to a tenant root server-side (E28), fences to public-classified
   * canonical rows (E29), redacts provenance, and audits every outcome
   * itself (D4). Absent → the paths fall through to the normal 404.
   */
  publicDiscovery?(
    orgSlug: string,
    format: PublicDiscoveryFormat,
  ): Promise<PublicDiscoveryResponse>;
  /** Optional source-specific signed webhook ingress. */
  webhooks?: HttpWebhooks;
  /** Optional, fixed-destination organization SSO issuer for the Control Room. */
  haloAgents?: HaloAgentsHandoff;
  /**
   * M10 — role-scoped memory graph + root View-as. Cookie-session surface
   * (every human role reaches /v1/memory-graph); the raw preview credential
   * is read from `x-halomem-preview-token` HERE and resolved through these
   * seams — handlers never see the raw token. Absent → the routes 404.
   */
  access?: HttpAccessGraph;
  /** C0 communication channels: public ingress + admin control plane. */
  channels?: HttpChannels;
}

/** C0 channels surface the adapter binds to the kernel channel services. */
export interface HttpChannels {
  /** Public webhook ingress; every deny path is a uniform 404. */
  ingress(
    kind: string,
    routeKey: string,
    raw: import("../types.js").RawChannelRequest,
  ): Promise<{
    status: number;
    body: string | null;
    contentType: string | null;
  }>;
  catalog(identity: Identity): Promise<unknown>;
  /** Click-to-connect: mint the provider authorize URL (owner/admin). */
  oauthStart(
    identity: Identity,
    connectionId: string,
  ): Promise<{ authorizeUrl: string }>;
  /** Public OAuth redirect target; single-use state is the only credential. */
  oauthCallback(input: {
    state: string | null;
    code: string | null;
    error: string | null;
  }): Promise<{ ok: boolean; redirect: string }>;
  managedGoogleChatStart(identity: Identity): Promise<unknown>;
  managedGoogleChatStatus(identity: Identity, setupId: string): Promise<unknown | null>;
  listConnections(identity: Identity): Promise<unknown>;
  getConnection(identity: Identity, id: string): Promise<unknown | null>;
  createConnection(
    identity: Identity,
    body: Record<string, unknown>,
  ): Promise<unknown>;
  setCredentials(
    identity: Identity,
    id: string,
    body: Record<string, unknown>,
  ): Promise<unknown>;
  assignAgent(identity: Identity, id: string, body: Record<string, unknown>): Promise<unknown>;
  assignAssistant(identity: Identity, id: string, body: Record<string, unknown>): Promise<unknown>;
  setupTelegram(identity: Identity, id: string, body: Record<string, unknown>): Promise<unknown>;
  transition(
    identity: Identity,
    id: string,
    op:
      | "pause"
      | "resume"
      | "activate"
      | "disconnect"
      | "delete"
      | "cutover"
      | "rollback",
    body: Record<string, unknown>,
  ): Promise<unknown>;
  /**
   * Point the provider installation at our ingress URL (Telegram today; any
   * cartridge that declares a registration request). Mints a fresh route key
   * server-side — the plaintext is never returned to the caller.
   */
  registerWebhook(
    identity: Identity,
    id: string,
    body: Record<string, unknown>,
  ): Promise<unknown>;
  listEvents(identity: Identity, id: string): Promise<unknown>;
}

/** M10 structural surface the adapter binds to the kernel facades. */
export interface HttpAccessGraph {
  /** Raw session-cookie token → full console Session (userId), or null. */
  resolveConsoleSession(token: string): Promise<Session | null>;
  /** The projected graph (+ topology); preview token optional and opaque. */
  memoryGraph(
    session: Session,
    opts: { scopeId?: string; cursor?: string; limit?: number },
    previewToken: string | null,
  ): Promise<unknown>;
  viewAsTargets(session: Session): Promise<unknown>;
  viewAsStart(
    session: Session,
    body: Record<string, unknown>,
  ): Promise<unknown>;
  viewAsEnd(session: Session, id: string): Promise<unknown>;
  /** Preview credential → { sessionId } when live; null otherwise (audited). */
  resolvePreview(
    session: Session,
    token: string,
  ): Promise<{ sessionId: string } | null>;
  /** Audits (denied, ROOT-attributed) then throws the 403 shape (D43). */
  rejectMutation(
    session: Session,
    previewSessionId: string,
    method: string,
    path: string,
  ): Promise<never>;
}

export interface HaloHttpServer {
  /** Bind and listen; port 0 → ephemeral. Resolves to the bound port. */
  start(port?: number): Promise<number>;
  /** Close listener and drop open connections. */
  stop(): Promise<void>;
  /** Underlying node server (tests / integrator). */
  readonly server: Server;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

const AGENT_ID = "http";
const MAX_BODY_BYTES = 1_048_576; // 1 MiB
// A decoded 512 KiB policy can expand to about 3 MiB when JSON uses \uXXXX
// escapes. The policy store still enforces the authoritative decoded limit.
const MAX_POLICY_DOCUMENT_BODY_BYTES = 3_200_000;
// A 5 MiB binary company file expands to about 6.7 MiB as base64; text
// uploads expand less. The ingest boundary still enforces the authoritative
// decoded per-format limits.
const MAX_COMPANY_FILE_BODY_BYTES = 7_500_000;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const TRACEPARENT_PATTERN = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const ASSISTANT_ID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * Origin-root paths that serve the Halofy mark. Favicon crawlers and MCP
 * connector UIs probe these fixed names and never follow a `<link rel=icon>`
 * from a page they did not load — so the bytes have to sit here, and they have
 * to be public (a 401 reads as "no icon" and the client falls back to the
 * hosting domain's logo).
 */
const BRAND_ICON_PATHS: ReadonlySet<string> = new Set([
  "/favicon.ico",
  "/favicon.png",
  "/icon.png",
  "/apple-touch-icon.png",
  "/apple-touch-icon-precomposed.png",
]);
/** The mark served for every BRAND_ICON_PATHS entry (a real PNG, always). */
const BRAND_ICON_FILE = "/console/assets/marks/halofy-mark-green.svg";

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

/**
 * POST /v1/mem/<route> → syscall method name. Route names double as AuditOps —
 * EXCEPT 'live-result' (M6/D15), which is not an AuditOp: routeOp maps it to
 * 'fault' (live-result rows audit as op:'fault' with a 'live_result' detail
 * prefix, so the AuditOp union stays untouched).
 */
const MEM_ROUTES = {
  read: "memRead",
  search: "memSearch",
  write: "memWrite",
  fault: "memFault",
  stats: "memStats",
  assemble: "memAssemble",
  policy: "memPolicy",
  "policy-ack": "memPolicyAck",
  pin: "memPin",
  unpin: "memUnpin",
  share: "memShare",
  "live-result": "memLiveResult",
} as const;
type MemRoute = keyof typeof MEM_ROUTES;

function isMemRoute(s: string): s is MemRoute {
  return Object.hasOwn(MEM_ROUTES, s);
}

/** Audit op attributed to a denial on a given route (see module header). */
function routeOp(path: string, method: string): AuditOp {
  if (path.startsWith("/v1/mem/")) {
    const op = path.slice("/v1/mem/".length);
    if (isMemRoute(op)) {
      if (op === "live-result") return "fault";
      if (op === "policy-ack") return "policy_ack";
      return op;
    }
  }
  if (path === "/metrics") return "stats";
  if (path === "/v1/mem/answer-outcome") return "answer_outcome";
  if (path === "/v1/agent-sessions/complete") return "session_capture";
  if (path === "/v1/mem/export") return "export";
  if (path === "/v1/copilot/complete") return "complete";
  if (path.startsWith("/v1/admin/")) return method === "GET" ? "read" : "write";
  if (path.startsWith("/v1/webhooks/sources/")) return "write";
  return "read"; // /mcp and unknown paths
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

/**
 * A browser NAVIGATION (GET/HEAD that asked for HTML), not an API call. Such a
 * caller gets the Halo status page instead of a JSON error envelope; every API
 * client (one that sends `Accept: application/json`, or the wildcard Node/curl
 * default) keeps the JSON contract byte for byte.
 */
function prefersHtml(req: IncomingMessage): boolean {
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;
  return (req.headers.accept ?? "").includes("text/html");
}

/**
 * Status copy for browser-facing failures. Deliberately GENERIC: the JSON
 * envelope's `message` can name internals (route names, validation detail), and
 * an unauthenticated navigation is the wrong place to publish it.
 */
const HTML_ERROR_COPY: Record<
  number,
  {
    eyebrow: string;
    heading: string;
    message: string;
    action?: { href: string; label: string };
  }
> = {
  400: {
    eyebrow: "Bad request",
    heading: "That link isn’t readable",
    message: "The address is malformed or missing something this route needs.",
  },
  401: {
    eyebrow: "Sign in required",
    heading: "You’re signed out",
    message: "Sign in to your workspace to continue.",
    action: { href: "/console/login", label: "Sign in" },
  },
  403: {
    eyebrow: "Forbidden",
    heading: "You don’t have access to that",
    message: "This account isn’t permitted to view this address.",
    action: { href: "/console/", label: "Back to the console" },
  },
  404: {
    eyebrow: "Not found",
    heading: "That page doesn’t exist",
    message: "The address may be mistyped, or the page may have moved.",
    action: { href: "/console/", label: "Back to the console" },
  },
  405: {
    eyebrow: "Not allowed",
    heading: "That address won’t answer this way",
    message: "This route doesn’t accept the request your browser made.",
    action: { href: "/console/", label: "Back to the console" },
  },
  429: {
    eyebrow: "Rate limited",
    heading: "Too many requests",
    message: "Requests are arriving too quickly. Try again in a minute.",
  },
  500: {
    eyebrow: "Server error",
    heading: "Something went wrong",
    message: "The request couldn’t be completed. Try again in a moment.",
  },
  503: {
    eyebrow: "Unavailable",
    heading: "This service is catching its breath",
    message: "A dependency is degraded right now. Try again shortly.",
  },
};

/** JSON for API callers, the Halo status page for browser navigations. */
function errorResponse(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  code: string,
  message: string,
): void {
  const copy =
    HTML_ERROR_COPY[status] ??
    (status >= 500 ? HTML_ERROR_COPY[500] : undefined);
  if (copy === undefined || !prefersHtml(req)) {
    return json(res, status, { error: message, code });
  }
  const body = renderHaloStatusPage({
    title: `${copy.heading} - Halofy`,
    eyebrow: copy.eyebrow,
    heading: copy.heading,
    messages: [copy.message],
    tone: status === 404 || status === 429 ? "notice" : "alert",
    action: copy.action,
  });
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

function boundedInteger(
  raw: string | null,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw))
    throw new HttpError(400, "bad_request", "invalid pagination");
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new HttpError(400, "bad_request", "invalid pagination");
  }
  return value;
}

function scimJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/scim+json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function scimError(
  status: number,
  detail: string,
  scimType?: string,
): Record<string, unknown> {
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
    status: String(status),
    detail,
    ...(scimType ? { scimType } : {}),
  };
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function initializeRequestContext(
  deps: HttpServerDeps,
  req: IncomingMessage,
  res: ServerResponse,
): {
  requestId: string;
  traceId: string;
  halomemTrace?: string;
  halomemTurn?: string;
} {
  const suppliedRequestId = headerValue(req.headers["x-request-id"]);
  const requestId =
    suppliedRequestId && REQUEST_ID_PATTERN.test(suppliedRequestId)
      ? suppliedRequestId
      : randomUUID();
  const suppliedTraceparent = headerValue(
    req.headers.traceparent,
  )?.toLowerCase();
  const match = suppliedTraceparent
    ? TRACEPARENT_PATTERN.exec(suppliedTraceparent)
    : null;
  const validParent =
    match && !/^0+$/.test(match[1]!) && !/^0+$/.test(match[2]!);
  const traceId = validParent ? match![1]! : randomBytes(16).toString("hex");
  const flags = validParent ? match![3]! : "01";
  const spanId = randomBytes(8).toString("hex");

  res.setHeader("x-request-id", requestId);
  res.setHeader("traceparent", `00-${traceId}-${spanId}-${flags}`);
  // The current control-room bundle contains a bootstrap inline script and
  // inline style attributes. Keep those working until the integrator moves
  // them to nonceable assets; all other source classes remain fail-closed.
  const formAction = deps.haloAgents
    ? `'self' ${new URL(deps.haloAgents.destination).origin}`
    : "'self'";
  // SSO: the login page talks to the IdP (GoTrue REST) straight from the
  // browser, so its origin must be reachable under connect-src. Everything
  // else stays fail-closed; without SSO the directive remains 'self' only.
  const ssoOrigin = deps.auth.ssoConfig?.().url;
  const connectSrc = ssoOrigin
    ? `'self' ${new URL(ssoOrigin).origin}`
    : "'self'";
  res.setHeader(
    "content-security-policy",
    `default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://cdn.brandfetch.io https://cdn.simpleicons.org; font-src 'self'; connect-src ${connectSrc}; base-uri 'none'; form-action ${formAction}; frame-ancestors 'none'`,
  );
  res.setHeader("x-content-type-options", "nosniff");
  res.setHeader("x-frame-options", "DENY");
  res.setHeader("referrer-policy", "no-referrer");
  res.setHeader(
    "permissions-policy",
    "camera=(), microphone=(), geolocation=()",
  );
  if (deps.secureCookies === true) {
    res.setHeader(
      "strict-transport-security",
      "max-age=31536000; includeSubDomains",
    );
  }
  // D37: the explicit HaloMem trace hint takes precedence over the W3C
  // traceparent id for syscall trace grouping (validated at the syscall
  // boundary; a hint is never identity — D9).
  const halomemTrace = headerValue(req.headers["x-halomem-trace"]);
  const halomemTurn = headerValue(req.headers["x-halomem-turn"]);
  return {
    requestId,
    traceId,
    ...(halomemTrace ? { halomemTrace } : {}),
    ...(halomemTurn ? { halomemTurn } : {}),
  };
}

function bearerKey(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  return match ? match[1] : null;
}

/**
 * The caller's own address, for rate-limit bucketing.
 *
 * `req.socket.remoteAddress` is the peer of the TCP connection. Behind a
 * reverse proxy that peer is the PROXY, identical for every caller — bucketing
 * on it collapses every client into ONE bucket, so a single actor tripping the
 * limit locks out everybody. `trustedProxyHops` says how many proxies sit in
 * front (Container Apps ingress = 1).
 *
 * With N trusted hops the client sits N from the RIGHT of `x-forwarded-for`:
 * each proxy APPENDS the peer it saw, so the rightmost entries are the ones a
 * caller cannot forge. Reading the leftmost entry instead would let anyone
 * pick their own bucket — and evade the limit — by sending the header.
 */
function clientAddress(
  req: IncomingMessage,
  trustedProxyHops?: number,
): string {
  const socketAddress = req.socket.remoteAddress ?? "unknown";
  if (!trustedProxyHops || trustedProxyHops <= 0) return socketAddress;
  const raw = headerValue(req.headers["x-forwarded-for"]);
  if (raw === undefined) return socketAddress;
  const chain = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  // Too few entries means the chain did not come through the expected number
  // of proxies — fall back rather than trust a caller-supplied prefix.
  return chain.length >= trustedProxyHops
    ? (chain[chain.length - trustedProxyHops] as string)
    : socketAddress;
}

async function readRawBody(
  req: IncomingMessage,
  maxBytes = MAX_BODY_BYTES,
): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) {
      throw new HttpError(
        413,
        "payload_too_large",
        `request body exceeds ${maxBytes} bytes`,
      );
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Parse the request body as a JSON object; empty body → {}. */
async function readJsonObject(
  req: IncomingMessage,
  maxBytes = MAX_BODY_BYTES,
): Promise<Record<string, unknown>> {
  const raw = await readRawBody(req, maxBytes);
  if (raw.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpError(400, "invalid_json", "request body is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(
      400,
      "invalid_body",
      "request body must be a JSON object",
    );
  }
  return parsed as Record<string, unknown>;
}

/**
 * Parse an OAuth endpoint body: application/x-www-form-urlencoded (the RFC
 * 6749 shape) or JSON. Never throws on malformed form input — the handlers
 * answer with the RFC error envelope for missing params.
 */
async function readOAuthBody(
  req: IncomingMessage,
): Promise<Record<string, unknown>> {
  const contentType = headerValue(req.headers["content-type"]) ?? "";
  if (contentType.includes("application/json")) return readJsonObject(req);
  const raw = await readRawBody(req);
  return Object.fromEntries(new URLSearchParams(raw));
}

function writeOAuthEnvelope(
  res: ServerResponse,
  envelope: OAuthEnvelope,
): void {
  const payload = JSON.stringify(envelope.body);
  res.writeHead(envelope.status, {
    ...envelope.headers,
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

/** Consent-surface envelopes carry raw HTML (or an empty redirect body). */
function writePageEnvelope(
  res: ServerResponse,
  envelope: OAuthPageEnvelope,
): void {
  res.writeHead(envelope.status, {
    ...envelope.headers,
    "content-length": Buffer.byteLength(envelope.body),
  });
  res.end(envelope.body);
}

/** Canonical issuer origin, falling back to the direct request for local/dev. */
function issuerBaseUrl(deps: HttpServerDeps, req: IncomingMessage): string {
  if (deps.publicUrl) return deps.publicUrl.replace(/\/+$/, "");
  const proto =
    headerValue(req.headers["x-forwarded-proto"]) ??
    (deps.secureCookies === true ? "https" : "http");
  const host = headerValue(req.headers.host) ?? "localhost";
  return `${proto}://${host}`;
}

/** Best-effort denial audit — a broken audit sink never masks the response. */
async function auditDenied(
  deps: HttpServerDeps,
  op: AuditOp,
  actor: string,
  namespace: Namespace,
  detail: string,
  agentId = AGENT_ID,
): Promise<void> {
  try {
    await deps.audit.append({
      ts: new Date().toISOString(),
      actor,
      agentId,
      op,
      memoryId: null,
      namespace,
      purpose: null,
      result: "denied",
      detail,
    });
  } catch {
    // D4 wants the row, but audit-sink failure must not break the transport.
  }
}

// ---------------------------------------------------------------------------
// MCP Streamable HTTP (/mcp) — MCP 2026-07-28 plus stateless legacy clients.
// ---------------------------------------------------------------------------

async function handleMcp(
  deps: HttpServerDeps,
  identity: Identity,
  req: IncomingMessage,
  res: ServerResponse,
  serverContext?: SyscallContext,
): Promise<void> {
  const handler = createMcpHandler(
    () =>
      deps.buildMcpServer(identity, serverContext, issuerBaseUrl(deps, req)),
    {
      // HaloMem never depended on protocol sessions. Keep ordinary 2025-era
      // tools/resources/prompts working while modern clients use 2026-07-28.
      legacy: "stateless",
      onerror(error) {
        console.error("mcp request error:", error.name);
      },
    },
  );
  res.on("close", () => {
    void handler.close().catch(() => {});
  });
  // Body stream is untouched (auth reads headers only) — let the SDK parse it.
  await toNodeHandler(handler)(req, res);
}

// ---------------------------------------------------------------------------
// M5 control-room routes (owner/admin, auditor read-only)
// ---------------------------------------------------------------------------

/**
 * A matched control-room route: the logical name (dispatched in
 * handleConsoleRoute), the captured id for `/sources/:id/sync`, and whether it
 * mutates (the auditor is denied on mutating routes — read-only everywhere).
 */
interface ConsoleRoute {
  name:
    | "overview"
    | "policy-documents-get"
    | "policy-documents-post"
    | "policy-document-delete"
    | "policy-document-adopt"
    | "policy-adoption-candidates-get"
    | "policy-scopes-get"
    | "policy-compliance-get"
    | "policy-enforcement-put"
    | "organization-get"
    | "organization-patch"
    | "people-get"
    | "people-post"
    | "person-access-impact"
    | "person-access-state"
    | "team-directory-get"
    | "teams-get"
    | "teams-post"
    | "team-update"
    | "team-invitation-create"
    | "team-invitation-rotate"
    | "team-invitation-revoke"
    | "team-member-add"
    | "team-memory-access-change"
    | "team-member-role-change"
    | "team-member-remove"
    | "memory-map"
    | "audit"
    | "audit-summary"
    | "audit-csv"
    | "sources-get"
    | "sources-post"
    | "source-lineage-get"
    | "knowledge-bases-get"
    | "knowledge-bases-post"
    | "knowledge-base-sources-get"
    | "knowledge-base-sources-post"
    | "knowledge-base-pause"
    | "knowledge-base-resume"
    | "knowledge-base-archive"
    | "company-files-get"
    | "entity-relationships-get"
    | "company-files-post"
    | "company-file-upload-status"
    | "company-file-archive"
    | "source-metadata-patch"
    | "connectors-get"
    | "source-credentials-get"
    | "source-credentials-post"
    | "nango-connect-start"
    | "nango-connect-complete"
    | "source-oauth-start"
    | "obsidian-pair"
    | "source-sync"
    | "source-import-csv"
    | "source-test"
    | "source-pause"
    | "source-resume"
    | "source-schedule"
    | "fragmentation-get"
    | "fragmentation-post"
    | "setup-capabilities"
    | "setup-status"
    | "setup-retry"
    | "proposals-list"
    | "proposal-get"
    | "proposal-metrics"
    | "consolidation-run"
    | "proposal-edit"
    | "proposal-approve"
    | "proposal-reject"
    | "disputes-list"
    | "dispute-resolve"
    | "conflicts-list"
    | "conflict-scan-request"
    | "conflict-scan-latest"
    | "conflict-scan-get"
    | "conflict-finding-acknowledge"
    | "conflict-finding-dismiss"
    | "conflict-finding-resolve"
    | "conflict-finding-overturn"
    | "readiness"
    | "user-analytics"
    | "gaps"
    | "setup-checklist"
    | "accuracy"
    | "automations-get"
    | "automations-put"
    | "knowledge-sync-status"
    | "knowledge-sync"
    | "credits"
    | "usage-queries"
    | "usage-query"
    | "usage-rollup"
    | "usage-ai-turns"
    | "usage-ai-turn"
    | "usage-ai-rollup"
    | "assistant-recycle-bin"
    | "assistant-recycle"
    | "assistant-restore"
    | "assistant-purge"
    | "usage-get"
    | "usage-cap-put"
    | "usage-alerts-put"
    | "setup";
  mutating: boolean;
  id?: string;
  /** Second captured segment (team-member-remove: the member's user id). */
  memberId?: string;
}

/**
 * D50: the exact governance READS a manager-level agent may perform in its own
 * team. Read-only by construction (the caller also checks `!route.mutating`),
 * and deliberately short: nothing here approves, publishes, resolves, mounts,
 * or changes a policy. Adding a name to this set widens a machine principal's
 * authority — do it in a contract, not in passing.
 */
/**
 * D50: a `member` human may deploy — and therefore must be able to see, rotate,
 * and revoke — agents in its OWN scope. This gate only says "a member may reach
 * the key routes"; what it may actually do there is decided by
 * `assertAgentKeyScope` (member → own namespace, member level, assistant type
 * only) and by `AuthService.list` (member → agent keys at its own namespace).
 * No other `/v1/admin/*` route opens up.
 */
function mayReachAgentKeyRoute(
  identity: Identity,
  path: string,
  method: string,
): boolean {
  if (identity.role !== "member") return false;
  if (path === "/v1/admin/keys") return method === "GET" || method === "POST";
  if (/^\/v1\/admin\/keys\/[^/]+\/reveal$/.test(path)) return method === "POST";
  if (/^\/v1\/admin\/keys\/[^/]+\/rotate$/.test(path)) return method === "POST";
  if (/^\/v1\/admin\/keys\/[^/]+$/.test(path)) return method === "DELETE";
  if (path === "/v1/admin/key-handoffs") return method === "GET";
  if (/^\/v1\/admin\/key-handoffs\/[^/]+\/claim$/.test(path)) return method === "POST";
  return false;
}

/**
 * The set is deliberately the INTERSECTION of "governance read" and "the owning
 * module already admits a machine principal". `/v1/admin/policy`,
 * `policy-documents-get`, and `conflicts-list` are NOT here: each is refused
 * further down by its own module gate (assertAdminScope, the auditor-role
 * check, the conflict-scan administrative gate), and widening a module's role
 * rule to satisfy a transport allowlist is exactly the kind of change that
 * turns into a leak. They stay human-only until a contract says otherwise.
 */
const MANAGER_AGENT_READ_ROUTES: ReadonlySet<ConsoleRoute["name"]> = new Set([
  "audit",
  "audit-summary",
  "policy-compliance-get",
  "disputes-list",
  "fragmentation-get",
]);

/**
 * Transport-level role matrix for the control room. Kernel handlers still
 * enforce namespace scope; this gate keeps the routes a visible screen calls
 * aligned with the signed-in role.
 */
function canAccessConsoleRoute(
  route: ConsoleRoute,
  identity: Identity,
): boolean {
  if (identity.role === "agent") {
    // D50 (CONTRACTS-AGENT-SCOPE.md): a MANAGER-level agent is the machine form
    // of the team admin scope, so it may READ its own team's governance
    // surfaces — and nothing else. Every other agent route decision stays the
    // fail-closed default below. Namespace scope is still enforced by the
    // handlers from identity.namespace; this gate only decides "which surface".
    return (
      MANAGER_AGENT_READ_ROUTES.has(route.name) &&
      !route.mutating &&
      effectiveAgentLevel(identity) === "manager"
    );
  }
  if (
    route.name === "setup" ||
    route.name === "setup-capabilities" ||
    route.name === "setup-status" ||
    route.name === "setup-retry"
  ) {
    return identity.role === "owner" && identity.namespace === "";
  }
  if (route.name === "teams-get") return canHuman(identity.role, "teams:read");
  if (route.name === "team-directory-get")
    return canHuman(identity.role, "teams:read");
  if (route.name === "teams-post")
    return canHuman(identity.role, "teams:write");
  if (route.name === "team-memory-access-change") {
    return canHuman(identity.role, "teams:write");
  }
  if (route.name === "team-invitation-create") {
    return canHuman(identity.role, "members:invite");
  }
  if (route.name === "team-member-add" || route.name === "team-member-remove") {
    return canHuman(identity.role, "members:write");
  }
  if (route.name === "team-member-role-change") {
    return canHuman(identity.role, "roles:write");
  }
  if (route.name === "assistant-purge") {
    return identity.role === "owner";
  }
  // The name and mark of the organization you work in are not privileged: the
  // Settings screen shows them to every human role. Writing them is not — the
  // kernel module enforces `organization:write` again, so this gate is the
  // transport half of one rule, not the whole of it.
  // (the machine-principal case already returned above, so this is a human)
  if (route.name === "organization-get") return true;
  if (route.name === "organization-patch") {
    return canHuman(identity.role, "organization:write");
  }
  if (identity.role === "member") {
    // Members get a team-scoped READ view (PRD persona): Home, Memory Map,
    // the usage/query-traction ledger, and the accuracy rollup. Scoping is
    // enforced by the read models via identity.namespace, not here.
    return (
      !route.mutating &&
      (route.name === "overview" ||
        route.name === "memory-map" ||
        route.name === "usage-queries" ||
        route.name === "usage-query" ||
        route.name === "usage-rollup" ||
        route.name === "usage-ai-turns" ||
        route.name === "usage-ai-turn" ||
        route.name === "usage-ai-rollup" ||
        route.name === "assistant-recycle-bin" ||
        route.name === "accuracy" ||
        route.name === "sources-get" ||
        route.name === "knowledge-bases-get" ||
        route.name === "knowledge-base-sources-get" ||
        route.name === "company-files-get" ||
        route.name === "connectors-get")
    );
  }
  if (identity.role === "auditor") return !route.mutating;
  return identity.role === "owner" || identity.role === "admin";
}

async function auditHaloAgentsHandoff(
  deps: HttpServerDeps,
  identity: Identity,
  result: "ok" | "denied" | "error",
  detail: string,
): Promise<void> {
  await deps.audit.append({
    ts: new Date().toISOString(),
    actor: identity.actor,
    agentId: AGENT_ID,
    op: "read",
    memoryId: null,
    namespace: identity.namespace,
    purpose: "halo-agents-sso-handoff",
    result,
    detail,
  });
}

function decodeConsolePathSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new HttpError(
      400,
      "bad_request",
      "route contains invalid percent encoding",
    );
  }
}

/** Match a path+method to a control-room route, or null if it is not one. */
function matchConsoleRoute(path: string, method: string): ConsoleRoute | null {
  if (path === "/v1/admin/overview" && method === "GET") {
    return { name: "overview", mutating: false };
  }
  if (path === "/v1/admin/policy-documents") {
    if (method === "GET")
      return { name: "policy-documents-get", mutating: false };
    if (method === "POST")
      return { name: "policy-documents-post", mutating: true };
  }
  // Registered before the `/policy-documents/:id` matchers so the literal
  // segment can never be read as a document id.
  if (path === "/v1/admin/policy-documents/adopt" && method === "POST") {
    return { name: "policy-document-adopt", mutating: true };
  }
  if (path === "/v1/admin/policy-adoption-candidates" && method === "GET") {
    return { name: "policy-adoption-candidates-get", mutating: false };
  }
  if (path === "/v1/admin/policy-scopes" && method === "GET") {
    return { name: "policy-scopes-get", mutating: false };
  }
  if (path === "/v1/admin/policy-compliance" && method === "GET") {
    return { name: "policy-compliance-get", mutating: false };
  }
  const policyEnforcement =
    /^\/v1\/admin\/policy-documents\/([^/]+)\/enforcement$/.exec(path);
  if (policyEnforcement && method === "PUT") {
    return {
      name: "policy-enforcement-put",
      id: decodeConsolePathSegment(policyEnforcement[1] ?? ""),
      mutating: true,
    };
  }
  const policyDocumentDelete = /^\/v1\/admin\/policy-documents\/([^/]+)$/.exec(
    path,
  );
  if (policyDocumentDelete && method === "DELETE") {
    return {
      name: "policy-document-delete",
      id: decodeConsolePathSegment(policyDocumentDelete[1] ?? ""),
      mutating: true,
    };
  }
  if (path === "/v1/admin/organization") {
    if (method === "GET") return { name: "organization-get", mutating: false };
    if (method === "PATCH")
      return { name: "organization-patch", mutating: true };
  }
  if (path === "/v1/admin/people") {
    if (method === "GET") return { name: "people-get", mutating: false };
    if (method === "POST") return { name: "people-post", mutating: true };
  }
  const personAccessImpact =
    /^\/v1\/admin\/people\/([^/]+)\/access-impact$/.exec(path);
  if (personAccessImpact && method === "GET") {
    return {
      name: "person-access-impact",
      mutating: false,
      id: decodeConsolePathSegment(personAccessImpact[1]),
    };
  }
  const personAccessState = /^\/v1\/admin\/people\/([^/]+)\/access-state$/.exec(
    path,
  );
  if (personAccessState && method === "PUT") {
    return {
      name: "person-access-state",
      mutating: true,
      id: decodeConsolePathSegment(personAccessState[1]),
    };
  }
  if (path === "/v1/admin/teams") {
    if (method === "GET") return { name: "teams-get", mutating: false };
    if (method === "POST") return { name: "teams-post", mutating: true };
  }
  const teamOne = /^\/v1\/admin\/teams\/([^/]+)$/.exec(path);
  if (teamOne && method === "PUT") {
    return {
      name: "team-update",
      mutating: true,
      id: decodeConsolePathSegment(teamOne[1]),
    };
  }
  const teamMemoryAccess = /^\/v1\/admin\/teams\/([^/]+)\/memory-access$/.exec(
    path,
  );
  if (teamMemoryAccess && method === "PUT") {
    return {
      name: "team-memory-access-change",
      mutating: true,
      id: decodeConsolePathSegment(teamMemoryAccess[1]),
    };
  }
  const teamMembers = /^\/v1\/admin\/teams\/([^/]+)\/members$/.exec(path);
  if (teamMembers && method === "POST") {
    return {
      name: "team-member-add",
      mutating: true,
      id: decodeConsolePathSegment(teamMembers[1]),
    };
  }
  if (path === "/v1/admin/team-directory" && method === "GET") {
    return { name: "team-directory-get", mutating: false };
  }
  const teamInvitations = /^\/v1\/admin\/teams\/([^/]+)\/invitations$/.exec(
    path,
  );
  if (teamInvitations && method === "POST") {
    return {
      name: "team-invitation-create",
      mutating: true,
      id: decodeConsolePathSegment(teamInvitations[1]),
    };
  }
  const teamInvitationOne =
    /^\/v1\/admin\/teams\/([^/]+)\/invitations\/([^/]+)$/.exec(path);
  if (teamInvitationOne && method === "DELETE") {
    return {
      name: "team-invitation-revoke",
      mutating: true,
      id: decodeConsolePathSegment(teamInvitationOne[1]),
      memberId: decodeConsolePathSegment(teamInvitationOne[2]),
    };
  }
  const teamInvitationRotation =
    /^\/v1\/admin\/teams\/([^/]+)\/invitations\/([^/]+)\/rotation$/.exec(path);
  if (teamInvitationRotation && method === "PUT") {
    return {
      name: "team-invitation-rotate",
      mutating: true,
      id: decodeConsolePathSegment(teamInvitationRotation[1]),
      memberId: decodeConsolePathSegment(teamInvitationRotation[2]),
    };
  }
  const teamMemberRole =
    /^\/v1\/admin\/teams\/([^/]+)\/members\/([^/]+)\/role$/.exec(path);
  if (teamMemberRole && method === "PUT") {
    return {
      name: "team-member-role-change",
      mutating: true,
      id: decodeConsolePathSegment(teamMemberRole[1]),
      memberId: decodeConsolePathSegment(teamMemberRole[2]),
    };
  }
  const teamMemberOne = /^\/v1\/admin\/teams\/([^/]+)\/members\/([^/]+)$/.exec(
    path,
  );
  if (teamMemberOne && method === "DELETE") {
    return {
      name: "team-member-remove",
      mutating: true,
      id: decodeConsolePathSegment(teamMemberOne[1]),
      memberId: decodeConsolePathSegment(teamMemberOne[2]),
    };
  }
  if (path === "/v1/admin/memory-map" && method === "GET") {
    return { name: "memory-map", mutating: false };
  }
  if (path === "/v1/admin/audit" && method === "GET") {
    return { name: "audit", mutating: false };
  }
  if (path === "/v1/admin/audit/summary" && method === "GET") {
    return { name: "audit-summary", mutating: false };
  }
  if (path === "/v1/admin/audit/export.csv" && method === "GET") {
    return { name: "audit-csv", mutating: false };
  }
  if (path === "/v1/admin/sources") {
    if (method === "GET") return { name: "sources-get", mutating: false };
    if (method === "POST") return { name: "sources-post", mutating: true };
  }
  if (path === "/v1/admin/knowledge-bases") {
    if (method === "GET")
      return { name: "knowledge-bases-get", mutating: false };
    if (method === "POST")
      return { name: "knowledge-bases-post", mutating: true };
  }
  const knowledgeBaseSources =
    /^\/v1\/admin\/knowledge-bases\/([^/]+)\/sources$/.exec(path);
  if (knowledgeBaseSources) {
    if (method === "GET") {
      return {
        name: "knowledge-base-sources-get",
        mutating: false,
        id: decodeConsolePathSegment(knowledgeBaseSources[1]),
      };
    }
    if (method === "POST") {
      return {
        name: "knowledge-base-sources-post",
        mutating: true,
        id: decodeConsolePathSegment(knowledgeBaseSources[1]),
      };
    }
  }
  const knowledgeBaseLifecycle =
    /^\/v1\/admin\/knowledge-bases\/([^/]+)\/(pause|resume|archive)$/.exec(
      path,
    );
  if (knowledgeBaseLifecycle && method === "POST") {
    return {
      name: `knowledge-base-${knowledgeBaseLifecycle[2]}` as
        | "knowledge-base-pause"
        | "knowledge-base-resume"
        | "knowledge-base-archive",
      mutating: true,
      id: decodeConsolePathSegment(knowledgeBaseLifecycle[1]),
    };
  }
  if (path === "/v1/admin/company-files") {
    if (method === "GET") return { name: "company-files-get", mutating: false };
    if (method === "POST")
      return { name: "company-files-post", mutating: true };
  }
  const companyFileUploadStatus =
    /^\/v1\/admin\/company-file-uploads\/([^/]+)$/.exec(path);
  if (companyFileUploadStatus && method === "GET") {
    return {
      name: "company-file-upload-status",
      mutating: false,
      id: decodeConsolePathSegment(companyFileUploadStatus[1]),
    };
  }
  if (path === "/v1/admin/entity-relationships" && method === "GET") {
    return { name: "entity-relationships-get", mutating: false };
  }
  const companyFileArchive =
    /^\/v1\/admin\/company-files\/([^/]+)\/archive$/.exec(path);
  if (companyFileArchive && method === "POST") {
    return {
      name: "company-file-archive",
      mutating: true,
      id: decodeConsolePathSegment(companyFileArchive[1]),
    };
  }
  const sourceMetadata = /^\/v1\/admin\/sources\/([^/]+)\/metadata$/.exec(path);
  if (sourceMetadata && method === "PATCH") {
    return {
      name: "source-metadata-patch",
      mutating: true,
      id: decodeConsolePathSegment(sourceMetadata[1]),
    };
  }
  if (path === "/v1/admin/connectors" && method === "GET") {
    return { name: "connectors-get", mutating: false };
  }
  if (path === "/v1/admin/source-credentials") {
    if (method === "GET")
      return { name: "source-credentials-get", mutating: false };
    if (method === "POST")
      return { name: "source-credentials-post", mutating: true };
  }
  if (path === "/v1/admin/nango/connect-sessions" && method === "POST") {
    return { name: "nango-connect-start", mutating: true };
  }
  const nangoComplete =
    /^\/v1\/admin\/nango\/connect-sessions\/([^/]+)\/complete$/.exec(path);
  if (nangoComplete && method === "POST") {
    return {
      name: "nango-connect-complete",
      mutating: true,
      id: decodeConsolePathSegment(nangoComplete[1]),
    };
  }
  const sourceOAuthStart =
    /^\/v1\/admin\/connectors\/oauth\/([a-z0-9_-]{1,64})\/start$/.exec(path);
  if (sourceOAuthStart && method === "POST") {
    return {
      name: "source-oauth-start",
      mutating: true,
      id: sourceOAuthStart[1],
    };
  }
  if (path === "/v1/admin/connectors/obsidian/pair" && method === "POST") {
    return { name: "obsidian-pair", mutating: true };
  }
  const syncMatch = /^\/v1\/admin\/sources\/([^/]+)\/sync$/.exec(path);
  if (syncMatch && method === "POST") {
    return {
      name: "source-sync",
      mutating: true,
      id: decodeURIComponent(syncMatch[1]),
    };
  }
  const csvImportMatch = /^\/v1\/admin\/sources\/([^/]+)\/import-csv$/.exec(
    path,
  );
  if (csvImportMatch && method === "POST") {
    return {
      name: "source-import-csv",
      mutating: true,
      id: decodeURIComponent(csvImportMatch[1]),
    };
  }
  const lineageMatch = /^\/v1\/admin\/sources\/([^/]+)\/lineage$/.exec(path);
  if (lineageMatch && method === "GET") {
    return {
      name: "source-lineage-get",
      mutating: false,
      id: decodeConsolePathSegment(lineageMatch[1]),
    };
  }
  const lifecycleMatch =
    /^\/v1\/admin\/sources\/([^/]+)\/(test|pause|resume|schedule)$/.exec(path);
  if (lifecycleMatch && method === "POST") {
    return {
      name: `source-${lifecycleMatch[2]}` as
        "source-test" | "source-pause" | "source-resume" | "source-schedule",
      mutating: lifecycleMatch[2] !== "test",
      id: decodeURIComponent(lifecycleMatch[1]),
    };
  }
  if (path === "/v1/admin/fragmentation") {
    if (method === "GET") return { name: "fragmentation-get", mutating: false };
    if (method === "POST")
      return { name: "fragmentation-post", mutating: true };
  }
  // M9 parity console read models. `/v1/admin/setup-checklist` is an EXACT
  // match placed before the `/v1/admin/setup/:id` regex family so the
  // setup-status route can never swallow it (builder #5's collision note).
  if (path === "/v1/admin/setup-checklist" && method === "GET") {
    return { name: "setup-checklist", mutating: false };
  }
  if (path === "/v1/admin/readiness" && method === "GET") {
    return { name: "readiness", mutating: false };
  }
  if (path === "/v1/admin/user-analytics" && method === "GET") {
    return { name: "user-analytics", mutating: false };
  }
  if (path === "/v1/admin/gaps" && method === "GET") {
    return { name: "gaps", mutating: false };
  }
  if (path === "/v1/admin/accuracy" && method === "GET") {
    return { name: "accuracy", mutating: false };
  }
  if (path === "/v1/admin/automations") {
    if (method === "GET") return { name: "automations-get", mutating: false };
    if (method === "PUT") return { name: "automations-put", mutating: true };
  }
  if (path === "/v1/admin/credits" && method === "GET") {
    return { name: "credits", mutating: false };
  }
  // M9 W3 #22 (E53/E56): S2 usage panel — summary read + cap/alert edits.
  // Usage analytics / query traction. The exact `/queries` match is placed
  // BEFORE the `:traceId` regex so the ledger route can never be swallowed.
  if (path === "/v1/admin/usage/queries" && method === "GET") {
    return { name: "usage-queries", mutating: false };
  }
  if (path === "/v1/admin/usage/rollup" && method === "GET") {
    return { name: "usage-rollup", mutating: false };
  }
  if (path === "/v1/admin/usage/turns" && method === "GET") {
    return { name: "usage-ai-turns", mutating: false };
  }
  if (path === "/v1/admin/usage/ai-rollup" && method === "GET") {
    return { name: "usage-ai-rollup", mutating: false };
  }
  if (path === "/v1/admin/usage/recycle-bin" && method === "GET") {
    return { name: "assistant-recycle-bin", mutating: false };
  }
  const usageAiTurn = /^\/v1\/admin\/usage\/turns\/([^/]+)$/.exec(path);
  if (usageAiTurn && method === "GET") {
    return {
      name: "usage-ai-turn",
      mutating: false,
      id: decodeConsolePathSegment(usageAiTurn[1]),
    };
  }
  const assistantRecycle =
    /^\/v1\/admin\/usage\/recycle-bin\/([^/]+)\/(recycle|restore|purge)$/.exec(
      path,
    );
  if (assistantRecycle && method === "POST") {
    return {
      name:
        assistantRecycle[2] === "recycle"
          ? "assistant-recycle"
          : assistantRecycle[2] === "restore"
            ? "assistant-restore"
            : "assistant-purge",
      mutating: true,
      id: decodeConsolePathSegment(assistantRecycle[1]),
    };
  }
  const usageQueryTrace = /^\/v1\/admin\/usage\/queries\/([^/]+)$/.exec(path);
  if (usageQueryTrace && method === "GET") {
    return {
      name: "usage-query",
      mutating: false,
      id: decodeConsolePathSegment(usageQueryTrace[1]),
    };
  }
  if (path === "/v1/admin/usage" && method === "GET") {
    return { name: "usage-get", mutating: false };
  }
  if (path === "/v1/admin/usage/cap" && method === "PUT") {
    return { name: "usage-cap-put", mutating: true };
  }
  if (path === "/v1/admin/usage/alerts" && method === "PUT") {
    return { name: "usage-alerts-put", mutating: true };
  }
  if (path === "/v1/admin/setup" && method === "POST") {
    return { name: "setup", mutating: true };
  }
  if (path === "/v1/admin/setup/capabilities" && method === "GET") {
    return { name: "setup-capabilities", mutating: false };
  }
  const setupRetry = /^\/v1\/admin\/setup\/([^/]+)\/retry$/.exec(path);
  if (setupRetry && method === "POST") {
    return {
      name: "setup-retry",
      mutating: true,
      id: decodeURIComponent(setupRetry[1]),
    };
  }
  const setupStatus = /^\/v1\/admin\/setup\/([^/]+)$/.exec(path);
  if (setupStatus && method === "GET") {
    return {
      name: "setup-status",
      mutating: false,
      id: decodeURIComponent(setupStatus[1]),
    };
  }
  if (path === "/v1/admin/proposals" && method === "GET") {
    return { name: "proposals-list", mutating: false };
  }
  if (path === "/v1/admin/proposals/metrics" && method === "GET") {
    return { name: "proposal-metrics", mutating: false };
  }
  if (path === "/v1/admin/consolidation/runs" && method === "POST") {
    return { name: "consolidation-run", mutating: true };
  }
  const proposalAction =
    /^\/v1\/admin\/proposals\/([^/]+)\/(edit|approve|reject)$/.exec(path);
  if (proposalAction && method === "POST") {
    return {
      name: `proposal-${proposalAction[2]}` as
        "proposal-edit" | "proposal-approve" | "proposal-reject",
      mutating: true,
      id: decodeURIComponent(proposalAction[1]),
    };
  }
  const proposal = /^\/v1\/admin\/proposals\/([^/]+)$/.exec(path);
  if (proposal && method === "GET") {
    return {
      name: "proposal-get",
      mutating: false,
      id: decodeURIComponent(proposal[1]),
    };
  }
  if (path === "/v1/admin/disputes" && method === "GET") {
    return { name: "disputes-list", mutating: false };
  }
  if (path === "/v1/admin/knowledge-sync") {
    if (method === "GET")
      return { name: "knowledge-sync-status", mutating: false };
    if (method === "POST") return { name: "knowledge-sync", mutating: true };
  }
  if (path === "/v1/admin/conflicts" && method === "GET") {
    return { name: "conflicts-list", mutating: false };
  }
  if (path === "/v1/admin/conflict-scans" && method === "POST") {
    return { name: "conflict-scan-request", mutating: true };
  }
  if (path === "/v1/admin/conflict-scans/latest" && method === "GET") {
    return { name: "conflict-scan-latest", mutating: false };
  }
  const conflictScan = /^\/v1\/admin\/conflict-scans\/([^/]+)$/.exec(path);
  if (conflictScan && method === "GET") {
    return {
      name: "conflict-scan-get",
      mutating: false,
      id: decodeURIComponent(conflictScan[1]),
    };
  }
  const conflictFinding =
    /^\/v1\/admin\/conflict-findings\/([^/]+)\/(acknowledge|dismiss|resolve|overturn)$/.exec(
      path,
    );
  if (conflictFinding && method === "POST") {
    return {
      name: `conflict-finding-${conflictFinding[2]}` as
        | "conflict-finding-acknowledge"
        | "conflict-finding-dismiss"
        | "conflict-finding-resolve"
        | "conflict-finding-overturn",
      mutating: true,
      id: decodeURIComponent(conflictFinding[1]),
    };
  }
  const disputeResolve = /^\/v1\/admin\/disputes\/([^/]+)\/resolve$/.exec(path);
  if (disputeResolve && method === "POST") {
    return {
      name: "dispute-resolve",
      mutating: true,
      id: decodeURIComponent(disputeResolve[1]),
    };
  }
  return null;
}

/** Dispatch a matched control-room route to its (optional) handler. */
async function handleConsoleRoute(
  deps: HttpServerDeps,
  route: ConsoleRoute,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  identity: Identity,
): Promise<void> {
  const require = <T>(handler: T | undefined, what: string): T => {
    if (handler === undefined)
      throw new HttpError(404, "not_found", `${what} unavailable`);
    return handler;
  };
  const requiredNamespace = (): Namespace => {
    const ns = url.searchParams.get("namespace");
    if (ns === null) {
      throw new HttpError(
        400,
        "invalid_query",
        "'namespace' query param is required",
      );
    }
    return ns;
  };

  switch (route.name) {
    case "overview":
      return json(
        res,
        200,
        await require(deps.admin.overview, "overview")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "policy-documents-get":
      return json(
        res,
        200,
        await require(deps.admin.listPolicyDocuments, "policy documents")(
          policyDocumentQueryFromUrl(url, identity),
          identity,
        ),
      );
    case "policy-documents-post": {
      const body = await readJsonObject(req, MAX_POLICY_DOCUMENT_BODY_BYTES);
      return json(
        res,
        201,
        await require(deps.admin
          .uploadPolicyDocument, "policy document upload")(body, identity),
      );
    }
    case "policy-scopes-get":
      return json(
        res,
        200,
        await require(deps.admin.listPolicyDocumentScopes, "policy scopes")(
          policyScopeQueryFromUrl(url),
          identity,
        ),
      );
    case "policy-adoption-candidates-get":
      return json(
        res,
        200,
        await require(deps.admin
          .listPolicyAdoptionCandidates, "policy adoption candidates")(
          policyAdoptionQueryFromUrl(url),
          identity,
        ),
      );
    case "policy-document-adopt": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.adoptPolicyDocument, "policy document adopt")(
          body,
          identity,
        ),
      );
    }
    case "policy-compliance-get":
      return json(
        res,
        200,
        await require(deps.admin.policyCompliance, "policy compliance")(
          requiredNamespace(),
          identity,
        ),
      );
    case "policy-enforcement-put": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.setPolicyEnforcement, "policy enforcement")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "policy-document-delete": {
      await require(deps.admin.deletePolicyDocument, "policy document delete")(
        route.id ?? "",
        identity,
      );
      return json(res, 204, { ok: true });
    }
    case "organization-get": {
      const organization = await require(deps.admin
        .organizationSettings, "organization settings")(identity);
      // A session that resolves to no tenant (the platform root on a
      // multi-tenant deployment) is not an error — the screen renders the
      // profile half and says the organization surface is unavailable.
      return json(res, 200, { organization: organization ?? null });
    }
    case "organization-patch": {
      const body = await readJsonObject(req);
      return json(res, 200, {
        organization: await require(deps.admin
          .updateOrganizationSettings, "organization settings")(body, identity),
      });
    }
    case "people-get":
      return json(
        res,
        200,
        await require(deps.admin.people, "people")(identity),
      );
    case "team-directory-get":
      return json(
        res,
        200,
        await require(deps.admin.teamDirectory, "team directory")(identity),
      );
    case "people-post": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.invitePerson, "invite")(body, identity),
      );
    }
    case "person-access-impact":
      return json(
        res,
        200,
        await require(deps.admin.personAccessImpact, "person access impact")(
          route.id ?? "",
          identity,
        ),
      );
    case "person-access-state": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .changePersonAccessState, "person access state")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "teams-get":
      return json(
        res,
        200,
        await require(deps.admin.listTeams, "teams")(identity),
      );
    case "teams-post": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.createTeam, "team create")(body, identity),
      );
    }
    case "team-update": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.updateTeam, "team update")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-memory-access-change": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .changeTeamMemoryAccess, "team memory access change")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-member-add": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.addTeamMember, "team member add")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-invitation-create": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.inviteTeamMember, "team invitation create")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-invitation-rotate": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .rotateTeamInvitation, "team invitation rotation")(
          route.id ?? "",
          route.memberId ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-invitation-revoke":
      return json(
        res,
        200,
        await require(deps.admin
          .revokeTeamInvitation, "team invitation revoke")(
          route.id ?? "",
          route.memberId ?? "",
          identity,
        ),
      );
    case "team-member-role-change": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .changeTeamMemberRole, "team member role change")(
          route.id ?? "",
          route.memberId ?? "",
          body,
          identity,
        ),
      );
    }
    case "team-member-remove":
      return json(
        res,
        200,
        await require(deps.admin.removeTeamMember, "team member remove")(
          route.id ?? "",
          route.memberId ?? "",
          identity,
        ),
      );
    case "memory-map":
      return json(
        res,
        200,
        await require(deps.admin.memoryMap, "memory map")(
          requiredNamespace(),
          identity,
        ),
      );
    case "audit": {
      const filters = auditFiltersFromQuery(url);
      return json(
        res,
        200,
        await require(deps.admin.auditSearch, "audit search")(
          filters,
          identity,
        ),
      );
    }
    case "audit-summary": {
      const filters = auditFiltersFromQuery(url);
      return json(
        res,
        200,
        await require(deps.admin.auditSummary, "audit summary")(
          filters,
          identity,
        ),
      );
    }
    case "audit-csv": {
      const filters = auditFiltersFromQuery(url);
      const result = await require(deps.admin
        .auditExportCsv, "audit csv export")(filters, identity);
      const body = Buffer.from(result.csv, "utf8");
      res.writeHead(200, {
        "content-type": "text/csv; charset=utf-8",
        "content-length": body.byteLength,
        "content-disposition": `attachment; filename="${result.filename.replaceAll('"', "")}"`,
        // The download itself must be able to state its own completeness: the
        // screen turns these into "N events" / "narrow the range" rather than
        // guessing from the byte count.
        "x-audit-rows": String(result.rowCount),
        "x-audit-truncated": result.truncated ? "true" : "false",
      });
      res.end(body);
      return;
    }
    case "sources-get":
      return json(
        res,
        200,
        await require(deps.admin.sourcesView, "sources")(identity),
      );
    case "source-lineage-get":
      return json(
        res,
        200,
        await require(deps.admin.sourceLineage, "source lineage")(
          route.id ?? "",
          identity,
        ),
      );
    case "sources-post": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.connectSource, "connect source")(
          body,
          identity,
        ),
      );
    }
    case "knowledge-bases-get":
      return json(
        res,
        200,
        await require(deps.admin.listKnowledgeBases, "knowledge bases")(
          knowledgeBaseQueryFromUrl(url),
          identity,
        ),
      );
    case "knowledge-bases-post":
      return json(
        res,
        201,
        await require(deps.admin.createKnowledgeBase, "knowledge base create")(
          await readJsonObject(req),
          identity,
        ),
      );
    case "knowledge-base-sources-get":
      return json(
        res,
        200,
        await require(deps.admin
          .listKnowledgeBaseSources, "knowledge base pieces")(
          route.id ?? "",
          selectedQueryFromUrl(url, ["page", "pageSize"]),
          identity,
        ),
      );
    case "knowledge-base-sources-post":
      return json(
        res,
        201,
        await require(deps.admin
          .attachKnowledgeBaseSource, "knowledge base piece create")(
          route.id ?? "",
          await readJsonObject(req),
          identity,
        ),
      );
    case "knowledge-base-pause":
    case "knowledge-base-resume":
    case "knowledge-base-archive": {
      const action = route.name.slice("knowledge-base-".length) as
        "pause" | "resume" | "archive";
      const handler =
        action === "pause"
          ? deps.admin.pauseKnowledgeBase
          : action === "resume"
            ? deps.admin.resumeKnowledgeBase
            : deps.admin.archiveKnowledgeBase;
      return json(
        res,
        200,
        await require(handler, `knowledge base ${action}`)(
          route.id ?? "",
          await readJsonObject(req),
          identity,
        ),
      );
    }
    case "company-files-get":
      return json(
        res,
        200,
        await require(deps.admin.listCompanyFiles, "company files")(
          companyFileQueryFromUrl(url),
          identity,
        ),
      );
    case "entity-relationships-get":
      return json(
        res,
        200,
        await require(deps.admin
          .listEntityRelationships, "entity relationships")(
          entityRelationshipQueryFromUrl(url),
          identity,
        ),
      );
    case "company-files-post":
      return json(
        res,
        202,
        await require(deps.admin.uploadCompanyFile, "company file upload")(
          await readJsonObject(req, MAX_COMPANY_FILE_BODY_BYTES),
          identity,
        ),
      );
    case "company-file-upload-status":
      return json(
        res,
        200,
        await require(deps.admin.companyFileUploadStatus, "company file upload status")(
          route.id ?? "",
          identity,
        ),
      );
    case "company-file-archive":
      return json(
        res,
        200,
        await require(deps.admin.archiveCompanyFile, "company file archive")(
          route.id ?? "",
          await readJsonObject(req),
          identity,
        ),
      );
    case "source-metadata-patch":
      return json(
        res,
        200,
        await require(deps.admin
          .updateSourceMetadata, "source metadata update")(
          route.id ?? "",
          await readJsonObject(req),
          identity,
        ),
      );
    case "connectors-get":
      return json(
        res,
        200,
        await require(deps.admin.connectors, "connector catalog")(identity),
      );
    case "source-credentials-get":
      return json(
        res,
        200,
        await require(deps.admin.listSourceCredentials, "source credentials")(
          identity,
        ),
      );
    case "source-credentials-post": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.createSourceCredential, "source credentials")(
          body,
          identity,
        ),
      );
    }
    case "nango-connect-start": {
      const body = await readJsonObject(req);
      res.setHeader("cache-control", "no-store");
      return json(
        res,
        201,
        await require(deps.admin
          .createNangoConnectSession, "Nango connect session")(body, identity),
      );
    }
    case "nango-connect-complete": {
      const body = await readJsonObject(req);
      res.setHeader("cache-control", "no-store");
      return json(
        res,
        200,
        await require(deps.admin
          .completeNangoConnectSession, "Nango connect completion")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "source-oauth-start": {
      const body = await readJsonObject(req);
      res.setHeader("cache-control", "no-store");
      return json(
        res,
        201,
        await require(deps.admin.startSourceOAuth, "connector OAuth start")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "obsidian-pair": {
      const body = await readJsonObject(req);
      res.setHeader("cache-control", "no-store");
      return json(
        res,
        201,
        await require(deps.admin.pairObsidian, "Obsidian pairing")(body, identity),
      );
    }
    case "source-sync":
      return json(
        res,
        202,
        await require(deps.admin.syncSource, "source sync")(
          route.id ?? "",
          identity,
        ),
      );
    case "source-import-csv": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.importCsvSource, "CSV source import")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "source-test":
      return json(
        res,
        200,
        await require(deps.admin.testSource, "source test")(
          route.id ?? "",
          identity,
        ),
      );
    case "source-pause":
      return json(
        res,
        200,
        await require(deps.admin.pauseSource, "source pause")(
          route.id ?? "",
          identity,
        ),
      );
    case "source-resume":
      return json(
        res,
        200,
        await require(deps.admin.resumeSource, "source resume")(
          route.id ?? "",
          identity,
        ),
      );
    case "source-schedule": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.scheduleSource, "source schedule")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "fragmentation-get":
      return json(
        res,
        200,
        await require(deps.admin.getFragmentation, "fragmentation")(
          requiredNamespace(),
          identity,
        ),
      );
    case "fragmentation-post": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.runFragmentation, "fragmentation")(
          body,
          identity,
        ),
      );
    }
    case "setup": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.setup, "setup")(body, identity),
      );
    }
    case "setup-capabilities":
      return json(
        res,
        200,
        await require(deps.admin.setupCapabilities, "setup capabilities")(
          identity,
        ),
      );
    case "setup-status":
      return json(
        res,
        200,
        await require(deps.admin.setupStatus, "setup status")(
          route.id ?? "",
          identity,
        ),
      );
    case "setup-retry":
      return json(
        res,
        200,
        await require(deps.admin.setupRetry, "setup retry")(
          route.id ?? "",
          identity,
        ),
      );
    case "proposals-list":
      return json(
        res,
        200,
        await require(deps.admin.listProposals, "proposal list")(identity),
      );
    case "proposal-get":
      return json(
        res,
        200,
        await require(deps.admin.getProposal, "proposal")(
          route.id ?? "",
          identity,
        ),
      );
    case "proposal-metrics":
      return json(
        res,
        200,
        await require(deps.admin.proposalMetrics, "proposal metrics")(
          requiredNamespace(),
          identity,
        ),
      );
    case "consolidation-run": {
      const body = await readJsonObject(req);
      return json(
        res,
        201,
        await require(deps.admin.runConsolidation, "consolidation run")(
          body,
          identity,
        ),
      );
    }
    case "proposal-edit":
    case "proposal-approve":
    case "proposal-reject": {
      const body = await readJsonObject(req);
      const handler =
        route.name === "proposal-edit"
          ? deps.admin.editProposal
          : route.name === "proposal-approve"
            ? deps.admin.approveProposal
            : deps.admin.rejectProposal;
      return json(
        res,
        200,
        await require(handler, route.name)(route.id ?? "", body, identity),
      );
    }
    case "readiness":
      return json(
        res,
        200,
        await require(deps.admin.readiness, "readiness")(identity),
      );
    case "user-analytics":
      return json(
        res,
        200,
        await require(deps.admin.userAnalytics, "user analytics")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "gaps":
      return json(
        res,
        200,
        await require(deps.admin.gapFeed, "gap feed")(identity),
      );
    case "setup-checklist":
      return json(
        res,
        200,
        await require(deps.admin.setupChecklist, "setup checklist")(identity),
      );
    case "accuracy":
      return json(
        res,
        200,
        await require(deps.admin.accuracy, "accuracy rollup")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "usage-queries":
      return json(
        res,
        200,
        await require(deps.admin.usageQueries, "usage queries")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "usage-query": {
      const detail = await require(deps.admin
        .usageQueryTrace, "usage query trace")(route.id ?? "", identity);
      // Same 404 for missing and cross-namespace: never leak existence.
      if (detail === null)
        throw new HttpError(404, "not_found", "trace not found");
      return json(res, 200, detail);
    }
    case "usage-rollup":
      return json(
        res,
        200,
        await require(deps.admin.usageRollup, "usage rollup")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "usage-ai-turns":
      return json(
        res,
        200,
        await require(deps.admin.usageAiTurns, "Assistant turns")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "usage-ai-turn": {
      const detail = await require(deps.admin
        .usageAiTurnDetail, "Assistant turn")(route.id ?? "", identity);
      if (detail === null)
        throw new HttpError(404, "not_found", "turn not found");
      return json(res, 200, detail);
    }
    case "usage-ai-rollup":
      return json(
        res,
        200,
        await require(deps.admin.usageAiRollup, "Assistant rollup")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "assistant-recycle-bin":
      return json(
        res,
        200,
        await require(deps.admin.assistantRecycleBin, "Assistant recycle bin")(
          identity,
        ),
      );
    case "assistant-recycle":
      return json(
        res,
        200,
        await require(deps.admin.recycleAssistantActor, "Assistant recycle")(
          route.id ?? "",
          identity,
        ),
      );
    case "assistant-restore":
      return json(
        res,
        200,
        await require(deps.admin.restoreAssistantActor, "Assistant restore")(
          route.id ?? "",
          identity,
        ),
      );
    case "assistant-purge": {
      const body = await readJsonObject(req);
      const confirmation =
        typeof body.confirmation === "string" ? body.confirmation : "";
      if (confirmation !== `PURGE:${route.id ?? ""}`) {
        throw new HttpError(
          400,
          "invalid_request",
          "explicit purge confirmation is required",
        );
      }
      return json(
        res,
        200,
        await require(deps.admin.purgeAssistantActor, "Assistant purge")(
          route.id ?? "",
          confirmation,
          identity,
        ),
      );
    }
    case "automations-get":
      return json(
        res,
        200,
        await require(deps.admin.listAutomations, "automations")(identity),
      );
    case "automations-put": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.configureAutomation, "automations")(
          body,
          identity,
        ),
      );
    }
    case "knowledge-sync-status":
      return json(
        res,
        200,
        await require(deps.admin.knowledgeSyncStatus, "knowledge sync status")(
          identity,
        ),
      );
    case "credits":
      return json(
        res,
        200,
        await require(deps.admin.credits, "credits")(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    case "usage-get":
      return json(
        res,
        200,
        await require(deps.admin.usageSummary, "usage summary")(identity),
      );
    case "usage-cap-put": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.setUsageCap, "usage cap")(body, identity),
      );
    }
    case "usage-alerts-put": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.upsertUsageAlert, "usage alerts")(
          body,
          identity,
        ),
      );
    }
    case "disputes-list":
      return json(
        res,
        200,
        await require(deps.admin.listDisputes, "dispute list")(identity),
      );
    case "conflicts-list":
      return json(
        res,
        200,
        await require(deps.admin.listConflicts, "conflict list")(identity),
      );
    case "conflict-scan-request": {
      const body = await readJsonObject(req);
      return json(
        res,
        202,
        await require(deps.admin.requestConflictScan, "conflict scan")(
          body,
          identity,
        ),
      );
    }
    case "knowledge-sync": {
      const body = await readJsonObject(req);
      if (
        ["namespace", "actor", "keyId", "role"].some((field) => field in body)
      ) {
        throw new HttpError(
          400,
          "identity_from_key",
          "namespace comes from your key",
        );
      }
      return json(
        res,
        202,
        await require(deps.admin.queueKnowledgeSync, "knowledge sync")(
          body,
          identity,
        ),
      );
    }
    case "conflict-scan-latest":
      return json(
        res,
        200,
        await require(deps.admin.latestConflictScan, "latest conflict scan")(
          identity,
        ),
      );
    case "conflict-scan-get":
      return json(
        res,
        200,
        await require(deps.admin.getConflictScan, "conflict scan")(
          route.id ?? "",
          identity,
        ),
      );
    case "conflict-finding-acknowledge":
    case "conflict-finding-dismiss": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .reviewConflictFinding, "conflict finding review")(
          route.id ?? "",
          route.name === "conflict-finding-acknowledge"
            ? "acknowledge"
            : "dismiss",
          body,
          identity,
        ),
      );
    }
    case "conflict-finding-resolve": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .resolveConflictFinding, "conflict finding resolve")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    // CA4: undo an automatic decision. Same authority as resolving one by hand.
    case "conflict-finding-overturn": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin
          .overturnConflictFinding, "conflict finding overturn")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
    case "dispute-resolve": {
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await require(deps.admin.resolveDispute, "dispute resolve")(
          route.id ?? "",
          body,
          identity,
        ),
      );
    }
  }
}

/** Convert known policy-register query parameters without accepting identity fields. */
function policyDocumentQueryFromUrl(
  url: URL,
  identity: Identity,
): Record<string, unknown> {
  const params = url.searchParams;
  const query: Record<string, unknown> = {
    namespace: params.get("namespace") ?? identity.namespace,
  };
  for (const key of ["page", "pageSize"] as const) {
    const value = params.get(key);
    if (value !== null) query[key] = Number(value);
  }
  for (const key of ["query", "kind", "status"] as const) {
    const value = params.get(key);
    if (value !== null && value !== "") query[key] = value;
  }
  return query;
}

/** Scope + bound for the "policy files found in memory" lane. */
function policyAdoptionQueryFromUrl(url: URL): Record<string, unknown> {
  const query: Record<string, unknown> = {};
  const namespace = url.searchParams.get("namespace");
  const limit = url.searchParams.get("limit");
  if (namespace !== null) query.namespace = namespace;
  if (limit !== null) query.limit = Number(limit);
  return query;
}

function policyScopeQueryFromUrl(url: URL): Record<string, unknown> {
  const query: Record<string, unknown> = {};
  const term = url.searchParams.get("query");
  const limit = url.searchParams.get("limit");
  if (term !== null && term !== "") query.query = term;
  if (limit !== null) query.limit = Number(limit);
  return query;
}

function selectedQueryFromUrl(
  url: URL,
  keys: readonly string[],
): Record<string, unknown> {
  const query: Record<string, unknown> = {};
  for (const [key, value] of url.searchParams.entries()) {
    if (!keys.includes(key)) {
      throw new HttpError(
        400,
        "invalid_query",
        `unknown query parameter '${key}'`,
      );
    }
    query[key] = key === "page" || key === "pageSize" ? Number(value) : value;
  }
  return query;
}

function knowledgeBaseQueryFromUrl(url: URL): Record<string, unknown> {
  return selectedQueryFromUrl(url, [
    "query",
    "targetTeamId",
    "kind",
    "status",
    "lifecycleState",
    "page",
    "pageSize",
  ]);
}

function companyFileQueryFromUrl(url: URL): Record<string, unknown> {
  const query = selectedQueryFromUrl(url, [
    "knowledgeBaseId",
    "targetTeamId",
    "query",
    "status",
    "lifecycleState",
    "includeUploads",
    "page",
    "pageSize",
  ]);
  if (typeof query.includeUploads === "string") {
    if (query.includeUploads !== "true" && query.includeUploads !== "false") {
      throw new HttpError(
        400,
        "invalid_query",
        "includeUploads must be true or false",
      );
    }
    query.includeUploads = query.includeUploads === "true";
  }
  return query;
}

function entityRelationshipQueryFromUrl(url: URL): Record<string, unknown> {
  const query = selectedQueryFromUrl(url, [
    "entityId",
    "relationship",
    "direction",
    "includeArchived",
    "limit",
  ]);
  if (typeof query.includeArchived === "string") {
    if (query.includeArchived !== "true" && query.includeArchived !== "false") {
      throw new HttpError(
        400,
        "invalid_query",
        "includeArchived must be true or false",
      );
    }
    query.includeArchived = query.includeArchived === "true";
  }
  if (typeof query.limit === "string") query.limit = Number(query.limit);
  return query;
}

/** Build AuditSearchFilters from the S8 query string (all params optional). */
function auditFiltersFromQuery(url: URL): Record<string, unknown> {
  const q = url.searchParams;
  const filters: Record<string, unknown> = {};
  for (const key of [
    "actor",
    "agentId",
    "op",
    "result",
    "since",
    "until",
  ] as const) {
    const v = q.get(key);
    if (v !== null) filters[key] = v;
  }
  const limit = q.get("limit");
  if (limit !== null && limit !== "") {
    const n = Number(limit);
    if (Number.isFinite(n)) filters.limit = n;
  }
  return filters;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

async function route(
  deps: HttpServerDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  context: {
    requestId: string;
    traceId: string;
    halomemTrace?: string;
    halomemTurn?: string;
  },
): Promise<void> {
  const method = req.method ?? "GET";
  const path = url.pathname;

  // --- open endpoints ------------------------------------------------------
  if (path === "/healthz") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    return json(res, 200, { ok: true });
  }

  if (path === "/healthz/mastra") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.copilot?.probe) return json(res, 503, { ok: false });
    try {
      await deps.copilot.probe();
      return json(res, 200, { ok: true });
    } catch {
      return json(res, 503, { ok: false });
    }
  }

  // Brand icons at the ORIGIN ROOT, unauthenticated. MCP clients (ChatGPT
  // connectors, Claude custom connectors) render a connector's icon from the
  // favicon of the host they connect to. Behind the identity middleware these
  // paths answered 401, so those clients fell back to the registrable domain's
  // icon — on Azure Container Apps that is Microsoft's, not ours. Serving the
  // Halofy mark here is what puts the Halo logo on the connector card.
  if (BRAND_ICON_PATHS.has(path)) {
    if (method !== "GET" && method !== "HEAD") {
      throw new HttpError(405, "method_not_allowed", "use GET");
    }
    if (deps.consoleDir === undefined) {
      throw new HttpError(404, "not_found", "icon not available");
    }
    return serveStatic(deps.consoleDir, BRAND_ICON_FILE, res, "", req.headers);
  }

  // M5: static console screens — served WITHOUT auth (the screens themselves
  // call the authenticated API from the browser). GET only; traversal rejected
  // inside serveStatic. No console dir configured → 404.
  if (path === "/console" || path.startsWith("/console/")) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (deps.consoleDir === undefined) {
      throw new HttpError(404, "not_found", "console not available");
    }
    return serveStatic(deps.consoleDir, path, res, url.search, req.headers);
  }

  // Whitelabel chat surface: `/chat` serves the console bundle's chat.html —
  // the Assistant screen alone, branded with the organization's own mark.
  // Same auth model as /console/*: the PAGE is public, every API call it
  // makes from the browser is cookie-authenticated and role-gated server-side.
  if (path === "/chat" || path === "/chat/") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (deps.consoleDir === undefined) {
      throw new HttpError(404, "not_found", "console not available");
    }
    return serveStatic(deps.consoleDir, "/console/chat", res, url.search, req.headers);
  }

  // SSO discovery for the login page — open by design (the page must know
  // whether to render the Google/email IdP flow before anyone signs in), and
  // never secret-bearing (see HttpAuth.ssoConfig).
  if (path === "/auth/sso/config") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    return json(res, 200, {
      ...(deps.auth.ssoConfig?.() ?? { enabled: false }),
      github: deps.auth.githubConfig?.() ?? false,
    });
  }

  let authThrottleBucket: string | null = null;
  if (
    deps.authThrottle &&
    (path === "/auth/login" ||
      path === "/auth/bootstrap" ||
      path === "/auth/invite/accept" ||
      path === "/auth/github" ||
      path === "/auth/github/callback" ||
      path === "/auth/sso" ||
      path === "/auth/signup")
  ) {
    const address = clientAddress(req, deps.trustedProxyHops);
    const bucket = createHash("sha256").update(address).digest("hex");
    authThrottleBucket = `auth:${bucket}`;
    const outcome = await deps.authThrottle.consume(authThrottleBucket);
    if (!outcome.allowed) {
      const retryAfter = Math.max(1, Math.ceil(outcome.retryAfterSec));
      res.setHeader("retry-after", String(retryAfter));
      await auditDenied(
        deps,
        "read",
        "unknown",
        "unknown",
        `429 ${method} ${path}`,
      );
      return json(res, 429, {
        error: "too many authentication attempts",
        code: "rate_limited",
      });
    }
  }

  // M5: human sign-in — the ONE unauthenticated /auth route (it mints the
  // session). Returns { user } + Set-Cookie on success; 401 (no oracle) on any
  // failure. Bad password / unknown email / disabled user all collapse to 401.
  if (path === "/auth/login") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.auth.login) {
      throw new HttpError(404, "not_found", "login unavailable");
    }
    const body = await readJsonObject(req);
    const email = body.email;
    const password = body.password;
    if (typeof email !== "string" || typeof password !== "string") {
      throw new HttpError(
        400,
        "invalid_body",
        "'email' and 'password' (strings) are required",
      );
    }
    const result = await deps.auth.login(email, password);
    if (result === null) {
      return json(res, 401, {
        error: "invalid email or password",
        code: "unauthorized",
      });
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    clearSignupCookie(res);
    setSessionCookie(res, result.token, deps.secureCookies === true);
    return json(res, 200, { user: result.user });
  }

  // SSO exchange: a Supabase access token (Google OAuth or hosted email auth)
  // → kernel session cookie. Authentication happened at the IdP; authorization
  // is enforced inside the exchange against the kernel users/invitations
  // tables. 403 `no_console_access` deliberately differs from 401: the caller
  // has PROVEN control of the email (no enumeration oracle is opened), and the
  // UX must say "ask your admin for an invitation" rather than "bad token".
  if (path === "/auth/sso") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.auth.ssoExchange)
      throw new HttpError(404, "not_found", "sso unavailable");
    const body = await readJsonObject(req);
    const accessToken = body.access_token;
    if (typeof accessToken !== "string" || accessToken.length === 0) {
      throw new HttpError(
        400,
        "invalid_body",
        "'access_token' (string) is required",
      );
    }
    const result = await deps.auth.ssoExchange(accessToken);
    if (result.status === "unauthenticated") {
      return json(res, 401, {
        error: "invalid identity token",
        code: "unauthorized",
      });
    }
    if (result.status === "no_account") {
      clearSignupCookie(res);
      return json(res, 403, {
        error:
          "this email has no control-room access; ask an admin for an invitation",
        code: "no_console_access",
      });
    }
    if (result.status === "onboarding_required") {
      if (authThrottleBucket)
        await deps.authThrottle?.reset?.(authThrottleBucket);
      setSignupCookie(res, result.signupToken, deps.secureCookies === true);
      return json(res, 202, {
        code: "onboarding_required",
        next: "/console/login?signup=organization",
      });
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    clearSignupCookie(res);
    setSessionCookie(res, result.token, deps.secureCookies === true);
    return json(res, 200, { user: result.user });
  }

  // The signup cookie is the sole authority. The request may supply only the
  // person's and organization's display names; email, namespace, tenant id,
  // and role are all resolved or fixed inside the service (D9).
  if (path === "/auth/signup") {
    const signupToken = parseCookies(req.headers.cookie)[SIGNUP_COOKIE] ?? "";
    if (method === "GET") {
      if (!deps.auth.signupPending) {
        throw new HttpError(404, "not_found", "signup unavailable");
      }
      const pending =
        signupToken === "" ? null : await deps.auth.signupPending(signupToken);
      res.setHeader("cache-control", "no-store");
      return pending === null
        ? json(res, 401, {
            error: "signup authority is missing or expired",
            code: "unauthorized",
          })
        : json(res, 200, pending);
    }
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    if (!deps.auth.signupComplete) {
      throw new HttpError(404, "not_found", "signup unavailable");
    }
    if (signupToken === "") {
      return json(res, 401, {
        error: "signup authority is missing or expired",
        code: "unauthorized",
      });
    }
    const body = await readJsonObject(req);
    if (
      Object.keys(body).some((key) => key !== "organizationName" && key !== "displayName") ||
      typeof body.organizationName !== "string" ||
      typeof body.displayName !== "string"
    ) {
      throw new HttpError(
        400,
        "invalid_body",
        "only 'organizationName' and 'displayName' (strings) are accepted",
      );
    }
    const completed = await deps.auth.signupComplete(
      signupToken,
      body.organizationName,
      body.displayName,
    );
    if (completed === null) {
      clearSignupCookie(res);
      return json(res, 401, {
        error: "signup authority is missing or expired",
        code: "unauthorized",
      });
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    setSessionCookie(res, completed.token, deps.secureCookies === true);
    clearSignupCookie(res);
    return json(res, 201, {
      organization: completed.organization,
      user: completed.user,
    });
  }

  // GitHub OAuth start (browser redirect flow): mint a single-use state nonce
  // (HttpOnly cookie — the callback must present the SAME nonce, binding the
  // redirect to this browser against CSRF) and 302 to GitHub. `mode=link` is
  // the Profile "Connect GitHub" flow; anything else is a plain login.
  if (path === "/auth/github") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.auth.githubAuthorize) {
      throw new HttpError(404, "not_found", "GitHub sign-in unavailable");
    }
    const mode = url.searchParams.get("mode") === "link" ? "link" : "login";
    const state = randomBytes(16).toString("hex");
    const redirectUri = `${issuerBaseUrl(deps, req)}/auth/github/callback`;
    // OA8: carry the consent bounce through the GitHub round trip. The state
    // value is hex and the mode is a bare word, so base64url (which has no
    // ".") stays unambiguous as a third dot-separated field; a two-field
    // cookie from an in-flight login still parses.
    const consentReturn = safeConsentReturn(url.searchParams.get("next"));
    const carried =
      consentReturn === ""
        ? ""
        : "." + Buffer.from(consentReturn, "utf8").toString("base64url");
    setOAuthStateCookie(
      res,
      `${state}.${mode}${carried}`,
      deps.secureCookies === true,
    );
    res.writeHead(302, {
      location: deps.auth.githubAuthorize(state, redirectUri),
      "content-length": 0,
    });
    res.end();
    return;
  }

  // GitHub OAuth callback. The state cookie is single-use — cleared on every
  // callback, match or not. Login mode mints the session cookie and lands on
  // the console; link mode requires an active human session and lands back on
  // the Profile screen with a one-shot status marker in the hash.
  if (path === "/auth/github/callback") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.auth.githubLogin) {
      throw new HttpError(404, "not_found", "GitHub sign-in unavailable");
    }
    clearOAuthStateCookie(res);
    const code = url.searchParams.get("code") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const cookieRaw =
      parseCookies(req.headers.cookie)[OAUTH_STATE_COOKIE] ?? "";
    const cookieParts = cookieRaw.split(".");
    const cookieState = cookieParts.length >= 2 ? cookieParts[0] : "";
    const linkMode = cookieParts[1] === "link";
    // Re-validated after decoding — the cookie is our own, but it is still
    // input, and the fence is what makes this not an open redirect (OA8).
    const consentReturn =
      cookieParts.length >= 3
        ? safeConsentReturn(
            Buffer.from(cookieParts[2], "base64url").toString("utf8"),
          )
        : "";
    if (
      code === "" ||
      state === "" ||
      cookieState === "" ||
      state !== cookieState
    ) {
      throw new HttpError(
        400,
        "invalid_state",
        "OAuth state mismatch; restart the sign-in",
      );
    }
    const redirectUri = `${issuerBaseUrl(deps, req)}/auth/github/callback`;
    if (linkMode) {
      const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      const linkIdentity =
        sessionToken !== undefined &&
        sessionToken !== "" &&
        deps.auth.resolveSession
          ? await deps.auth.resolveSession(sessionToken)
          : null;
      if (linkIdentity === null || !deps.auth.githubLink) {
        res.writeHead(302, { location: "/console/login", "content-length": 0 });
        res.end();
        return;
      }
      const linked = await deps.auth.githubLink(
        code,
        redirectUri,
        linkIdentity,
      );
      const marker =
        linked.status === "linked"
          ? "linked=github"
          : linked.status === "conflict"
            ? "error=github_conflict"
            : "error=github";
      res.writeHead(302, {
        location: `/console/#settings?${marker}`,
        "content-length": 0,
      });
      res.end();
      return;
    }
    const result = await deps.auth.githubLogin(code, redirectUri);
    if (result.status !== "ok") {
      res.writeHead(302, {
        location: `/console/login?error=github_${result.status}`,
        "content-length": 0,
      });
      res.end();
      return;
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    clearSignupCookie(res);
    setSessionCookie(res, result.token, deps.secureCookies === true);
    res.writeHead(302, {
      location: consentReturn || "/console/",
      "content-length": 0,
    });
    res.end();
    return;
  }

  if (path === "/auth/bootstrap") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.auth.bootstrap)
      throw new HttpError(404, "not_found", "bootstrap unavailable");
    const body = await readJsonObject(req);
    if (
      Object.keys(body).some(
        (key) => !["token", "email", "displayName", "password", "organization"].includes(key),
      ) ||
      typeof body.token !== "string" ||
      typeof body.email !== "string" ||
      typeof body.displayName !== "string" ||
      typeof body.password !== "string" ||
      typeof body.organization !== "string"
    ) {
      throw new HttpError(400, "invalid_body", "invalid bootstrap request");
    }
    // The first human owns an organization from the first second of the
    // install; the server derives its id from this display name (D9).
    const result = await deps.auth.bootstrap({
      token: body.token,
      email: body.email,
      displayName: body.displayName,
      password: body.password,
      organization: body.organization,
    });
    if (result === null) {
      return json(res, 401, {
        error: "bootstrap unavailable",
        code: "unauthorized",
      });
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    clearSignupCookie(res);
    setSessionCookie(res, result.token, deps.secureCookies === true);
    return json(res, 201, { user: result.user });
  }

  if (path === "/auth/invite/accept") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.auth.acceptInvite)
      throw new HttpError(404, "not_found", "activation unavailable");
    const body = await readJsonObject(req);
    if (
      Object.keys(body).some((key) => !["token", "password"].includes(key)) ||
      typeof body.token !== "string" ||
      typeof body.password !== "string"
    ) {
      throw new HttpError(400, "invalid_body", "invalid activation request");
    }
    const user = await deps.auth.acceptInvite(body.token, body.password);
    if (user === null) {
      return json(res, 401, {
        error: "invalid activation",
        code: "unauthorized",
      });
    }
    if (authThrottleBucket)
      await deps.authThrottle?.reset?.(authThrottleBucket);
    return json(res, 200, { user });
  }

  const scimMatch = /^\/scim\/v2\/(Users|Groups)(?:\/([^/]+))?$/.exec(path);
  if (scimMatch) {
    const token = bearerKey(req);
    const tenant =
      deps.scim && token !== null ? deps.scim.resolve(token) : null;
    if (!tenant) {
      return scimJson(res, 401, {
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        status: "401",
        detail: "invalid SCIM credential",
      });
    }
    const resource = scimMatch[1];
    const id = scimMatch[2] ? decodeURIComponent(scimMatch[2]) : undefined;
    try {
      if (method === "GET") {
        if (id) {
          const found =
            resource === "Users"
              ? await tenant.getUser(id)
              : await tenant.getGroup(id);
          return found
            ? scimJson(res, 200, found)
            : scimJson(res, 404, scimError(404, "resource not found"));
        }
        const filter = url.searchParams.get("filter") ?? undefined;
        const resources =
          resource === "Users"
            ? await tenant.listUsers(filter)
            : await tenant.listGroups(filter);
        const startIndex = Math.max(
          1,
          Number(url.searchParams.get("startIndex") ?? 1) || 1,
        );
        const count = Math.max(
          0,
          Math.min(1000, Number(url.searchParams.get("count") ?? 100) || 0),
        );
        return scimJson(res, 200, {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
          totalResults: resources.length,
          startIndex,
          itemsPerPage: Math.min(
            count,
            Math.max(0, resources.length - startIndex + 1),
          ),
          Resources: resources.slice(startIndex - 1, startIndex - 1 + count),
        });
      }
      if (method === "POST" && !id) {
        const body = await readJsonObject(req);
        const created =
          resource === "Users"
            ? await tenant.provisionUser(body)
            : await tenant.provisionGroup(body);
        return scimJson(res, 201, created);
      }
      if (method === "PUT" && id) {
        const body = await readJsonObject(req);
        const replaced =
          resource === "Users"
            ? await tenant.replaceUser(id, body)
            : await tenant.replaceGroup(id, body);
        return replaced
          ? scimJson(res, 200, replaced)
          : scimJson(res, 404, scimError(404, "resource not found"));
      }
      if (method === "PATCH" && id) {
        const body = await readJsonObject(req);
        const patched =
          resource === "Users"
            ? await tenant.patchUser(id, body)
            : await tenant.patchGroup(id, body);
        return patched
          ? scimJson(res, 200, patched)
          : scimJson(res, 404, scimError(404, "resource not found"));
      }
      if (method === "DELETE" && id) {
        const deleted =
          resource === "Users"
            ? await tenant.deleteUser(id)
            : await tenant.deleteGroup(id);
        if (!deleted)
          return scimJson(res, 404, scimError(404, "resource not found"));
        res.statusCode = 204;
        res.end();
        return;
      }
      res.setHeader("allow", id ? "GET, PUT, PATCH, DELETE" : "GET, POST");
      return scimJson(res, 405, scimError(405, "method not allowed"));
    } catch (error) {
      if (error instanceof Error && error.name === "ScimValidationError") {
        return scimJson(
          res,
          400,
          scimError(400, error.message, "invalidValue"),
        );
      }
      throw error;
    }
  }

  // A paired Obsidian vault authenticates with its source-specific HMAC, not
  // a HaloMem API key. Keep this route above the Identity middleware.
  const obsidianMatch = /^\/v1\/ingest\/obsidian\/([A-Za-z0-9_-]{1,128})$/.exec(path);
  if (obsidianMatch) {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.webhooks?.obsidian) {
      throw new HttpError(404, "not_found", "Obsidian ingress unavailable");
    }
    if (deps.webhookThrottle) {
      const address = clientAddress(req, deps.trustedProxyHops);
      const addressHash = createHash("sha256").update(address).digest("hex");
      // The route source id is unauthenticated attacker input. Only the
      // address bucket is safe here; the kernel consumes the durable source
      // bucket after source resolution and raw-body HMAC verification.
      const outcome = await deps.webhookThrottle.consume(`obsidian:ip:${addressHash}`);
      if (!outcome.allowed) {
        res.setHeader(
          "retry-after",
          String(Math.max(1, Math.ceil(outcome.retryAfterSec))),
        );
        return json(res, 429, {
          error: "Obsidian rate limit exceeded",
          code: "rate_limited",
        });
      }
    }
    const timestamp = headerValue(req.headers["x-halomem-timestamp"]);
    const signature = headerValue(req.headers["x-halomem-signature"]);
    if (!timestamp || !signature) {
      await auditDenied(
        deps,
        "write",
        "obsidian:unknown",
        "unknown",
        `401 ${method} /v1/ingest/obsidian/:sourceId`,
        "ingest",
      );
      return json(res, 401, {
        error: "invalid obsidian signature",
        code: "unauthorized",
      });
    }
    const rawBody = await readRawBody(req);
    const result = await deps.webhooks.obsidian(
      obsidianMatch[1],
      rawBody,
      timestamp,
      signature,
    );
    return json(res, 202, { accepted: true, result });
  }

  // Signed source ingress authenticates with the source-specific HMAC, not a
  // HaloMem API key. Keep this route above the ordinary Identity middleware.
  const webhookMatch = /^\/v1\/webhooks\/sources\/([A-Za-z0-9_-]{1,128})$/.exec(
    path,
  );
  if (webhookMatch) {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.webhooks)
      throw new HttpError(404, "not_found", "webhook ingress unavailable");
    if (deps.webhookThrottle) {
      const address = clientAddress(req, deps.trustedProxyHops);
      const addressHash = createHash("sha256").update(address).digest("hex");
      const outcomes = await Promise.all([
        deps.webhookThrottle.consume(`webhook:ip:${addressHash}`),
        deps.webhookThrottle.consume(`webhook:source:${webhookMatch[1]}`),
      ]);
      const blocked = outcomes.find((outcome) => !outcome.allowed);
      if (blocked) {
        res.setHeader(
          "retry-after",
          String(Math.max(1, Math.ceil(blocked.retryAfterSec))),
        );
        // The durable rate bucket is the bounded abuse signal; one audit row
        // per rejected packet would itself be an amplification vector.
        return json(res, 429, {
          error: "webhook rate limit exceeded",
          code: "rate_limited",
        });
      }
    }
    const timestamp = headerValue(req.headers["x-halomem-timestamp"]);
    const signature = headerValue(req.headers["x-halomem-signature"]);
    if (!timestamp || !signature) {
      await auditDenied(
        deps,
        "write",
        "webhook:unknown",
        "unknown",
        `401 ${method} /v1/webhooks/sources/:sourceId`,
        "ingest",
      );
      return json(res, 401, {
        error: "invalid webhook signature",
        code: "unauthorized",
      });
    }
    const rawBody = await readRawBody(req);
    const result = await deps.webhooks.ingest(
      webhookMatch[1],
      rawBody,
      timestamp,
      signature,
    );
    return json(res, 202, { accepted: true, result });
  }

  // M9 #1: GitHub App webhook ingress. Authenticated by the shared
  // X-Hub-Signature-256 HMAC (verified in the kernel handler), never by an API
  // key — kept above the Identity middleware like the signed source ingress.
  if (path === "/v1/ingest/github/webhook") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.webhooks?.github) {
      throw new HttpError(
        404,
        "not_found",
        "GitHub webhook ingress unavailable",
      );
    }
    if (deps.webhookThrottle) {
      const address = clientAddress(req, deps.trustedProxyHops);
      const addressHash = createHash("sha256").update(address).digest("hex");
      const outcome = await deps.webhookThrottle.consume(
        `webhook:github:${addressHash}`,
      );
      if (!outcome.allowed) {
        res.setHeader(
          "retry-after",
          String(Math.max(1, Math.ceil(outcome.retryAfterSec))),
        );
        return json(res, 429, {
          error: "webhook rate limit exceeded",
          code: "rate_limited",
        });
      }
    }
    const rawBody = await readRawBody(req);
    const result = await deps.webhooks.github(
      rawBody,
      headerValue(req.headers["x-hub-signature-256"]),
      headerValue(req.headers["x-github-event"]),
    );
    return json(res, 202, result);
  }

  // C0 channels: public provider webhook ingress. The opaque route key in the
  // path is the credential locator (only its sha256 is stored) and the
  // provider signature/secret is the credential — never an API key. Every
  // deny path is a uniform 404. Kept above the Identity middleware.
  const channelIngressMatch =
    /^\/v1\/channels\/ingress\/([a-z_]{1,32})\/([A-Za-z0-9_-]{16,128})$/.exec(
      path,
    );
  if (channelIngressMatch) {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.channels) throw new HttpError(404, "not_found", "not found");
    const address = clientAddress(req, deps.trustedProxyHops);
    const addressHash = createHash("sha256").update(address).digest("hex");
    if (deps.webhookThrottle) {
      const outcomes = await Promise.all([
        deps.webhookThrottle.consume(`channel:ip:${addressHash}`),
        deps.webhookThrottle.consume(
          `channel:route:${createHash("sha256").update(channelIngressMatch[2]!).digest("hex")}`,
        ),
      ]);
      const blocked = outcomes.find((outcome) => !outcome.allowed);
      if (blocked) {
        res.setHeader(
          "retry-after",
          String(Math.max(1, Math.ceil(blocked.retryAfterSec))),
        );
        return json(res, 429, {
          error: "webhook rate limit exceeded",
          code: "rate_limited",
        });
      }
    }
    const rawBody = await readRawBody(req);
    const headers: Record<string, string | undefined> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      headers[name.toLowerCase()] = Array.isArray(value) ? value[0] : value;
    }
    const result = await deps.channels.ingress(
      channelIngressMatch[1]!,
      channelIngressMatch[2]!,
      {
        method: "POST",
        path,
        headers,
        // Provider JSON is UTF-8; re-encoding the decoded body is byte-exact
        // for signature verification over the raw request.
        rawBody: Buffer.from(rawBody, "utf8"),
        receivedAt: new Date().toISOString(),
        remoteAddressHash: addressHash,
      },
    );
    res.writeHead(
      result.status,
      result.contentType ? { "content-type": result.contentType } : {},
    );
    res.end(result.body ?? "");
    return;
  }

  // C0 channels: provider OAuth redirect target. Public by necessity — the
  // browser arrives from the provider; the single-use hashed state row is the
  // only credential, consumed transactionally in the service. Every outcome
  // is audited and the response never leaks why a state was rejected.
  if (path === "/v1/channels/oauth/callback") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.channels) throw new HttpError(404, "not_found", "not found");
    const result = await deps.channels.oauthCallback({
      state: url.searchParams.get("state"),
      code: url.searchParams.get("code"),
      error: url.searchParams.get("error"),
    });
    res.writeHead(303, { location: result.redirect });
    res.end();
    return;
  }

  // Direct connector OAuth redirect target (Linear first). Public by
  // necessity — the browser arrives from the provider; the single-use hashed
  // state row is the only credential, consumed transactionally in the
  // service. Every outcome is audited and the response never leaks why a
  // state was rejected.
  if (path === "/v1/connectors/oauth/callback") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.admin.sourceOAuthCallback)
      throw new HttpError(404, "not_found", "not found");
    const result = await deps.admin.sourceOAuthCallback({
      state: url.searchParams.get("state"),
      code: url.searchParams.get("code"),
      error: url.searchParams.get("error"),
    });
    res.writeHead(303, { location: result.redirect });
    res.end();
    return;
  }

  // --- M9 #11b (D29): hosted OAuth AS ---------------------------------------
  // Client-credential endpoints authenticate INSIDE the handlers (client_id +
  // client_secret, audited); the metadata documents are public. All are kept
  // above the Identity middleware — no API key or cookie is involved.
  if (
    path === "/.well-known/oauth-authorization-server" ||
    path === "/.well-known/oauth-protected-resource" ||
    path === "/.well-known/oauth-protected-resource/mcp"
  ) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.oauth) throw new HttpError(404, "not_found", "oauth unavailable");
    const issuer = issuerBaseUrl(deps, req);
    return writeOAuthEnvelope(
      res,
      path === "/.well-known/oauth-authorization-server"
        ? deps.oauth.metadata(issuer)
        : deps.oauth.resourceMetadata(
            issuer,
            path.endsWith("/mcp") ? "/mcp" : "",
          ),
    );
  }
  if (
    path === "/oauth/token" ||
    path === "/oauth/introspect" ||
    path === "/oauth/revoke" ||
    path === "/oauth/register"
  ) {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.oauth) throw new HttpError(404, "not_found", "oauth unavailable");
    if (path === "/oauth/register" && deps.oauth.register === undefined) {
      throw new HttpError(404, "not_found", "registration unavailable");
    }
    const request: OAuthEnvelopeRequest = {
      body: await readOAuthBody(req),
      ...(req.headers.authorization !== undefined
        ? { authorization: req.headers.authorization }
        : {}),
      clientAddress: clientAddress(req, deps.trustedProxyHops),
    };
    const envelope =
      path === "/oauth/token"
        ? await deps.oauth.token(request)
        : path === "/oauth/introspect"
          ? await deps.oauth.introspect(request)
          : path === "/oauth/revoke"
            ? await deps.oauth.revoke(request)
            : await deps.oauth.register!(request);
    return writeOAuthEnvelope(res, envelope);
  }

  // CONTRACTS-OAUTH-CONNECT OA8 — the consent surface. Above the Identity
  // middleware: the page must render for SIGNED-OUT users (login bounce), so
  // the cookie session is resolved here, best-effort, never required.
  if (path === "/oauth/authorize" || path === "/oauth/authorize/decision") {
    if (!deps.oauth?.authorizePage || !deps.oauth.authorizeDecision) {
      throw new HttpError(404, "not_found", "oauth authorization unavailable");
    }
    const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    const sessionIdentity =
      sessionToken !== undefined &&
      sessionToken !== "" &&
      deps.auth.resolveSession
        ? await deps.auth.resolveSession(sessionToken)
        : null;
    const issuer = issuerBaseUrl(deps, req);
    if (path === "/oauth/authorize") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      const pageEnvelope = await deps.oauth.authorizePage(
        Object.fromEntries(url.searchParams),
        url.search.startsWith("?") ? url.search.slice(1) : url.search,
        sessionIdentity,
        issuer,
      );
      return writePageEnvelope(res, pageEnvelope);
    }
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    const decisionEnvelope = await deps.oauth.authorizeDecision(
      await readOAuthBody(req),
      sessionIdentity,
      issuer,
    );
    return writePageEnvelope(res, decisionEnvelope);
  }

  // --- M9 #11a (E28–E30): unauthenticated public discovery (org tier) -------
  // Placed BELOW every real route family and ABOVE the identity middleware:
  // real routes always win (the matcher's reserved-slug list is defense in
  // depth, not the primary fence), and no credential is involved. The module
  // audits every outcome (D4) and returns a byte-identical 404 for unknown,
  // suspended, and zero-public-content orgs (anti-fingerprinting, E30).
  if (deps.publicDiscovery && method === "GET") {
    const pub = matchPublicDiscoveryPath(path);
    if (pub !== null) {
      const r = await deps.publicDiscovery(pub.orgSlug, pub.format);
      res.writeHead(r.status, {
        "content-type": r.contentType,
        "cache-control": "public, max-age=60",
      });
      res.end(r.body);
      return;
    }
  }

  // --- auth middleware (everything below requires an Identity) --------------
  // Bearer key takes precedence (agent/service path, unchanged). If no bearer
  // key is present, fall back to the human session cookie (M5). Presenting a
  // bearer key means the bearer path is authoritative — a bad key is a 401
  // even if a cookie is also present (no silent downgrade).
  const key = bearerKey(req);
  let identity: Identity | null;
  if (key !== null) {
    identity = key.startsWith("hmc_")
      ? path === "/mcp" && deps.auth.resolveCopilotCapability
        ? await deps.auth.resolveCopilotCapability(key)
        : null
      : key.startsWith("hmt_")
        ? // D29: OAuth bearer — resolved server-side exactly like an API key.
          deps.auth.resolveOauth
          ? await deps.auth.resolveOauth(key)
          : null
        : key.startsWith("hm_")
          ? await deps.auth.resolve(key)
          : deps.auth.resolveOidc && key.split(".").length === 3
            ? await deps.auth.resolveOidc(key)
            : null;
  } else {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    identity =
      token !== undefined && token !== "" && deps.auth.resolveSession
        ? await deps.auth.resolveSession(token)
        : null;
    // The server slides `sessions.expires_at` on every resolve (idle window,
    // src/console/auth.ts). Re-send the cookie so the BROWSER's copy of that
    // window slides with it — otherwise the cookie would expire on a fixed
    // schedule from sign-in and a still-valid session would stop being
    // presented. Same opaque token, same attributes: only Max-Age moves.
    //
    // Skipped for /auth/logout, which clears this cookie further down; two
    // Set-Cookie headers for one name would leave the outcome to header order.
    if (
      identity !== null &&
      token !== undefined &&
      token !== "" &&
      path !== "/auth/logout"
    ) {
      setSessionCookie(res, token, deps.secureCookies === true);
    }
  }
  if (identity === null) {
    await auditDenied(
      deps,
      routeOp(path, method),
      "unknown",
      "unknown",
      `401 ${method} ${path}`,
    );
    // OA7 (RFC 9728 §5.1): a 401 on the MCP surface tells OAuth-only clients
    // (ChatGPT, Claude connectors) where the protected-resource metadata
    // lives, which is how they discover the authorize/register endpoints.
    if (path === "/mcp" && deps.oauth) {
      res.setHeader(
        "www-authenticate",
        mcpChallengeHeader(issuerBaseUrl(deps, req)),
      );
    }
    // A browser NAVIGATION here is a signed-out human, not a client with a bad
    // key: they get the Halo "you're signed out" page with a way back in. Every
    // API caller keeps the JSON envelope (and the WWW-Authenticate header).
    return errorResponse(
      req,
      res,
      401,
      "unauthorized",
      "invalid or missing credential",
    );
  }

  // --- M10 (D43): transport-wide read-only fence for preview credentials ---
  // Whenever the dedicated header is presented on a state-changing method,
  // the mutation is rejected 403 — a resolving credential is additionally
  // audited (denied) under the ROOT actor with its preview session id. An
  // invalid token NEVER lets a mutation pass through as "no preview".
  const previewToken = headerValue(req.headers[PREVIEW_TOKEN_HEADER]);
  if (
    previewToken !== undefined &&
    previewToken.trim() !== "" &&
    !enforcePreviewReadOnly(method)
  ) {
    const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (deps.access && sessionToken !== undefined && sessionToken !== "") {
      const rootSession = await deps.access.resolveConsoleSession(sessionToken);
      if (rootSession !== null) {
        const resolved = await deps.access.resolvePreview(
          rootSession,
          previewToken,
        );
        if (resolved !== null) {
          // Audits + throws PreviewReadOnlyError (name AuthzError → 403).
          await deps.access.rejectMutation(
            rootSession,
            resolved.sessionId,
            method,
            path,
          );
        }
        // resolvePreview already audited the invalid-credential denial.
      }
    }
    return json(res, 403, { error: "preview is read-only", code: "forbidden" });
  }

  // --- M10: role-scoped memory graph + root View-as (cookie sessions) ------
  if (
    path === "/v1/memory-graph" ||
    path === "/v1/root/view-as/targets" ||
    path === "/v1/root/view-as/sessions" ||
    path.startsWith("/v1/root/view-as/sessions/")
  ) {
    if (!deps.access)
      throw new HttpError(404, "not_found", "access graph unavailable");
    // These are HUMAN console surfaces: only a cookie session carries the
    // userId the projection is keyed on. A bearer credential (agent/service)
    // is denied — machine reads go through the syscall surface.
    const sessionToken =
      key === null
        ? parseCookies(req.headers.cookie)[SESSION_COOKIE]
        : undefined;
    const session =
      sessionToken !== undefined && sessionToken !== ""
        ? await deps.access.resolveConsoleSession(sessionToken)
        : null;
    if (session === null) {
      await auditDenied(
        deps,
        routeOp(path, method),
        identity.actor,
        identity.namespace,
        `403 ${method} ${path} human session required`,
      );
      return json(res, 403, {
        error: "human session required",
        code: "forbidden",
      });
    }

    if (path === "/v1/memory-graph") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      // D9: `scope`/`cursor`/`limit` are the ONLY client inputs — opaque and
      // re-resolved server-side. Anything else (namespace, role, tenant,
      // grant-root injection attempts) is rejected AND audited.
      for (const param of url.searchParams.keys()) {
        if (param !== "scope" && param !== "cursor" && param !== "limit") {
          await auditDenied(
            deps,
            "read",
            identity.actor,
            identity.namespace,
            `400 ${method} ${path} caller-owned query parameter rejected`,
          );
          throw new HttpError(
            400,
            "invalid_query",
            "only 'scope', 'cursor', and 'limit' are accepted",
          );
        }
      }
      const scope = url.searchParams.get("scope");
      const cursor = url.searchParams.get("cursor");
      const rawLimit = url.searchParams.get("limit");
      const limit = rawLimit === null ? undefined : Number(rawLimit);
      return json(
        res,
        200,
        await deps.access.memoryGraph(
          session,
          {
            ...(scope !== null && scope !== "" ? { scopeId: scope } : {}),
            ...(cursor !== null && cursor !== "" ? { cursor } : {}),
            ...(limit !== undefined && Number.isFinite(limit) ? { limit } : {}),
          },
          previewToken !== undefined && previewToken.trim() !== ""
            ? previewToken
            : null,
        ),
      );
    }

    if (path === "/v1/root/view-as/targets") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      return json(res, 200, await deps.access.viewAsTargets(session));
    }

    if (path === "/v1/root/view-as/sessions") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      const body = await readJsonObject(req);
      // D9: the body may carry ONLY the documented opaque fields. A caller
      // asserting namespace/tenant/actor/grant roots is rejected + audited.
      for (const bodyKey of Object.keys(body)) {
        if (
          bodyKey !== "subjectUserId" &&
          bodyKey !== "role" &&
          bodyKey !== "functionalAreaIds" &&
          bodyKey !== "reason"
        ) {
          await auditDenied(
            deps,
            "write",
            identity.actor,
            identity.namespace,
            `400 ${method} ${path} caller-owned field rejected`,
          );
          throw new HttpError(
            400,
            "invalid_body",
            "only 'subjectUserId', 'role', 'functionalAreaIds', and 'reason' are accepted",
          );
        }
      }
      return json(res, 201, await deps.access.viewAsStart(session, body));
    }

    const previewMatch = /^\/v1\/root\/view-as\/sessions\/([^/]+)$/.exec(path);
    if (previewMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      return json(
        res,
        200,
        await deps.access.viewAsEnd(
          session,
          decodeURIComponent(previewMatch[1]!),
        ),
      );
    }
    throw new HttpError(404, "not_found", "unknown view-as route");
  }

  // M5: authenticated /auth routes.
  if (path === "/auth/logout") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    // Invalidate the session server-side if we authenticated by cookie.
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (token !== undefined && token !== "" && deps.auth.logout) {
      await deps.auth.logout(token);
    }
    clearSessionCookie(res);
    return json(res, 200, { ok: true });
  }
  if (path === "/auth/me") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    // M10 (D41/E1): human roles cross the public boundary as PRODUCT roles
    // (owner → root, auditor → member + audit:read entitlement). The machine
    // `agent` is a principal type, not a human role — it passes unchanged.
    // Identity itself stays INTERNAL; only this serialization translates.
    const roleView =
      identity.role === "agent" ? null : toProductRole(identity.role);
    // The mandatory-setup gate (CONTRACTS-SETUP-GATE.md): every human session
    // carries the server-persisted onboarding flag so the console shell can
    // lock itself to the setup surface. Machine principals have no console.
    // Brownout: a failed flag read omits the field (treated as not gated) —
    // a hiccup here must never block login.
    let onboarding: unknown;
    if (identity.role !== "agent" && deps.admin.onboardingState) {
      try {
        onboarding = await deps.admin.onboardingState(identity);
      } catch {
        onboarding = undefined;
      }
    }
    let displayName: string | null | undefined;
    let avatar: string | null | undefined;
    if (identity.role !== "agent" && deps.auth.profile) {
      try {
        const profile = (await deps.auth.profile(identity)) as {
          displayName?: unknown;
          avatar?: unknown;
        } | null;
        const rawDisplayName = profile?.displayName;
        displayName =
          typeof rawDisplayName === "string" && rawDisplayName.trim() !== ""
            ? rawDisplayName.trim()
            : null;
        const rawAvatar = profile?.avatar;
        avatar =
          profile && Object.prototype.hasOwnProperty.call(profile, "avatar")
            ? typeof rawAvatar === "string" && rawAvatar !== ""
              ? rawAvatar
              : null
            : undefined;
      } catch {
        displayName = undefined;
        avatar = undefined;
      }
    }
    return json(res, 200, {
      keyId: identity.keyId,
      namespace: identity.namespace,
      actor: identity.actor,
      ...(displayName !== undefined ? { displayName } : {}),
      ...(avatar !== undefined ? { avatar } : {}),
      role: roleView === null ? identity.role : roleView.role,
      ...(roleView !== null && roleView.entitlements.length > 0
        ? { entitlements: roleView.entitlements }
        : {}),
      ...(deps.haloAgents ? { capabilities: { haloAgents: true } } : {}),
      ...(onboarding !== undefined ? { onboarding } : {}),
    });
  }
  // Member operating profile (D59): there is deliberately no target user in
  // this route. Reject every query parameter instead of silently accepting a
  // misleading selector; the subject comes from the resolved session only.
  if (path === "/auth/profile") {
    // S18 Settings → Profile: the same no-subject rule applies to the write.
    // A PATCH changes only the SESSION user's own display name and/or avatar.
    if (method === "PATCH") {
      if (url.searchParams.size > 0) {
        throw new HttpError(
          400,
          "bad_request",
          "profile does not accept query parameters",
        );
      }
      if (!deps.auth.updateProfile) {
        throw new HttpError(404, "not_found", "profile updates unavailable");
      }
      const body = await readJsonObject(req);
      if (
        Object.keys(body).some(
          (key) => key !== "displayName" && key !== "avatar",
        )
      ) {
        throw new HttpError(
          400,
          "invalid_body",
          "only 'displayName' and 'avatar' are accepted",
        );
      }
      return json(res, 200, await deps.auth.updateProfile(identity, body));
    }
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET or PATCH");
    if (url.searchParams.size > 0) {
      throw new HttpError(
        400,
        "bad_request",
        "profile does not accept query parameters",
      );
    }
    if (!deps.auth.profile) {
      throw new HttpError(404, "not_found", "profile unavailable");
    }
    const profile = await deps.auth.profile(identity);
    if (profile === null)
      throw new HttpError(404, "not_found", "profile unavailable");
    return json(res, 200, profile);
  }
  // Profile screen (s18): the session user's linked external identities.
  // Self-service — any authenticated human. The adapter resolves the user row
  // from the session actor, so an API-key caller sees an empty list / a 404.
  if (path === "/auth/identities") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.auth.listIdentities) {
      throw new HttpError(404, "not_found", "identities unavailable");
    }
    return json(res, 200, await deps.auth.listIdentities(identity));
  }
  // Connect Google to the CURRENT session (Profile screen). Unlike the
  // /auth/sso exchange this never mints a session — it only records the link,
  // so an authenticated caller is required and the token is used for nothing
  // but proving the Google account.
  if (path === "/auth/identities/google" && method === "POST") {
    if (!deps.auth.ssoLinkGoogle) {
      throw new HttpError(404, "not_found", "Google sign-in unavailable");
    }
    const body = await readJsonObject(req);
    const accessToken = body.access_token;
    if (typeof accessToken !== "string" || accessToken.length === 0) {
      throw new HttpError(
        400,
        "invalid_body",
        "'access_token' (string) is required",
      );
    }
    const result = await deps.auth.ssoLinkGoogle(accessToken, identity);
    if (result.status === "conflict") {
      return json(res, 409, {
        error: "that Google account is already connected to a different user",
        code: "identity_conflict",
      });
    }
    if (result.status !== "linked") {
      return json(res, 401, {
        error: "invalid identity token",
        code: "unauthorized",
      });
    }
    return json(res, 200, {
      ok: true,
      provider: "google",
      login: result.login,
    });
  }
  if (
    path === "/auth/identities/github" ||
    path === "/auth/identities/google"
  ) {
    if (method !== "DELETE") {
      throw new HttpError(405, "method_not_allowed", "use DELETE");
    }
    if (!deps.auth.unlinkIdentity) {
      throw new HttpError(404, "not_found", "identities unavailable");
    }
    const provider = path === "/auth/identities/github" ? "github" : "google";
    const label = provider === "github" ? "GitHub" : "Google";
    const removed = await deps.auth.unlinkIdentity(identity, provider);
    if (removed === "last_method") {
      return json(res, 409, {
        error:
          "this is your only way to sign in; set a password or connect another account first",
        code: "last_sign_in_method",
      });
    }
    if (!removed) {
      throw new HttpError(404, "not_found", `no linked ${label} identity`);
    }
    return json(res, 200, { ok: true });
  }
  if (path === "/auth/halo-agents") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.haloAgents)
      throw new HttpError(404, "not_found", "Halo Agents handoff unavailable");

    // Only a current human cookie session may mint this browser handoff. An
    // API key or OIDC bearer is valid for syscalls, but never for interactive
    // cross-product sign-in.
    const sessionToken = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (
      key !== null ||
      !sessionToken ||
      !deps.auth.resolveSession ||
      identity.role === "agent"
    ) {
      await auditHaloAgentsHandoff(
        deps,
        identity,
        "denied",
        `403 ${method} ${path} human session required`,
      );
      return json(res, 403, {
        error: "human session required",
        code: "forbidden",
      });
    }

    if (headerValue(req.headers.origin) !== deps.haloAgents.issuer) {
      await auditHaloAgentsHandoff(
        deps,
        identity,
        "denied",
        `403 ${method} ${path} same-origin initiation required`,
      );
      return json(res, 403, {
        error: "same-origin initiation required",
        code: "forbidden",
      });
    }

    let body: Record<string, unknown>;
    try {
      body = await readJsonObject(req);
    } catch (error) {
      await auditHaloAgentsHandoff(
        deps,
        identity,
        "denied",
        `400 ${method} ${path} invalid request body`,
      );
      throw error;
    }
    if (Object.keys(body).length !== 0) {
      await auditHaloAgentsHandoff(
        deps,
        identity,
        "denied",
        `400 ${method} ${path} caller-owned handoff input rejected`,
      );
      throw new HttpError(
        400,
        "invalid_body",
        "handoff request body must be empty",
      );
    }

    try {
      const assertion = deps.haloAgents.createAssertion(identity);
      await auditHaloAgentsHandoff(
        deps,
        identity,
        "ok",
        `200 ${method} ${path}`,
      );
      res.setHeader("cache-control", "no-store");
      res.setHeader("referrer-policy", "no-referrer");
      return json(res, 200, {
        destination: deps.haloAgents.destination,
        assertion,
      });
    } catch (error) {
      try {
        await auditHaloAgentsHandoff(
          deps,
          identity,
          "error",
          `503 ${method} ${path}`,
        );
      } catch {
        // Issuance remains blocked when the mandatory audit sink is unavailable.
      }
      throw new HttpError(
        503,
        "handoff_unavailable",
        error instanceof Error
          ? error.message
          : "Halo Agents handoff unavailable",
      );
    }
  }

  // --- MCP Streamable HTTP -------------------------------------------------
  if (path === "/mcp") {
    // Only the short-lived Copilot capability may bind Halo's server-minted
    // turn context to sidecar MCP tools. Ordinary API/OAuth callers cannot
    // turn headers into the sensitive-Assistant suppression marker.
    const boundAssistant = (
      identity as Identity & {
        assistantObservability?: {
          turnId: string;
          traceId: string;
          invocationId: string;
        };
      }
    ).assistantObservability;
    if (
      key?.startsWith("hmc_") &&
      boundAssistant &&
      (context.halomemTrace !== boundAssistant.traceId ||
        context.halomemTurn !== boundAssistant.turnId)
    ) {
      throw new HttpError(
        401,
        "invalid_assistant_trace",
        "Assistant trace binding mismatch",
      );
    }
    const assistantContext =
      key?.startsWith("hmc_") &&
      boundAssistant &&
      context.halomemTrace === boundAssistant.traceId &&
      context.halomemTurn === boundAssistant.turnId
        ? {
            traceId: boundAssistant.traceId,
            tool: "halo-assistant-sidecar",
            sensitiveTurnId: boundAssistant.turnId,
          }
        : undefined;
    return handleMcp(deps, identity, req, res, assistantContext);
  }

  // --- metrics (any role) --------------------------------------------------
  if (path === "/metrics") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    return json(res, 200, deps.metrics.snapshot());
  }

  // --- async write ticket status --------------------------------------------
  // GET /v1/mem/write/:ticket — redeem a ticket returned by mem_write
  // {async:true}. Without this route failed queue jobs would be invisible to
  // remote callers (kernel.writeStatus reachable from no transport).
  const ticketMatch = /^\/v1\/mem\/write\/([^/]+)$/.exec(path);
  if (ticketMatch) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.syscalls.writeStatus) {
      throw new HttpError(404, "not_found", "write status unavailable");
    }
    const status = await deps.syscalls.writeStatus(
      decodeURIComponent(ticketMatch[1]),
      identity,
    );
    if (status === undefined) {
      throw new HttpError(404, "not_found", "unknown or expired ticket");
    }
    return json(res, 200, status);
  }

  // --- M8 governed agent connectivity -------------------------------------
  if (path === "/v1/agent-sessions/complete") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.syscalls.completeAgentSession) {
      throw new HttpError(
        404,
        "not_found",
        "agent session capture unavailable",
      );
    }
    const body = await readJsonObject(req);
    if (
      Object.hasOwn(body, "namespace") ||
      Object.hasOwn(body, "actor") ||
      Object.hasOwn(body, "keyId") ||
      Object.hasOwn(body, "agentId")
    ) {
      await auditDenied(
        deps,
        "session_capture",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "agent identity comes from your key",
      );
    }
    return json(
      res,
      201,
      await deps.syscalls.completeAgentSession(body, identity),
    );
  }

  if (path === "/v1/agent/source-read") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.syscalls.sourceRead) {
      throw new HttpError(404, "not_found", "governed source read unavailable");
    }
    const body = await readJsonObject(req);
    const allowedFields = new Set([
      "grantId",
      "connectorId",
      "sourceRef",
      "purpose",
      "query",
      "requestedFields",
      "requestedRows",
      "requestedBytes",
      "expectedPolicyVersion",
      "accessRequestId",
    ]);
    if (Object.keys(body).some((key) => !allowedFields.has(key))) {
      await auditDenied(
        deps,
        "read",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned authority rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "gateway_authority_from_server",
        "gateway authority is server-resolved",
      );
    }
    return json(res, 200, await deps.syscalls.sourceRead(body, identity));
  }

  if (path === "/v1/agent/access-requests") {
    if (method === "GET") {
      if (!deps.syscalls.listAgentAccessRequests) {
        throw new HttpError(404, "not_found", "access requests unavailable");
      }
      return json(
        res,
        200,
        await deps.syscalls.listAgentAccessRequests(identity),
      );
    }
    if (method === "POST") {
      if (!deps.syscalls.requestAgentAccess) {
        throw new HttpError(404, "not_found", "access requests unavailable");
      }
      const body = await readJsonObject(req);
      const allowedFields = new Set([
        "grantId",
        "connectorId",
        "sourceRef",
        "purpose",
        "requestedFields",
        "requestedRows",
        "requestedBytes",
        "justification",
        "requestedDurationSeconds",
        "maxUses",
      ]);
      if (Object.keys(body).some((key) => !allowedFields.has(key))) {
        await auditDenied(
          deps,
          "write",
          identity.actor,
          identity.namespace,
          `400 ${method} ${path} caller-owned authority rejected`,
          identity.role === "agent" ? identity.keyId : AGENT_ID,
        );
        throw new HttpError(
          400,
          "gateway_authority_from_server",
          "gateway authority is server-resolved",
        );
      }
      return json(
        res,
        201,
        await deps.syscalls.requestAgentAccess(body, identity),
      );
    }
    throw new HttpError(405, "method_not_allowed", "use GET or POST");
  }

  if (path === "/v1/agent/describe-access") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.syscalls.describeAgentAccess) {
      throw new HttpError(404, "not_found", "describe access unavailable");
    }
    return json(res, 200, await deps.syscalls.describeAgentAccess(identity));
  }

  // --- M9 #9 (E20/E22): audited skill invocation gate ----------------------
  if (path === "/v1/skills/invoke") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.syscalls.invokeSkill) {
      throw new HttpError(404, "not_found", "skill library unavailable");
    }
    const body = await readJsonObject(req);
    if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
      await auditDenied(
        deps,
        "skill_invoke",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "namespace comes from your key",
      );
    }
    return json(res, 200, await deps.syscalls.invokeSkill(body, identity));
  }

  // --- S16: member-visible skill library (list / submit / download) --------
  // Exact-matched AFTER /v1/skills/invoke so neither swallows the other; the
  // download regex requires the trailing /download segment for the same reason.
  if (path === "/v1/skills") {
    if (method === "GET") {
      if (!deps.syscalls.listSkills) {
        throw new HttpError(404, "not_found", "skill library unavailable");
      }
      return json(res, 200, await deps.syscalls.listSkills(identity));
    }
    if (method === "POST") {
      if (!deps.syscalls.registerSkill) {
        throw new HttpError(404, "not_found", "skill library unavailable");
      }
      const body = await readJsonObject(req);
      if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
        await auditDenied(
          deps,
          "write",
          identity.actor,
          identity.namespace,
          `400 ${method} ${path} caller-owned identity rejected`,
          identity.role === "agent" ? identity.keyId : AGENT_ID,
        );
        throw new HttpError(
          400,
          "identity_from_key",
          "namespace comes from your key",
        );
      }
      return json(res, 201, await deps.syscalls.registerSkill(body, identity));
    }
    throw new HttpError(405, "method_not_allowed", "use GET or POST");
  }

  const skillDownload = /^\/v1\/skills\/([^/]+)\/download$/.exec(path);
  if (skillDownload) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.syscalls.downloadSkill) {
      throw new HttpError(404, "not_found", "skill library unavailable");
    }
    const result = (await deps.syscalls.downloadSkill(
      decodeURIComponent(skillDownload[1]!),
      identity,
    )) as { filename?: string; content?: string };
    res.writeHead(200, {
      "content-type": "text/markdown; charset=utf-8",
      "content-disposition": `attachment; filename="${(result.filename ?? "skill.md").replaceAll('"', "")}"`,
    });
    res.end(result.content ?? "");
    return;
  }

  // --- M9 #6: manifest read syscall (GET — the one non-POST /v1/mem route) --
  if (path === "/v1/mem/manifest") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.syscalls.memManifest) {
      throw new HttpError(404, "not_found", "manifest unavailable");
    }
    let parsed: ParsedManifestRequest;
    try {
      parsed = parseManifestArgs(Object.fromEntries(url.searchParams));
    } catch (err) {
      if (err instanceof ManifestArgsError) {
        throw new HttpError(400, "bad_request", err.message);
      }
      throw err;
    }
    const result = (await deps.syscalls.memManifest(
      parsed.args as unknown as Record<string, unknown>,
      identity,
    )) as { markdown: string };
    if (parsed.format === "text") {
      res.writeHead(200, { "content-type": "text/markdown; charset=utf-8" });
      res.end(result.markdown);
      return;
    }
    return json(res, 200, result);
  }

  // --- M9 #7: governed markdown export (D28) --------------------------------
  if (path === "/v1/mem/export") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.syscalls.memExport) {
      throw new HttpError(404, "not_found", "export unavailable");
    }
    const body = await readJsonObject(req);
    if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
      await auditDenied(
        deps,
        "export",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "namespace comes from your key",
      );
    }
    const result = (await deps.syscalls.memExport(body, identity)) as {
      markdown?: string;
      filename?: string;
    };
    const accept = headerValue(req.headers.accept) ?? "";
    if (
      accept.includes("text/markdown") &&
      typeof result.markdown === "string"
    ) {
      res.writeHead(200, {
        "content-type": "text/markdown; charset=utf-8",
        "content-disposition": `attachment; filename="${(result.filename ?? "memory-export.md").replaceAll('"', "")}"`,
      });
      res.end(result.markdown);
      return;
    }
    return json(res, 200, result);
  }

  // --- M9 #18 (D31): per-turn answer-outcome capture ------------------------
  if (path === "/v1/mem/answer-outcome") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.syscalls.recordAnswerOutcome) {
      throw new HttpError(404, "not_found", "answer outcomes unavailable");
    }
    const body = await readJsonObject(req);
    // parseAnswerOutcomeBody (kernel side) additionally hard-rejects
    // namespace/actor/resolvedBy — this transport check mirrors the sibling
    // mem routes so the denial audits at the boundary too (D9/D4).
    if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
      await auditDenied(
        deps,
        "answer_outcome",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "namespace comes from your key",
      );
    }
    return json(
      res,
      201,
      await deps.syscalls.recordAnswerOutcome(body, identity),
    );
  }

  // --- memory syscalls -----------------------------------------------------
  if (path.startsWith("/v1/mem/")) {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    const op = path.slice("/v1/mem/".length);
    if (!isMemRoute(op))
      throw new HttpError(404, "not_found", `unknown syscall '${op}'`);
    const body = await readJsonObject(req);
    if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
      await auditDenied(
        deps,
        routeOp(path, method),
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "namespace comes from your key",
      );
    }
    // M6 additive surface: 'live-result' is optional (HttpSyscallsX) — a
    // kernel without the federation lane leaves the handler undefined → 404.
    const handler = (deps.syscalls as unknown as Record<string, unknown>)[
      MEM_ROUTES[op]
    ] as
      | ((
          payload: Record<string, unknown>,
          identity: Identity,
          ctx?: SyscallContext,
        ) => Promise<unknown>)
      | undefined;
    if (!handler)
      throw new HttpError(404, "not_found", `syscall '${op}' unavailable`);
    // M6 (D13): merge header-borne passthrough source tokens into the fault
    // payload only. RADIOACTIVE — the merged payload goes to the syscall and
    // nowhere else (never logged, audited, or echoed).
    const payload =
      op === "fault"
        ? withSourceTokens(body, req.headers as Record<string, unknown>)
        : body;
    // D37: the explicit X-Halomem-Trace hint wins over the W3C traceparent
    // id; either is only a grouping hint — identity stays key-resolved (D9).
    const result = await handler(payload, identity, {
      traceId: context.halomemTrace ?? context.traceId,
      tool: `http:${op}`,
    });
    return json(res, 200, result);
  }

  // --- Halo Copilot model runtime -----------------------------------------
  if (path === "/v1/copilot/profiles") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    return json(res, 200, await deps.copilot.listProfiles(identity));
  }

  // M9 #13 (E47): derived chips for S10 — rides the copilot family (any
  // resolved identity; per-namespace derivation happens kernel-side).
  if (path === "/v1/copilot/suggested-questions") {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.suggestedQuestions) {
      throw new HttpError(404, "not_found", "suggested questions unavailable");
    }
    return json(res, 200, await deps.suggestedQuestions(identity));
  }

  if (path === "/v1/copilot/routines") {
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    if (method === "GET") {
      if (!deps.copilot.listRoutines)
        throw new HttpError(404, "not_found", "Copilot routines unavailable");
      return json(res, 200, await deps.copilot.listRoutines(identity));
    }
    if (method === "POST") {
      if (!deps.copilot.createRoutine)
        throw new HttpError(404, "not_found", "Copilot routines unavailable");
      const body = await readJsonObject(req);
      if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
        throw new HttpError(
          400,
          "identity_from_key",
          "identity comes from your credential",
        );
      }
      return json(res, 201, await deps.copilot.createRoutine(body, identity));
    }
    throw new HttpError(405, "method_not_allowed", "use GET or POST");
  }

  const copilotRoutineMatch =
    /^\/v1\/copilot\/routines\/([0-9A-HJKMNP-TV-Z]{26})$/.exec(path);
  if (copilotRoutineMatch) {
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    const id = copilotRoutineMatch[1]!;
    if (method === "PATCH") {
      if (!deps.copilot.updateRoutine)
        throw new HttpError(404, "not_found", "Copilot routines unavailable");
      const body = await readJsonObject(req);
      if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
        throw new HttpError(
          400,
          "identity_from_key",
          "identity comes from your credential",
        );
      }
      const routine = await deps.copilot.updateRoutine(id, body, identity);
      if (routine === null)
        throw new HttpError(404, "not_found", "routine not found");
      return json(res, 200, routine);
    }
    if (method === "DELETE") {
      if (!deps.copilot.deleteRoutine)
        throw new HttpError(404, "not_found", "Copilot routines unavailable");
      return json(res, 200, {
        deleted: await deps.copilot.deleteRoutine(id, identity),
      });
    }
    throw new HttpError(405, "method_not_allowed", "use PATCH or DELETE");
  }

  if (path === "/v1/copilot/conversations") {
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    if (method === "GET") {
      if (!deps.copilot.listConversations)
        throw new HttpError(404, "not_found", "Copilot history unavailable");
      const limit = boundedInteger(url.searchParams.get("limit"), 100, 1, 100);
      const offset = boundedInteger(
        url.searchParams.get("offset"),
        0,
        0,
        1_000_000,
      );
      return json(
        res,
        200,
        await deps.copilot.listConversations(identity, limit, offset),
      );
    }
    if (method === "POST") {
      if (!deps.copilot.createConversation)
        throw new HttpError(404, "not_found", "Copilot history unavailable");
      const body = await readJsonObject(req);
      if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
        throw new HttpError(
          400,
          "identity_from_key",
          "identity comes from your credential",
        );
      }
      return json(
        res,
        201,
        await deps.copilot.createConversation(body, identity),
      );
    }
    if (method === "DELETE") {
      if (!deps.copilot.clearConversations)
        throw new HttpError(404, "not_found", "Copilot history unavailable");
      return json(res, 200, await deps.copilot.clearConversations(identity));
    }
    throw new HttpError(405, "method_not_allowed", "use GET, POST, or DELETE");
  }

  const copilotConversationMatch =
    /^\/v1\/copilot\/conversations\/([0-9A-HJKMNP-TV-Z]{26})$/.exec(path);
  if (copilotConversationMatch) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    if (!deps.copilot.getConversation)
      throw new HttpError(404, "not_found", "Copilot history unavailable");
    const conversation = await deps.copilot.getConversation(
      copilotConversationMatch[1]!,
      identity,
    );
    if (conversation === null)
      throw new HttpError(404, "not_found", "conversation not found");
    return json(res, 200, conversation);
  }

  if (path === "/v1/copilot/complete") {
    if (method !== "POST")
      throw new HttpError(405, "method_not_allowed", "use POST");
    if (!deps.copilot)
      throw new HttpError(404, "not_found", "Copilot runtime unavailable");
    const body = await readJsonObject(req);
    if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
      await auditDenied(
        deps,
        "complete",
        identity.actor,
        identity.namespace,
        `400 ${method} ${path} caller-owned identity rejected`,
      );
      throw new HttpError(
        400,
        "identity_from_key",
        "namespace comes from your credential",
      );
    }
    const conversationId = body.conversationId;
    const turnId = typeof body.turnId === "string" ? body.turnId.trim() : "";
    if (
      typeof conversationId !== "string" ||
      !ASSISTANT_ID_PATTERN.test(conversationId) ||
      turnId.length === 0 ||
      turnId.length > 128
    ) {
      throw new HttpError(
        400,
        "bad_request",
        "conversationId and turnId are required for an Assistant turn",
      );
    }
    return json(res, 200, await deps.copilot.complete(body, identity));
  }

  // --- C0 channels: admin control plane ------------------------------------
  // Reads allow owner/admin/auditor; mutations require owner/admin at the
  // transport (defense in depth — the lifecycle service re-asserts authority
  // server-side and audits every outcome).
  if (path.startsWith("/v1/channels/")) {
    const requireChannels = (): HttpChannels => {
      if (!deps.channels)
        throw new HttpError(404, "not_found", "channels unavailable");
      return deps.channels;
    };
    const canRead =
      identity.role === "owner" ||
      identity.role === "admin" ||
      identity.role === "auditor";
    const canManage = identity.role === "owner" || identity.role === "admin";
    const denyRole = async (): Promise<never> => {
      await auditDenied(
        deps,
        routeOp(path, method),
        identity.actor,
        identity.namespace,
        `403 ${method} ${path}`,
      );
      throw new HttpError(403, "forbidden", "owner or admin role required");
    };
    if (path === "/v1/channels/catalog") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!canRead) return denyRole();
      return json(res, 200, await requireChannels().catalog(identity));
    }
    if (path === "/v1/channels/google-chat/managed") {
      if (method !== "POST") throw new HttpError(405, "method_not_allowed", "use POST");
      if (!canManage) return denyRole();
      return json(res, 201, await requireChannels().managedGoogleChatStart(identity));
    }
    const managedGoogleChatMatch =
      /^\/v1\/channels\/google-chat\/managed\/([0-9A-HJKMNP-TV-Z]{26})$/.exec(path);
    if (managedGoogleChatMatch) {
      if (method !== "GET") throw new HttpError(405, "method_not_allowed", "use GET");
      if (!canManage) return denyRole();
      const setup = await requireChannels().managedGoogleChatStatus(
        identity,
        managedGoogleChatMatch[1]!,
      );
      if (setup === null) throw new HttpError(404, "not_found", "unknown Google Chat setup");
      return json(res, 200, setup);
    }
    if (path === "/v1/channels/connections") {
      const channels = requireChannels();
      if (method === "GET") {
        if (!canRead) return denyRole();
        return json(res, 200, await channels.listConnections(identity));
      }
      if (method === "POST") {
        if (!canManage) return denyRole();
        return json(
          res,
          201,
          await channels.createConnection(identity, await readJsonObject(req)),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }
    const connectionMatch =
      /^\/v1\/channels\/connections\/([0-9A-HJKMNP-TV-Z]{26})(?:\/(credentials|assign|assistant|telegram-setup|pause|resume|activate|disconnect|delete|cutover|rollback|webhook|events|oauth\/start))?$/
        .exec(path);
    if (connectionMatch) {
      const channels = requireChannels();
      const id = connectionMatch[1]!;
      const sub = connectionMatch[2];
      if (sub === undefined) {
        if (method !== "GET")
          throw new HttpError(405, "method_not_allowed", "use GET");
        if (!canRead) return denyRole();
        const connection = await channels.getConnection(identity, id);
        if (connection === null)
          throw new HttpError(404, "not_found", "unknown connection");
        return json(res, 200, connection);
      }
      if (sub === "events") {
        if (method !== "GET")
          throw new HttpError(405, "method_not_allowed", "use GET");
        if (!canRead) return denyRole();
        return json(res, 200, await channels.listEvents(identity, id));
      }
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!canManage) return denyRole();
      if (sub === "oauth/start") {
        return json(res, 200, await channels.oauthStart(identity, id));
      }
      const body = await readJsonObject(req);
      if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "actor")) {
        throw new HttpError(
          400,
          "identity_from_key",
          "identity comes from your credential",
        );
      }
      if (sub === "credentials") {
        return json(
          res,
          200,
          await channels.setCredentials(identity, id, body),
        );
      }
      if (sub === "assign") {
        return json(res, 200, await channels.assignAgent(identity, id, body));
      }
      if (sub === "assistant") {
        return json(res, 200, await channels.assignAssistant(identity, id, body));
      }
      if (sub === "telegram-setup") {
        return json(res, 200, await channels.setupTelegram(identity, id, body));
      }
      if (sub === "webhook") {
        return json(
          res,
          200,
          await channels.registerWebhook(identity, id, body),
        );
      }
      return json(
        res,
        200,
        await channels.transition(
          identity,
          id,
          sub as
            | "pause"
            | "resume"
            | "activate"
            | "disconnect"
            | "delete"
            | "cutover"
            | "rollback",
          body,
        ),
      );
    }
    throw new HttpError(404, "not_found", "unknown channels route");
  }

  // --- admin: certificate read (owner OR auditor) --------------------------
  // Placed BEFORE the owner/admin gate below: an auditor MAY read a deletion
  // certificate (a regulator reads, never mints) even though every other
  // /v1/admin/* route is owner/admin-only.
  const certMatch = /^\/v1\/admin\/certificate\/([^/]+)$/.exec(path);
  if (certMatch) {
    if (method !== "GET")
      throw new HttpError(405, "method_not_allowed", "use GET");
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      await auditDenied(
        deps,
        routeOp(path, method),
        identity.actor,
        identity.namespace,
        `403 ${method} ${path}`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      return json(res, 403, {
        error: "owner, admin, or auditor role required",
        code: "forbidden",
      });
    }
    if (!deps.admin.getCertificate) {
      throw new HttpError(404, "not_found", "certificate lookup unavailable");
    }
    const cert = await deps.admin.getCertificate(
      decodeURIComponent(certMatch[1]),
      identity,
    );
    if (cert === null || cert === undefined) {
      throw new HttpError(404, "not_found", "unknown certificate");
    }
    return json(res, 200, cert);
  }

  // --- M5 control-room management API --------------------------------------
  // Placed BEFORE the owner/admin gate so an AUDITOR (read-only everywhere in
  // its scope) can reach the READ screens (overview/people/memory-map/audit/
  // sources/fragmentation GET). The MUTATING routes here re-assert owner/admin
  // (auditor denied + audited). All handlers are subtree-scoped in the kernel;
  // an absent handler 404s (a deployment without the console API).
  {
    const consoleRoute = matchConsoleRoute(path, method);
    if (consoleRoute !== null) {
      if (!canAccessConsoleRoute(consoleRoute, identity)) {
        await auditDenied(
          deps,
          routeOp(path, method),
          identity.actor,
          identity.namespace,
          `403 ${method} ${path}`,
          identity.role === "agent" ? identity.keyId : AGENT_ID,
        );
        return json(res, 403, {
          error: "route is not available for this role",
          code: "forbidden",
        });
      }
      return handleConsoleRoute(deps, consoleRoute, req, res, url, identity);
    }
  }

  // M8A oversight read models are available to the audit role as well as
  // owners/admins. Mutations remain behind the owner/admin gate below.
  if (
    method === "GET" &&
    (path === "/v1/admin/agent-connections" ||
      path === "/v1/admin/agent-access/events" ||
      path === "/v1/admin/agent-access/alerts" ||
      path === "/v1/admin/agent-access/requests")
  ) {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      identity.role !== "auditor"
    ) {
      await auditDenied(
        deps,
        "read",
        identity.actor,
        identity.namespace,
        `403 ${method} ${path}`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      return json(res, 403, {
        error: "owner, admin, or auditor role required",
        code: "forbidden",
      });
    }
    if (path === "/v1/admin/agent-connections") {
      if (!deps.admin.listAgentConnections) {
        throw new HttpError(404, "not_found", "agent connections unavailable");
      }
      return json(res, 200, await deps.admin.listAgentConnections(identity));
    }
    const filters = Object.fromEntries(url.searchParams.entries());
    if (path === "/v1/admin/agent-access/events") {
      if (!deps.admin.listAgentAccessEvents) {
        throw new HttpError(
          404,
          "not_found",
          "agent access events unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.listAgentAccessEvents(filters, identity),
      );
    }
    if (path === "/v1/admin/agent-access/alerts") {
      if (!deps.admin.listAgentAccessAlerts) {
        throw new HttpError(
          404,
          "not_found",
          "agent access alerts unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.listAgentAccessAlerts(filters, identity),
      );
    }
    if (!deps.admin.listAgentAccessRequests) {
      throw new HttpError(
        404,
        "not_found",
        "agent access requests unavailable",
      );
    }
    return json(
      res,
      200,
      await deps.admin.listAgentAccessRequests(filters, identity),
    );
  }

  // --- admin (owner/admin only, 403 audited) -------------------------------
  if (path.startsWith("/v1/admin/")) {
    if (
      identity.role !== "owner" &&
      identity.role !== "admin" &&
      !mayReachAgentKeyRoute(identity, path, method)
    ) {
      await auditDenied(
        deps,
        routeOp(path, method),
        identity.actor,
        identity.namespace,
        `403 ${method} ${path}`,
        identity.role === "agent" ? identity.keyId : AGENT_ID,
      );
      return json(res, 403, {
        error: "admin role required",
        code: "forbidden",
      });
    }

    if (path === "/v1/admin/policy") {
      if (method === "GET") {
        const ns = url.searchParams.get("namespace") ?? identity.namespace;
        return json(res, 200, await deps.admin.getPolicy(ns, identity));
      }
      if (method === "PUT") {
        const body = await readJsonObject(req);
        if (typeof body.yaml !== "string") {
          throw new HttpError(
            400,
            "invalid_body",
            "'yaml' (string) is required",
          );
        }
        const ns =
          typeof body.namespace === "string"
            ? body.namespace
            : identity.namespace;
        return json(
          res,
          200,
          await deps.admin.setPolicy(ns, body.yaml, identity),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or PUT");
    }

    if (path === "/v1/admin/keys") {
      if (method === "GET")
        return json(res, 200, await deps.admin.listKeys(identity));
      if (method === "POST") {
        const body = await readJsonObject(req);
        return json(res, 201, await deps.admin.issueKey(body, identity));
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const keyRevealMatch = /^\/v1\/admin\/keys\/([^/]+)\/reveal$/.exec(path);
    if (keyRevealMatch) {
      if (method !== "POST") throw new HttpError(405, "method_not_allowed", "use POST");
      if (!identity.sessionUserId || key !== null || !parseCookies(req.headers.cookie)[SESSION_COOKIE]) {
        await auditDenied(
          deps,
          "read",
          identity.actor,
          identity.namespace,
          `403 ${method} /v1/admin/keys/:id/reveal human session required`,
        );
        return json(res, 403, { error: "human session required", code: "forbidden" });
      }
      if (headerValue(req.headers.origin) !== issuerBaseUrl(deps, req)) {
        await auditDenied(
          deps,
          "read",
          identity.actor,
          identity.namespace,
          `403 ${method} /v1/admin/keys/:id/reveal same-origin required`,
        );
        return json(res, 403, { error: "same-origin initiation required", code: "forbidden" });
      }
      if (!deps.admin.revealKey) {
        throw new HttpError(404, "not_found", "key reveal unavailable");
      }
      await readJsonObject(req);
      res.setHeader("cache-control", "no-store");
      res.setHeader("referrer-policy", "no-referrer");
      return json(
        res,
        200,
        await deps.admin.revealKey(decodeURIComponent(keyRevealMatch[1]), identity),
      );
    }

    if (path === "/v1/admin/key-handoffs") {
      if (method !== "GET") throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.listKeyHandoffs) {
        throw new HttpError(404, "not_found", "key handoffs unavailable");
      }
      res.setHeader("cache-control", "no-store");
      return json(res, 200, await deps.admin.listKeyHandoffs(identity));
    }
    const keyHandoffClaim = /^\/v1\/admin\/key-handoffs\/([^/]+)\/claim$/.exec(path);
    if (keyHandoffClaim) {
      if (method !== "POST") throw new HttpError(405, "method_not_allowed", "use POST");
      if (!identity.sessionUserId || key !== null || !parseCookies(req.headers.cookie)[SESSION_COOKIE]) {
        await auditDenied(
          deps,
          "share",
          identity.actor,
          identity.namespace,
          `403 ${method} /v1/admin/key-handoffs/:id/claim human session required`,
        );
        return json(res, 403, { error: "human session required", code: "forbidden" });
      }
      if (headerValue(req.headers.origin) !== issuerBaseUrl(deps, req)) {
        await auditDenied(
          deps,
          "share",
          identity.actor,
          identity.namespace,
          `403 ${method} /v1/admin/key-handoffs/:id/claim same-origin required`,
        );
        return json(res, 403, { error: "same-origin initiation required", code: "forbidden" });
      }
      if (!deps.admin.claimKeyHandoff) {
        throw new HttpError(404, "not_found", "key handoffs unavailable");
      }
      res.setHeader("cache-control", "no-store");
      res.setHeader("referrer-policy", "no-referrer");
      return json(res, 200, await deps.admin.claimKeyHandoff(
        decodeURIComponent(keyHandoffClaim[1]), identity,
      ));
    }
    const keyHandoff = /^\/v1\/admin\/key-handoffs\/([^/]+)$/.exec(path);
    if (keyHandoff) {
      if (method !== "DELETE") throw new HttpError(405, "method_not_allowed", "use DELETE");
      if (!deps.admin.revokeKeyHandoff) {
        throw new HttpError(404, "not_found", "key handoffs unavailable");
      }
      return json(res, 200, await deps.admin.revokeKeyHandoff(
        decodeURIComponent(keyHandoff[1]), identity,
      ));
    }

    if (path === "/v1/admin/agent-connections") {
      if (method === "GET") {
        if (!deps.admin.listAgentConnections) {
          throw new HttpError(
            404,
            "not_found",
            "agent connections unavailable",
          );
        }
        return json(res, 200, await deps.admin.listAgentConnections(identity));
      }
      if (method === "POST") {
        if (!deps.admin.createAgentConnection) {
          throw new HttpError(
            404,
            "not_found",
            "agent connections unavailable",
          );
        }
        return json(
          res,
          201,
          await deps.admin.createAgentConnection(
            await readJsonObject(req),
            identity,
          ),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    if (path === "/v1/admin/agent-badges") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.issueAgentBadge) {
        throw new HttpError(
          404,
          "not_found",
          "agent badge issuance unavailable",
        );
      }
      return json(
        res,
        201,
        await deps.admin.issueAgentBadge(await readJsonObject(req), identity),
      );
    }

    if (path === "/v1/admin/agent-access/events") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.listAgentAccessEvents) {
        throw new HttpError(
          404,
          "not_found",
          "agent access events unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.listAgentAccessEvents(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/agent-access/alerts") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.listAgentAccessAlerts) {
        throw new HttpError(
          404,
          "not_found",
          "agent access alerts unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.listAgentAccessAlerts(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    }

    const agentAlertMatch =
      /^\/v1\/admin\/agent-access\/alerts\/([^/]+)\/acknowledge$/.exec(path);
    if (agentAlertMatch) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.acknowledgeAgentAccessAlert) {
        throw new HttpError(
          404,
          "not_found",
          "agent access alerts unavailable",
        );
      }
      await readJsonObject(req);
      return json(
        res,
        200,
        await deps.admin.acknowledgeAgentAccessAlert(
          decodeURIComponent(agentAlertMatch[1]!),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/agent-access/requests") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.listAgentAccessRequests) {
        throw new HttpError(
          404,
          "not_found",
          "agent access requests unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.listAgentAccessRequests(
          Object.fromEntries(url.searchParams.entries()),
          identity,
        ),
      );
    }

    const agentRequestDecisionMatch =
      /^\/v1\/admin\/agent-access\/requests\/([^/]+)\/(approve|deny)$/.exec(
        path,
      );
    if (agentRequestDecisionMatch) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      const id = decodeURIComponent(agentRequestDecisionMatch[1]!);
      const body = await readJsonObject(req);
      if (agentRequestDecisionMatch[2] === "approve") {
        if (!deps.admin.approveAgentAccessRequest) {
          throw new HttpError(
            404,
            "not_found",
            "agent access requests unavailable",
          );
        }
        return json(
          res,
          200,
          await deps.admin.approveAgentAccessRequest(id, body, identity),
        );
      }
      if (!deps.admin.denyAgentAccessRequest) {
        throw new HttpError(
          404,
          "not_found",
          "agent access requests unavailable",
        );
      }
      return json(
        res,
        200,
        await deps.admin.denyAgentAccessRequest(id, body, identity),
      );
    }

    const agentConnectionMatch =
      /^\/v1\/admin\/agent-connections\/([^/]+)$/.exec(path);
    if (agentConnectionMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      if (!deps.admin.revokeAgentConnection) {
        throw new HttpError(404, "not_found", "agent connections unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.revokeAgentConnection(
          decodeURIComponent(agentConnectionMatch[1]!),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/model-catalog") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.listModelCatalog) {
        throw new HttpError(404, "not_found", "model catalog unavailable");
      }
      return json(res, 200, {
        providers: await deps.admin.listModelCatalog(identity),
      });
    }

    if (path === "/v1/admin/model-connections") {
      if (method === "GET") {
        if (!deps.admin.listModelConnections) {
          throw new HttpError(
            404,
            "not_found",
            "model connections unavailable",
          );
        }
        return json(res, 200, await deps.admin.listModelConnections(identity));
      }
      if (method === "POST") {
        if (!deps.admin.createModelConnection) {
          throw new HttpError(
            404,
            "not_found",
            "model connections unavailable",
          );
        }
        return json(
          res,
          201,
          await deps.admin.createModelConnection(
            await readJsonObject(req),
            identity,
          ),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const modelConnectionMatch =
      /^\/v1\/admin\/model-connections\/([^/]+)$/.exec(path);
    if (modelConnectionMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      if (!deps.admin.revokeModelConnection) {
        throw new HttpError(404, "not_found", "model connections unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.revokeModelConnection(
          decodeURIComponent(modelConnectionMatch[1]!),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/model-profiles") {
      if (method === "GET") {
        if (!deps.admin.listModelProfiles) {
          throw new HttpError(404, "not_found", "model profiles unavailable");
        }
        return json(res, 200, await deps.admin.listModelProfiles(identity));
      }
      if (method === "POST") {
        if (!deps.admin.createModelProfile) {
          throw new HttpError(404, "not_found", "model profiles unavailable");
        }
        return json(
          res,
          201,
          await deps.admin.createModelProfile(
            await readJsonObject(req),
            identity,
          ),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const modelProfileMatch = /^\/v1\/admin\/model-profiles\/([^/]+)$/.exec(
      path,
    );
    if (modelProfileMatch) {
      if (method === "PATCH") {
        if (!deps.admin.updateModelProfile) {
          throw new HttpError(404, "not_found", "model profiles unavailable");
        }
        return json(
          res,
          200,
          await deps.admin.updateModelProfile(
            decodeURIComponent(modelProfileMatch[1]!),
            await readJsonObject(req),
            identity,
          ),
        );
      }
      if (method !== "DELETE") {
        throw new HttpError(405, "method_not_allowed", "use PATCH or DELETE");
      }
      if (!deps.admin.deleteModelProfile) {
        throw new HttpError(404, "not_found", "model profiles unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.deleteModelProfile(
          decodeURIComponent(modelProfileMatch[1]!),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/pins") {
      if (method === "GET") {
        if (!deps.admin.listPins)
          throw new HttpError(404, "not_found", "pin listing unavailable");
        const namespace =
          url.searchParams.get("namespace") ?? identity.namespace;
        return json(res, 200, await deps.admin.listPins(namespace, identity));
      }
      if (method === "POST") {
        if (!deps.admin.createPin)
          throw new HttpError(404, "not_found", "pin creation unavailable");
        return json(
          res,
          201,
          await deps.admin.createPin(await readJsonObject(req), identity),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const pinMatch = /^\/v1\/admin\/pins\/([^/]+)$/.exec(path);
    if (pinMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      if (!deps.admin.deletePin)
        throw new HttpError(404, "not_found", "pin deletion unavailable");
      return json(
        res,
        200,
        await deps.admin.deletePin(decodeURIComponent(pinMatch[1]), identity),
      );
    }

    if (path === "/v1/admin/mounts/fork") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.forkMount)
        throw new HttpError(404, "not_found", "mount fork unavailable");
      return json(
        res,
        201,
        await deps.admin.forkMount(await readJsonObject(req), identity),
      );
    }

    const mountMatch = /^\/v1\/admin\/mounts\/([^/]+)$/.exec(path);
    if (mountMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      if (!deps.admin.revokeMount)
        throw new HttpError(404, "not_found", "mount revocation unavailable");
      return json(
        res,
        200,
        await deps.admin.revokeMount(
          decodeURIComponent(mountMatch[1]),
          identity,
        ),
      );
    }

    if (path === "/v1/admin/movement/run") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.runMovement)
        throw new HttpError(404, "not_found", "movement unavailable");
      return json(
        res,
        200,
        await deps.admin.runMovement(await readJsonObject(req), identity),
      );
    }

    if (path === "/v1/admin/scorecard") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.runScorecard) {
        throw new HttpError(404, "not_found", "scorecard unavailable");
      }
      const body = await readJsonObject(req);
      const ns =
        typeof body.namespace === "string"
          ? body.namespace
          : identity.namespace;
      return json(res, 200, await deps.admin.runScorecard(ns, identity));
    }

    // M4: compliance erasure — owner/admin (the gate above), subtree-scoped
    // by the caller's identity inside kernel.memForget.
    if (path === "/v1/admin/forget") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.forget) {
        throw new HttpError(404, "not_found", "forget unavailable");
      }
      const body = await readJsonObject(req);
      return json(res, 200, await deps.admin.forget(body, identity));
    }

    // R6: warm-store mirror admin (root-owner-only inside the kernel methods).
    if (path === "/v1/admin/warmstores") {
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET");
      if (!deps.admin.warmStores) {
        throw new HttpError(404, "not_found", "warm stores unavailable");
      }
      return json(res, 200, await deps.admin.warmStores(identity));
    }

    if (path === "/v1/admin/warmstores/flush") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.warmFlush) {
        throw new HttpError(404, "not_found", "warm-store flush unavailable");
      }
      return json(res, 200, await deps.admin.warmFlush(identity));
    }

    const warmRebuildMatch = /^\/v1\/admin\/warmstores\/([^/]+)\/rebuild$/.exec(
      path,
    );
    if (warmRebuildMatch) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.warmRebuild) {
        throw new HttpError(404, "not_found", "warm-store rebuild unavailable");
      }
      const body = await readJsonObject(req);
      return json(
        res,
        200,
        await deps.admin.warmRebuild(
          decodeURIComponent(warmRebuildMatch[1]!),
          body,
          identity,
        ),
      );
    }

    // M4: tenant admin.
    if (path === "/v1/admin/tenants") {
      if (method === "GET") {
        if (!deps.admin.listTenants) {
          throw new HttpError(404, "not_found", "tenant listing unavailable");
        }
        return json(res, 200, await deps.admin.listTenants(identity));
      }
      if (method === "POST") {
        if (!deps.admin.registerTenant) {
          throw new HttpError(
            404,
            "not_found",
            "tenant registration unavailable",
          );
        }
        const body = await readJsonObject(req);
        return json(res, 201, await deps.admin.registerTenant(body, identity));
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    // Organization adoption — the orphan-namespace repair (root only, kernel-enforced).
    if (path === "/v1/admin/org/adopt") {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.adoptOrganization) {
        throw new HttpError(
          404,
          "not_found",
          "organization adoption unavailable",
        );
      }
      const body = await readJsonObject(req);
      return json(res, 200, await deps.admin.adoptOrganization(body, identity));
    }

    const suspendMatch = /^\/v1\/admin\/tenants\/([^/]+)\/suspend$/.exec(path);
    if (suspendMatch) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.suspendTenant) {
        throw new HttpError(404, "not_found", "tenant suspend unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.suspendTenant(
          decodeURIComponent(suspendMatch[1]),
          identity,
        ),
      );
    }

    // M9 #23 (E52): audited, scope-preserving key rotation. Exact suffix match
    // runs before the generic /keys/:id DELETE so the id can never be
    // "abc/rotate".
    const keyRotateMatch = /^\/v1\/admin\/keys\/([^/]+)\/rotate$/.exec(path);
    if (keyRotateMatch) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      if (!deps.admin.rotateKey) {
        throw new HttpError(404, "not_found", "key rotation unavailable");
      }
      await readJsonObject(req);
      return json(
        res,
        201,
        await deps.admin.rotateKey(
          decodeURIComponent(keyRotateMatch[1]),
          identity,
        ),
      );
    }

    // M9 #1 (E1/E2): GitHub App installations — summaries only; no token or
    // installation id ever crosses this boundary.
    if (path === "/v1/admin/github/installations") {
      if (method === "GET") {
        if (!deps.admin.listGitHubInstallations) {
          throw new HttpError(
            404,
            "not_found",
            "GitHub App installations unavailable",
          );
        }
        return json(
          res,
          200,
          await deps.admin.listGitHubInstallations(identity),
        );
      }
      if (method === "POST") {
        if (!deps.admin.startGitHubInstall) {
          throw new HttpError(
            404,
            "not_found",
            "GitHub App installations unavailable",
          );
        }
        return json(
          res,
          201,
          await deps.admin.startGitHubInstall(
            await readJsonObject(req),
            identity,
          ),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const githubInstallAction =
      /^\/v1\/admin\/github\/installations\/([^/]+)\/(approve|revoke)$/.exec(
        path,
      );
    if (githubInstallAction) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      const id = decodeURIComponent(githubInstallAction[1]!);
      const body = await readJsonObject(req);
      if (githubInstallAction[2] === "approve") {
        if (!deps.admin.approveGitHubInstall) {
          throw new HttpError(
            404,
            "not_found",
            "GitHub App installations unavailable",
          );
        }
        return json(
          res,
          200,
          await deps.admin.approveGitHubInstall(id, body, identity),
        );
      }
      if (!deps.admin.revokeGitHubInstall) {
        throw new HttpError(
          404,
          "not_found",
          "GitHub App installations unavailable",
        );
      }
      return json(res, 200, await deps.admin.revokeGitHubInstall(id, identity));
    }

    // M9 #11b (D29): OAuth client registry. Secrets are returned exactly
    // once at creation; only sha256 digests are ever stored (E23).
    if (path === "/v1/admin/oauth/clients") {
      if (method === "GET") {
        if (!deps.admin.listOAuthClients) {
          throw new HttpError(404, "not_found", "oauth clients unavailable");
        }
        return json(res, 200, await deps.admin.listOAuthClients(identity));
      }
      if (method === "POST") {
        if (!deps.admin.createOAuthClient) {
          throw new HttpError(404, "not_found", "oauth clients unavailable");
        }
        return json(
          res,
          201,
          await deps.admin.createOAuthClient(
            await readJsonObject(req),
            identity,
          ),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const oauthClientAction =
      /^\/v1\/admin\/oauth\/clients\/([^/]+)\/(approve|revoke)$/.exec(path);
    if (oauthClientAction) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      const id = decodeURIComponent(oauthClientAction[1]!);
      const body = await readJsonObject(req);
      if (oauthClientAction[2] === "approve") {
        if (!deps.admin.approveOAuthClient) {
          throw new HttpError(404, "not_found", "oauth clients unavailable");
        }
        return json(
          res,
          200,
          await deps.admin.approveOAuthClient(id, identity),
        );
      }
      if (!deps.admin.revokeOAuthClient) {
        throw new HttpError(404, "not_found", "oauth clients unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.revokeOAuthClient(id, body, identity),
      );
    }

    // M9 #9 (E19–E22): company skill library management.
    if (path === "/v1/admin/skills") {
      if (method === "GET") {
        if (!deps.admin.listSkills) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        return json(res, 200, await deps.admin.listSkills(identity));
      }
      if (method === "POST") {
        if (!deps.admin.registerSkill) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        return json(
          res,
          201,
          await deps.admin.registerSkill(await readJsonObject(req), identity),
        );
      }
      throw new HttpError(405, "method_not_allowed", "use GET or POST");
    }

    const skillLabelsMatch = /^\/v1\/admin\/skills\/([^/]+)\/labels$/.exec(
      path,
    );
    if (skillLabelsMatch) {
      if (method !== "PATCH")
        throw new HttpError(405, "method_not_allowed", "use PATCH");
      if (!deps.admin.updateSkillLabels) {
        throw new HttpError(404, "not_found", "skill labels unavailable");
      }
      return json(
        res,
        200,
        await deps.admin.updateSkillLabels(
          decodeURIComponent(skillLabelsMatch[1]!),
          await readJsonObject(req),
          identity,
        ),
      );
    }
    const skillAction =
      /^\/v1\/admin\/skills\/([^/]+)\/(vet|override|retire|approve|reject)$/.exec(
        path,
      );
    if (skillAction) {
      if (method !== "POST")
        throw new HttpError(405, "method_not_allowed", "use POST");
      const id = decodeURIComponent(skillAction[1]!);
      if (skillAction[2] === "vet") {
        if (!deps.admin.vetSkill)
          throw new HttpError(404, "not_found", "skills unavailable");
        await readJsonObject(req);
        return json(res, 200, await deps.admin.vetSkill(id, identity));
      }
      if (skillAction[2] === "override") {
        if (!deps.admin.overrideSkill) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        return json(
          res,
          200,
          await deps.admin.overrideSkill(
            id,
            await readJsonObject(req),
            identity,
          ),
        );
      }
      if (skillAction[2] === "approve") {
        if (!deps.admin.approveSkill) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        await readJsonObject(req);
        return json(res, 200, await deps.admin.approveSkill(id, identity));
      }
      if (skillAction[2] === "reject") {
        if (!deps.admin.rejectSkill) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        return json(
          res,
          200,
          await deps.admin.rejectSkill(id, await readJsonObject(req), identity),
        );
      }
      if (!deps.admin.retireSkill)
        throw new HttpError(404, "not_found", "skills unavailable");
      await readJsonObject(req);
      return json(res, 200, await deps.admin.retireSkill(id, identity));
    }

    const skillMatch = /^\/v1\/admin\/skills\/([^/]+)$/.exec(path);
    if (skillMatch) {
      const id = decodeURIComponent(skillMatch[1]!);
      if (method === "PATCH") {
        if (!deps.admin.updateSkill) {
          throw new HttpError(404, "not_found", "skills unavailable");
        }
        return json(
          res,
          200,
          await deps.admin.updateSkill(id, await readJsonObject(req), identity),
        );
      }
      if (method !== "GET")
        throw new HttpError(405, "method_not_allowed", "use GET or PATCH");
      if (!deps.admin.getSkill)
        throw new HttpError(404, "not_found", "skills unavailable");
      return json(res, 200, await deps.admin.getSkill(id, identity));
    }

    const keyMatch = /^\/v1\/admin\/keys\/([^/]+)$/.exec(path);
    if (keyMatch) {
      if (method !== "DELETE")
        throw new HttpError(405, "method_not_allowed", "use DELETE");
      return json(
        res,
        200,
        await deps.admin.revokeKey(decodeURIComponent(keyMatch[1]), identity),
      );
    }

    throw new HttpError(404, "not_found", "unknown admin route");
  }

  throw new HttpError(404, "not_found", "unknown route");
}

export async function handleHttpRequest(
  deps: HttpServerDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const startedAt = performance.now();
  const context = initializeRequestContext(deps, req, res);
  let observedRoute = "/other";
  res.once("finish", () => {
    try {
      deps.telemetry?.observe({
        requestId: context.requestId,
        traceId: context.traceId,
        method: req.method ?? "GET",
        route: observedRoute,
        status: res.statusCode,
        durationMs: Math.max(0, performance.now() - startedAt),
      });
    } catch {
      // Telemetry must never turn a completed request into a process crash.
    }
  });
  let url: URL;
  try {
    url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  } catch {
    return json(res, 400, {
      error: "malformed request url",
      code: "bad_request",
    });
  }
  observedRoute = httpRouteTemplate(url.pathname);
  try {
    await route(deps, req, res, url, context);
  } catch (err) {
    if (res.headersSent) {
      // Mid-stream failure (e.g. inside the MCP transport) — nothing sane to
      // send; drop the connection.
      res.destroy();
      return;
    }
    if (err instanceof HttpError) {
      // Browser navigations render the Halo status page; API callers keep JSON.
      return errorResponse(req, res, err.status, err.code, err.message);
    }
    const message = err instanceof Error ? err.message : String(err);
    // Name-based mapping for kernel-layer errors (integrator wiring): the
    // syscall/admin layer throws AuthzError (role denial), RateLimitError
    // (token bucket), and BadRequestError (payload validation).
    const name = err instanceof Error ? err.name : "";
    if (name === "AuthzError")
      return json(res, 403, { error: message, code: "forbidden" });
    if (name === "RateLimitError") {
      const rateLimitErr = err as { retryAfterSec?: number };
      if (rateLimitErr.retryAfterSec) {
        res.setHeader(
          "retry-after",
          String(Math.max(1, Math.ceil(rateLimitErr.retryAfterSec))),
        );
      }
      return json(res, 429, { error: message, code: "rate_limited" });
    }
    if (name === "ClassificationDeniedError") {
      return json(res, 403, { error: message, code: "classification_denied" });
    }
    if (name === "BadRequestError")
      return json(res, 400, { error: message, code: "bad_request" });
    if (name === "ChannelLifecycleError") {
      const code = (err as { code?: string }).code ?? "";
      if (code === "channel-role-denied" || code === "channel-scope-denied") {
        return json(res, 403, { error: message, code: "forbidden" });
      }
      if (code === "channel-stale" || code === "channel-transition-denied") {
        return json(res, 409, { error: message, code: "conflict" });
      }
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "ChannelOAuthError") {
      const code = (err as { code?: string }).code ?? "";
      if (code === "oauth-unavailable") {
        return json(res, 503, { error: message, code: "oauth_unavailable" });
      }
      if (code === "oauth-connection-invalid") {
        return json(res, 404, { error: "not found", code: "not_found" });
      }
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (message.startsWith("channel-credential-")) {
      if (message.endsWith("-stale"))
        return json(res, 409, { error: message, code: "conflict" });
      if (message.endsWith("-denied"))
        return json(res, 403, { error: message, code: "forbidden" });
      if (message.endsWith("-unavailable") || message.endsWith("-error")) {
        return json(res, 503, {
          error: message,
          code: "channel_credentials_unavailable",
        });
      }
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (
      name === "InvalidAgentConnectionGrantError" ||
      name === "InvalidAgentOversightRecordError"
    ) {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "PolicyDocumentValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "PolicyDocumentConflictError") {
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (name === "PolicyDocumentQuotaError") {
      return json(res, 409, { error: message, code: "policy_document_quota" });
    }
    if (
      name === "KnowledgeBaseValidationError" ||
      name === "KnowledgeBaseSourceValidationError" ||
      name === "CompanyFileValidationError"
    ) {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (
      name === "KnowledgeBaseNotFoundError" ||
      name === "KnowledgeBaseSourceNotFoundError"
    ) {
      return json(res, 404, { error: "not found", code: "not_found" });
    }
    // M10 (D46): unauthorized and nonexistent scopes/subjects/previews are
    // byte-identical not-founds; the kernel already wrote the denial audit.
    if (
      name === "PreviewNotFoundError" ||
      name === "MemoryGraphNotFoundError" ||
      name === "ChannelConnectionNotFoundError"
    ) {
      return json(res, 404, { error: "not found", code: "not_found" });
    }
    // M10 (contract rule 12): authorization dependency failure browns out to
    // "unavailable" — never a wider projection, never a 200.
    if (name === "ProjectionUnavailableError") {
      return json(res, 503, {
        error: "access view unavailable",
        code: "access_unavailable",
      });
    }
    if (name === "CompanyFileIdempotencyError") {
      const code = (err as { code?: string }).code;
      if (
        code === "company_file_idempotency_conflict" ||
        code === "company_file_upload_processing" ||
        code === "company_file_upload_unreserved"
      ) {
        return json(res, 409, { error: message, code });
      }
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (
      name === "KnowledgeBaseConflictError" ||
      name === "KnowledgeBaseSourceConflictError" ||
      name === "CompanyFileConflictError"
    ) {
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (name === "CompanyFileLeaseExpiredError") {
      return json(res, 409, {
        error: "upload lease expired",
        code: "lease_expired",
      });
    }
    if (name === "CompanyFileQuotaError") {
      return json(res, 429, {
        error: "company file quota exceeded",
        code: "company_file_quota",
      });
    }
    if (
      name === "CompanyFileConcurrencyError" ||
      name === "PolicyDocumentConcurrencyError"
    ) {
      return json(res, 429, {
        error: "too many uploads in progress",
        code: "too_many_concurrent_uploads",
      });
    }
    if (name === "NangoConnectionLimitError") {
      return json(res, 409, { error: message, code: "connection_limit" });
    }
    if (name === "NangoConnectionPendingError") {
      return json(res, 409, { error: message, code: "authorization_pending" });
    }
    if (name === "NangoUnavailableError") {
      return json(res, 503, { error: message, code: "provider_unavailable" });
    }
    if (name === "WebhookAuthorizationError") {
      return json(res, 401, {
        error: "invalid webhook signature",
        code: "unauthorized",
      });
    }
    if (name === "WebhookValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "WebhookDeliveryError") {
      return json(res, 503, {
        error: message,
        code: "webhook_delivery_failed",
      });
    }
    if (name === "ObsidianAuthorizationError") {
      return json(res, 401, {
        error: "invalid obsidian signature",
        code: "unauthorized",
      });
    }
    if (name === "ObsidianValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "ObsidianDeliveryError") {
      return json(res, 503, {
        error: message,
        code: "obsidian_delivery_failed",
      });
    }
    if (name === "PinValidationError")
      return json(res, 400, { error: message, code: "bad_request" });
    if (name === "SharingValidationError")
      return json(res, 400, { error: message, code: "bad_request" });
    if (name === "SharingAuthorizationError")
      return json(res, 403, { error: message, code: "forbidden" });
    if (name === "SetupConflictError")
      return json(res, 409, { error: message, code: "conflict" });
    if (name === "SignupValidationError") {
      return json(res, 400, { error: message, code: "invalid_body" });
    }
    // Bad organization display name on the bootstrap path — a client mistake,
    // not a server fault, and it must not read as "bootstrap unavailable".
    if (name === "OrganizationNameError") {
      return json(res, 400, { error: message, code: "invalid_body" });
    }
    // S18 Settings: an unusable name or icon is the same class of mistake.
    if (name === "SettingsBadRequestError") {
      return json(res, 400, { error: message, code: "invalid_body" });
    }
    if (name === "SignupConflictError") {
      clearSignupCookie(res);
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (name === "MovementConflictError")
      return json(res, 409, { error: message, code: "conflict" });
    if (name === "ProposalConflictError")
      return json(res, 409, { error: message, code: "conflict" });
    if (name === "ConsolidationAuthorizationError")
      return json(res, 403, { error: message, code: "forbidden" });
    if (name === "DisputeConflictError")
      return json(res, 409, { error: message, code: "conflict" });
    if (name === "ConflictFindingConflictError") {
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (name === "ConflictFindingNotFoundError") {
      return json(res, 404, { error: "not found", code: "not_found" });
    }
    if (name === "DisputeAuthorizationError")
      return json(res, 403, { error: message, code: "forbidden" });
    if (name === "AutomationAuthorizationError") {
      return json(res, 403, { error: message, code: "forbidden" });
    }
    if (name === "AnswerOutcomeValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "AnswerOutcomeAuthorizationError") {
      return json(res, 403, { error: message, code: "forbidden" });
    }
    if (name === "ManifestArgsError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "GitHubAppAuthzError") {
      return json(res, 403, { error: message, code: "forbidden" });
    }
    if (name === "GitHubAppStateError") {
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (
      name === "GitHubAppNotConfiguredError" ||
      name === "GitHubAppUnavailableError"
    ) {
      return json(res, 503, { error: message, code: "provider_unavailable" });
    }
    if (name === "OAuthClientInputError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "CreditExhaustedError") {
      return json(res, 402, { error: message, code: "credits_exhausted" });
    }
    if (name === "QuotaLimitError" || name === "EarlyAccessLimitError") {
      const limit = err as Error & { code?: string; feature?: string | null; limit?: number | null };
      return json(res, 402, {
        error: message,
        code: limit.code ?? (name === "QuotaLimitError" ? "quota_limit" : "early_access_limit"),
        feature: limit.feature ?? null,
        limit: limit.limit ?? null,
      });
    }
    if (name === "CopilotTurnInProgressError") {
      return json(res, 409, { error: message, code: "turn_in_progress" });
    }
    if (name === "CopilotTurnRecoveryError") {
      return json(res, 409, { error: message, code: "turn_recovery_required" });
    }
    if (
      name === "UsageCapAuthorizationError" ||
      name === "UsageAlertAuthorizationError"
    ) {
      return json(res, 403, { error: message, code: "forbidden" });
    }
    if (name === "UsageCapValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "SkillAuthorizationError") {
      return json(res, 403, { error: message, code: "forbidden" });
    }
    if (name === "SkillNotFoundError") {
      return json(res, 404, { error: message, code: "not_found" });
    }
    if (name === "SkillConflictError") {
      return json(res, 409, { error: message, code: "conflict" });
    }
    if (name === "SkillLabelValidationError") {
      return json(res, 400, { error: message, code: "bad_request" });
    }
    if (name === "ModelProfileUnavailableError") {
      return json(res, 404, { error: "LLM Key not found", code: "not_found" });
    }
    if (name === "ModelProviderRequestError") {
      return json(res, 502, { error: message, code: "provider_unavailable" });
    }
    return errorResponse(req, res, 500, "internal", "internal server error");
  }
}

// ---------------------------------------------------------------------------
// Public factory
// ---------------------------------------------------------------------------

export function createHttpServer(deps: HttpServerDeps): HaloHttpServer {
  const server = createServer((req, res) => {
    void handleHttpRequest(deps, req, res);
  });

  return {
    server,
    start(port = 0): Promise<number> {
      return new Promise((resolve, reject) => {
        const onError = (err: Error) => reject(err);
        server.once("error", onError);
        server.listen(port, () => {
          server.removeListener("error", onError);
          const addr = server.address();
          resolve(typeof addr === "object" && addr !== null ? addr.port : port);
        });
      });
    },
    stop(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
