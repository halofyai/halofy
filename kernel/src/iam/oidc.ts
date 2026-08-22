import { createHash } from "node:crypto";
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTVerifyOptions } from "jose";

import type { HumanRole, Identity } from "../types.js";

export interface OidcAuthorityBinding {
  namespace: string;
  role: HumanRole;
}

export interface OidcProviderMapping {
  issuer: string;
  audiences: string[];
  subjects?: Record<string, OidcAuthorityBinding>;
  groups?: Record<string, OidcAuthorityBinding>;
}

export interface OidcMapperConfig {
  providers: OidcProviderMapping[];
  clockSkewSec?: number;
}

/** Claims must come from a signature-verifying JWT adapter; this mapper assigns authority. */
export interface VerifiedOidcClaims {
  iss?: unknown;
  sub?: unknown;
  aud?: unknown;
  exp?: unknown;
  nbf?: unknown;
  email?: unknown;
  email_verified?: unknown;
  groups?: unknown;
  [claim: string]: unknown;
}

export class OidcMappingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OidcMappingError";
  }
}

const HUMAN_ROLES = new Set<HumanRole>(["owner", "admin", "auditor", "member"]);

function sameBinding(left: OidcAuthorityBinding, right: OidcAuthorityBinding): boolean {
  return left.namespace === right.namespace && left.role === right.role;
}

function assertBinding(binding: OidcAuthorityBinding): void {
  if (typeof binding.namespace !== "string" || binding.namespace.length > 512) {
    throw new OidcMappingError("OIDC namespace binding is invalid");
  }
  if (!HUMAN_ROLES.has(binding.role)) {
    throw new OidcMappingError("OIDC role binding is invalid");
  }
}

function audiences(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
    return value;
  }
  return [];
}

export class OidcIdentityMapper {
  private readonly providers: Map<string, OidcProviderMapping>;
  private readonly clockSkewSec: number;

  constructor(config: OidcMapperConfig) {
    this.clockSkewSec = config.clockSkewSec ?? 60;
    if (!Number.isFinite(this.clockSkewSec) || this.clockSkewSec < 0) {
      throw new OidcMappingError("OIDC clock skew must be non-negative");
    }
    this.providers = new Map();
    for (const provider of config.providers) {
      if (
        !provider.issuer.startsWith("https://") ||
        provider.audiences.length === 0 ||
        provider.audiences.some((audience) => typeof audience !== "string" || audience.length === 0)
      ) {
        throw new OidcMappingError("OIDC provider requires an HTTPS issuer and audience");
      }
      if (this.providers.has(provider.issuer)) {
        throw new OidcMappingError("duplicate OIDC issuer mapping");
      }
      for (const binding of Object.values(provider.subjects ?? {})) assertBinding(binding);
      for (const binding of Object.values(provider.groups ?? {})) assertBinding(binding);
      this.providers.set(provider.issuer, {
        issuer: provider.issuer,
        audiences: [...provider.audiences],
        subjects: provider.subjects ? { ...provider.subjects } : undefined,
        groups: provider.groups ? { ...provider.groups } : undefined,
      });
    }
  }

  map(claims: VerifiedOidcClaims, options: { now?: Date } = {}): Identity {
    if (typeof claims.iss !== "string") throw new OidcMappingError("OIDC issuer is missing");
    const provider = this.providers.get(claims.iss);
    if (!provider) throw new OidcMappingError("OIDC issuer is not trusted");
    if (typeof claims.sub !== "string" || claims.sub.length === 0 || claims.sub.length > 512) {
      throw new OidcMappingError("OIDC subject is invalid");
    }
    if (!audiences(claims.aud).some((audience) => provider.audiences.includes(audience))) {
      throw new OidcMappingError("OIDC audience is not allowed");
    }
    const nowSec = Math.floor((options.now ?? new Date()).getTime() / 1000);
    if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
      throw new OidcMappingError("OIDC expiry is missing");
    }
    if (claims.exp + this.clockSkewSec < nowSec) throw new OidcMappingError("OIDC token is expired");
    if (claims.nbf !== undefined) {
      if (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf)) {
        throw new OidcMappingError("OIDC not-before claim is invalid");
      }
      if (claims.nbf - this.clockSkewSec > nowSec) {
        throw new OidcMappingError("OIDC token is not active");
      }
    }

    const groupIds = Array.isArray(claims.groups)
      ? claims.groups.filter((value): value is string => typeof value === "string").slice(0, 256)
      : [];
    let binding = provider.subjects?.[claims.sub];
    if (!binding) {
      const matches = groupIds.flatMap((group) => {
        const match = provider.groups?.[group];
        return match ? [match] : [];
      });
      binding = matches[0];
      if (binding && matches.some((candidate) => !sameBinding(candidate, binding!))) {
        throw new OidcMappingError("OIDC group bindings are ambiguous");
      }
    }
    if (!binding) throw new OidcMappingError("OIDC subject has no server-side authority binding");

    const verifiedEmail = claims.email_verified === true && typeof claims.email === "string"
      && claims.email.length <= 320 && claims.email.includes("@");
    const actor = verifiedEmail ? (claims.email as string).trim().toLowerCase() : `oidc:${claims.sub}`;
    const digest = createHash("sha256").update(`${claims.iss}\0${claims.sub}`).digest("hex");
    return {
      keyId: `oidc:${digest}`,
      namespace: binding.namespace,
      actor,
      role: binding.role,
      sourcePrincipals: [claims.sub, actor],
      sourceGroups: groupIds,
      credentialExpiresAt: new Date(claims.exp * 1000).toISOString(),
    };
  }
}

/** Signature-verifying OIDC boundary; only its output may enter OidcIdentityMapper. */
export class OidcJwtVerifier {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly options: {
    issuer: string;
    audience: string | string[];
    jwksUri?: string;
    algorithms?: string[];
  }) {
    if (!options.issuer.startsWith("https://")) {
      throw new OidcMappingError("OIDC verifier requires an HTTPS issuer");
    }
    const jwksUri = options.jwksUri ?? `${options.issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
    const url = new URL(jwksUri);
    if (url.protocol !== "https:") throw new OidcMappingError("OIDC JWKS URI must use HTTPS");
    this.jwks = createRemoteJWKSet(url, {
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
      timeoutDuration: 5_000,
    });
  }

  async verify(token: string): Promise<VerifiedOidcClaims> {
    if (!token || token.length > 16_384) throw new OidcMappingError("OIDC token is invalid");
    const verifyOptions: JWTVerifyOptions = {
      issuer: this.options.issuer,
      audience: this.options.audience,
      algorithms: this.options.algorithms ?? ["RS256", "RS384", "RS512", "ES256", "ES384"],
      clockTolerance: 60,
    };
    try {
      const { payload } = await jwtVerify(token, this.jwks, verifyOptions);
      return payload as VerifiedOidcClaims;
    } catch {
      throw new OidcMappingError("OIDC token verification failed");
    }
  }
}

export interface OidcAuthenticatorProvider extends OidcProviderMapping {
  jwksUri?: string;
  algorithms?: string[];
}

/** Multi-issuer enterprise bearer authenticator with verified server-side mapping. */
export class OidcAuthenticator {
  private readonly mapper: OidcIdentityMapper;
  private readonly verifiers = new Map<string, OidcJwtVerifier>();

  constructor(providers: OidcAuthenticatorProvider[]) {
    this.mapper = new OidcIdentityMapper({ providers });
    for (const provider of providers) {
      this.verifiers.set(provider.issuer, new OidcJwtVerifier({
        issuer: provider.issuer,
        audience: provider.audiences,
        jwksUri: provider.jwksUri,
        algorithms: provider.algorithms,
      }));
    }
  }

  async authenticate(token: string): Promise<Identity | null> {
    let issuer: unknown;
    try { issuer = decodeJwt(token).iss; } catch { return null; }
    if (typeof issuer !== "string") return null;
    const verifier = this.verifiers.get(issuer);
    if (!verifier) return null;
    try {
      return this.mapper.map(await verifier.verify(token));
    } catch {
      return null;
    }
  }
}
