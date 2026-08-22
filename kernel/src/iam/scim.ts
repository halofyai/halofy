import type { HumanRole } from "../types.js";
import { ulid } from "ulid";
import type { Db } from "../db/client.js";

export const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
export const SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
export const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
export const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

export interface ScimAuthorityBinding {
  namespace: string;
  role: HumanRole;
}

export interface ScimDirectoryUser extends ScimAuthorityBinding {
  externalId: string;
  email: string;
  displayName: string;
  active: boolean;
  groupIds: string[];
}

export interface ScimDirectoryGroup {
  externalId: string;
  displayName: string;
  memberExternalIds: string[];
}

export interface ScimDirectory {
  upsertUser(user: ScimDirectoryUser): Promise<void>;
  replaceGroup(group: ScimDirectoryGroup): Promise<void>;
  getUser?(id: string): Promise<ScimUserResource | null>;
  listUsers?(filter?: string): Promise<ScimUserResource[]>;
  deleteUser?(id: string): Promise<boolean>;
  getGroup?(id: string): Promise<ScimGroupResource | null>;
  listGroups?(filter?: string): Promise<ScimGroupResource[]>;
  deleteGroup?(id: string): Promise<boolean>;
}

export interface ScimServiceConfig {
  groups: Record<string, ScimAuthorityBinding>;
  defaultBinding?: ScimAuthorityBinding;
}

export interface ScimUserResource {
  schemas: [typeof SCIM_USER_SCHEMA];
  id: string;
  externalId: string;
  userName: string;
  displayName: string;
  active: boolean;
  groups: Array<{ value: string }>;
}

export interface ScimGroupResource {
  schemas: [typeof SCIM_GROUP_SCHEMA];
  id: string;
  externalId: string;
  displayName: string;
  members: Array<{ value: string }>;
}

export class ScimValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScimValidationError";
  }
}

interface ParsedScimUser {
  externalId: string;
  email: string;
  displayName: string;
  active: boolean;
  groupIds: string[];
}

interface ParsedScimGroup {
  externalId: string;
  displayName: string;
  memberExternalIds: string[];
}

function object(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ScimValidationError(`${what} must be an object`);
  }
  return value as Record<string, unknown>;
}

function boundedString(value: unknown, what: string, max = 512): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) {
    throw new ScimValidationError(`${what} is invalid`);
  }
  return value.trim();
}

function assertSchema(body: Record<string, unknown>, schema: string): void {
  if (!Array.isArray(body.schemas) || !body.schemas.includes(schema)) {
    throw new ScimValidationError(`SCIM schema '${schema}' is required`);
  }
}

function rejectAuthority(body: Record<string, unknown>): void {
  if (Object.hasOwn(body, "namespace") || Object.hasOwn(body, "role")) {
    throw new ScimValidationError("SCIM clients cannot assert namespace or role");
  }
}

export function validateScimUser(input: unknown): ParsedScimUser {
  const body = object(input, "SCIM user");
  assertSchema(body, SCIM_USER_SCHEMA);
  rejectAuthority(body);
  const externalId = boundedString(body.externalId, "SCIM externalId", 256);
  const displayName = boundedString(body.displayName, "SCIM displayName", 80);
  let email = typeof body.userName === "string" ? body.userName.trim().toLowerCase() : "";
  if ((!email || !email.includes("@")) && Array.isArray(body.emails)) {
    const candidate = body.emails.map((entry) => object(entry, "SCIM email"))
      .find((entry) => entry.primary === true) ?? object(body.emails[0], "SCIM email");
    email = typeof candidate.value === "string" ? candidate.value.trim().toLowerCase() : "";
  }
  if (!email.includes("@") || email.length > 320) {
    throw new ScimValidationError("SCIM user email is invalid");
  }
  const groups = body.groups ?? [];
  if (!Array.isArray(groups) || groups.length > 256) {
    throw new ScimValidationError("SCIM groups are invalid");
  }
  const groupIds = groups.map((entry) => boundedString(
    object(entry, "SCIM group reference").value,
    "SCIM group value",
    256,
  ));
  if (body.active !== undefined && typeof body.active !== "boolean") {
    throw new ScimValidationError("SCIM active flag is invalid");
  }
  return {
    externalId,
    email,
    displayName,
    active: body.active !== false,
    groupIds: [...new Set(groupIds)],
  };
}

export function validateScimGroup(input: unknown): ParsedScimGroup {
  const body = object(input, "SCIM group");
  assertSchema(body, SCIM_GROUP_SCHEMA);
  rejectAuthority(body);
  const externalId = boundedString(body.externalId, "SCIM externalId", 256);
  const displayName = boundedString(body.displayName, "SCIM displayName", 256);
  const members = body.members ?? [];
  if (!Array.isArray(members) || members.length > 10_000) {
    throw new ScimValidationError("SCIM members are invalid");
  }
  const memberExternalIds = members.map((entry) => boundedString(
    object(entry, "SCIM member").value,
    "SCIM member value",
    256,
  ));
  return { externalId, displayName, memberExternalIds: [...new Set(memberExternalIds)] };
}

const ROLE_PRECEDENCE: Record<HumanRole, number> = {
  owner: 4, admin: 3, auditor: 2, member: 1,
};

function selectAuthorityBinding(
  bindings: ScimAuthorityBinding[],
  fallback?: ScimAuthorityBinding,
): ScimAuthorityBinding | undefined {
  if (bindings.length === 0) return fallback;
  const namespace = bindings[0]!.namespace;
  if (bindings.some((binding) => binding.namespace !== namespace)) {
    throw new ScimValidationError("SCIM user has ambiguous authority groups");
  }
  return [...bindings].sort((a, b) => ROLE_PRECEDENCE[b.role] - ROLE_PRECEDENCE[a.role])[0];
}

export class ScimProvisioningService {
  private readonly config: ScimServiceConfig;

  constructor(
    private readonly directory: ScimDirectory,
    config: ScimServiceConfig,
  ) {
    const roles = new Set<HumanRole>(["owner", "admin", "auditor", "member"]);
    const groups: Record<string, ScimAuthorityBinding> = {};
    for (const [groupId, binding] of Object.entries(config.groups)) {
      if (
        groupId.length === 0 || groupId.length > 256 ||
        typeof binding.namespace !== "string" || binding.namespace.length > 512 ||
        !roles.has(binding.role)
      ) {
        throw new ScimValidationError("SCIM authority mapping is invalid");
      }
      groups[groupId] = { ...binding };
    }
    const uniqueBindings = [...new Map(
      Object.values(groups).map((binding) => [`${binding.namespace}\0${binding.role}`, binding]),
    ).values()];
    const defaultBinding = config.defaultBinding ??
      (uniqueBindings.length === 1 && uniqueBindings[0]?.role === "member"
        ? uniqueBindings[0]
        : undefined);
    if (defaultBinding) assertAuthorityBinding(defaultBinding);
    this.config = { groups, ...(defaultBinding ? { defaultBinding: { ...defaultBinding } } : {}) };
  }

  async provisionUser(input: unknown): Promise<ScimUserResource> {
    const user = validateScimUser(input);
    const bindings = user.groupIds.flatMap((groupId) => {
      const binding = this.config.groups[groupId];
      return binding ? [binding] : [];
    });
    const binding = selectAuthorityBinding(
      bindings,
      user.groupIds.length === 0 ? this.config.defaultBinding : undefined,
    );
    if (!binding) throw new ScimValidationError("SCIM user has no mapped group or default authority");
    await this.directory.upsertUser({ ...user, namespace: binding.namespace, role: binding.role });
    const stored = await this.directory.listUsers?.(`externalId eq "${escapeFilter(user.externalId)}"`);
    return stored?.[0] ?? toUserResource(user.externalId, user);
  }

  async provisionGroup(input: unknown): Promise<ScimGroupResource> {
    const group = validateScimGroup(input);
    await this.directory.replaceGroup(group);
    const stored = await this.directory.listGroups?.(`externalId eq "${escapeFilter(group.externalId)}"`);
    return stored?.[0] ?? toGroupResource(group.externalId, group);
  }

  async getUser(id: string): Promise<ScimUserResource | null> {
    return this.requireDirectory("getUser")(id);
  }

  async listUsers(filter?: string): Promise<ScimUserResource[]> {
    return this.requireDirectory("listUsers")(filter);
  }

  async deleteUser(id: string): Promise<boolean> {
    return this.requireDirectory("deleteUser")(id);
  }

  async getGroup(id: string): Promise<ScimGroupResource | null> {
    return this.requireDirectory("getGroup")(id);
  }

  async listGroups(filter?: string): Promise<ScimGroupResource[]> {
    return this.requireDirectory("listGroups")(filter);
  }

  async deleteGroup(id: string): Promise<boolean> {
    return this.requireDirectory("deleteGroup")(id);
  }

  async replaceUser(id: string, input: unknown): Promise<ScimUserResource | null> {
    const existing = await this.getUser(id);
    if (!existing) return null;
    const body = object(input, "SCIM user");
    await this.provisionUser({ ...body, externalId: existing.externalId });
    // Return the canonical stable-id projection, not the filtered upsert
    // readback, so group/user aggregates cannot lag the replacement response.
    return this.getUser(id);
  }

  async replaceGroup(id: string, input: unknown): Promise<ScimGroupResource | null> {
    const existing = await this.getGroup(id);
    if (!existing) return null;
    const body = object(input, "SCIM group");
    await this.provisionGroup({ ...body, externalId: existing.externalId });
    return this.getGroup(id);
  }

  async patchUser(id: string, input: unknown): Promise<ScimUserResource | null> {
    const existing = await this.getUser(id);
    if (!existing) return null;
    const next = applyPatch(existing, input, new Set(["active", "userName", "displayName"]));
    return this.replaceUser(id, {
      schemas: [SCIM_USER_SCHEMA], externalId: existing.externalId,
      userName: next.userName, displayName: next.displayName, active: next.active, groups: next.groups,
    });
  }

  async patchGroup(id: string, input: unknown): Promise<ScimGroupResource | null> {
    const existing = await this.getGroup(id);
    if (!existing) return null;
    const next = applyPatch(existing, input, new Set(["displayName", "members"]));
    return this.replaceGroup(id, {
      schemas: [SCIM_GROUP_SCHEMA], externalId: existing.externalId,
      displayName: next.displayName, members: next.members,
    });
  }

  private requireDirectory<K extends keyof ScimDirectory>(name: K): NonNullable<ScimDirectory[K]> {
    const handler = this.directory[name];
    if (typeof handler !== "function") {
      throw new ScimValidationError(`SCIM directory does not support ${String(name)}`);
    }
    return handler.bind(this.directory) as NonNullable<ScimDirectory[K]>;
  }
}

function assertAuthorityBinding(binding: ScimAuthorityBinding): void {
  if (typeof binding.namespace !== "string" || binding.namespace.length === 0 ||
      binding.namespace.length > 512 ||
      !new Set<HumanRole>(["owner", "admin", "auditor", "member"]).has(binding.role)) {
    throw new ScimValidationError("SCIM default authority mapping is invalid");
  }
}

function escapeFilter(value: string): string {
  return value.replace(/["\\]/g, (match) => `\\${match}`);
}

function toUserResource(id: string, user: ParsedScimUser): ScimUserResource {
  return {
    schemas: [SCIM_USER_SCHEMA], id, externalId: user.externalId,
    userName: user.email, displayName: user.displayName, active: user.active,
    groups: user.groupIds.map((value) => ({ value })),
  };
}

function toGroupResource(id: string, group: ParsedScimGroup): ScimGroupResource {
  return {
    schemas: [SCIM_GROUP_SCHEMA], id, externalId: group.externalId,
    displayName: group.displayName,
    members: group.memberExternalIds.map((value) => ({ value })),
  };
}

function applyPatch<T extends object>(
  resource: T,
  input: unknown,
  allowed: Set<string>,
): T {
  const body = object(input, "SCIM patch");
  assertSchema(body, SCIM_PATCH_SCHEMA);
  if (!Array.isArray(body.Operations) || body.Operations.length === 0 || body.Operations.length > 100) {
    throw new ScimValidationError("SCIM patch Operations are invalid");
  }
  const next = structuredClone(resource) as Record<string, unknown>;
  const apply = (op: string, rawPath: string, value: unknown): void => {
    const filtered = /^(members|groups)\[value\s+eq\s+"((?:[^"\\]|\\.)*)"\]$/i.exec(rawPath);
    const path = filtered?.[1] ?? rawPath;
    if (!allowed.has(path)) throw new ScimValidationError("SCIM patch path is unsupported");
    if (filtered) {
      if (op !== "remove") throw new ScimValidationError("filtered SCIM patch only supports remove");
      const target = filtered[2]!.replace(/\\(["\\])/g, "$1");
      const current = Array.isArray(next[path]) ? next[path] as Array<Record<string, unknown>> : [];
      next[path] = current.filter((item) => item.value !== target);
      return;
    }
    if (op === "remove") {
      if (path === "members" || path === "groups") next[path] = [];
      else throw new ScimValidationError(`SCIM patch cannot remove ${path}`);
      return;
    }
    if (op === "add" && (path === "members" || path === "groups")) {
      const current = Array.isArray(next[path]) ? next[path] as Array<Record<string, unknown>> : [];
      const incoming = Array.isArray(value) ? value : [value];
      const merged = [...current, ...incoming].map((item) => object(item, `SCIM ${path} value`));
      next[path] = [...new Map(merged.map((item) => [String(item.value), item])).values()];
      return;
    }
    next[path] = structuredClone(value);
  };
  for (const raw of body.Operations) {
    const operation = object(raw, "SCIM patch operation");
    const op = boundedString(operation.op, "SCIM patch op", 16).toLowerCase();
    if (!new Set(["add", "replace", "remove"]).has(op)) {
      throw new ScimValidationError("SCIM patch op is unsupported");
    }
    const path = operation.path === undefined ? undefined : boundedString(operation.path, "SCIM patch path", 128);
    if (!path) {
      if (op === "remove") throw new ScimValidationError("SCIM remove requires a path");
      const values = object(operation.value, "SCIM patch value");
      const entries = Object.entries(values).filter(([key]) => allowed.has(key));
      if (entries.length === 0) throw new ScimValidationError("SCIM patch value has no supported fields");
      for (const [key, value] of entries) apply(op, key, value);
      continue;
    }
    apply(op, path, operation.value);
  }
  return next as T;
}

/** Postgres SCIM directory; user authority remains server-mapped and durable. */
export class DbScimDirectory implements ScimDirectory {
  private readonly tenantNamespace: string;

  constructor(
    private readonly db: Db,
    private readonly groupBindings: Record<string, ScimAuthorityBinding>,
    private readonly defaultBinding?: ScimAuthorityBinding,
  ) {
    const namespaces = [...new Set(Object.values(groupBindings).map((binding) => binding.namespace))];
    if (namespaces.length !== 1 || !namespaces[0]) {
      throw new ScimValidationError("each SCIM credential must map exactly one tenant namespace");
    }
    this.tenantNamespace = namespaces[0];
  }

  async upsertUser(user: ScimDirectoryUser): Promise<void> {
    if (user.namespace !== this.tenantNamespace) {
      throw new ScimValidationError("SCIM credential cannot provision another tenant");
    }
    const now = new Date().toISOString();
    await this.db.transaction(async (tx) => {
      const mapped = await tx.query(
        `SELECT su.user_id, u.namespace
         FROM scim_users su
         JOIN users u ON u.id = su.user_id
         WHERE su.external_id = $1 AND su.tenant_namespace = $2`,
        [user.externalId, user.namespace],
      );
      const byEmail = await tx.query(`SELECT id, namespace FROM users WHERE email = $1`, [user.email]);
      const mappedUserId = mapped.rows[0]?.user_id as string | undefined;
      const emailUserId = byEmail.rows[0]?.id as string | undefined;
      if (byEmail.rows[0] && String(byEmail.rows[0].namespace) !== user.namespace) {
        throw new ScimValidationError("SCIM email is already owned by another tenant");
      }
      if (mappedUserId && emailUserId && emailUserId !== mappedUserId) {
        throw new ScimValidationError("SCIM email is already owned by another user");
      }
      const userId = mappedUserId ?? emailUserId ?? ulid();
      if (mappedUserId || emailUserId) {
        const updated = await tx.query(
          `UPDATE users SET email = $2, display_name = $4, role = $5, status = $6
           WHERE id = $1 AND namespace = $3
           RETURNING id`,
          [
            userId,
            user.email,
            user.namespace,
            user.displayName,
            user.role,
            user.active ? "active" : "disabled",
          ],
        );
        if (updated.rows.length !== 1) {
          throw new ScimValidationError("SCIM user update crossed a tenant boundary");
        }
      } else {
        const inserted = await tx.query(
          `INSERT INTO users
             (id, email, display_name, namespace, role, password_hash, status, created_at)
           VALUES ($1, $2, $3, $4, $5, NULL, $6, $7)
           ON CONFLICT (email) DO NOTHING
           RETURNING id`,
          [
            userId,
            user.email,
            user.displayName,
            user.namespace,
            user.role,
            user.active ? "active" : "disabled",
            now,
          ],
        );
        if (inserted.rows.length !== 1) {
          throw new ScimValidationError("SCIM email is already owned by another user");
        }
      }
      await tx.query(
        `INSERT INTO scim_users (external_id, tenant_namespace, user_id, updated_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (external_id, tenant_namespace) DO UPDATE SET
           user_id = EXCLUDED.user_id, updated_at = EXCLUDED.updated_at`,
        [user.externalId, user.namespace, userId, now],
      );
    });
  }

  async replaceGroup(group: ScimDirectoryGroup): Promise<void> {
    const binding = this.groupBindings[group.externalId];
    if (!binding) throw new ScimValidationError("SCIM group has no server-side authority mapping");
    const now = new Date().toISOString();
    await this.db.transaction(async (tx) => {
      const existing = await tx.query(
        `SELECT id FROM scim_groups WHERE tenant_namespace = $1 AND external_id = $2`,
        [binding.namespace, group.externalId],
      );
      const groupId = existing.rows[0]?.id as string | undefined ?? ulid();
      await tx.query(
        `INSERT INTO scim_groups
           (id, tenant_namespace, external_id, display_name, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT (tenant_namespace, external_id) DO UPDATE SET
           display_name = EXCLUDED.display_name, updated_at = EXCLUDED.updated_at`,
        [groupId, binding.namespace, group.externalId, group.displayName, now],
      );
      const previous = await tx.query(
        `SELECT user_id FROM scim_group_members WHERE group_id = $1`, [groupId],
      );
      await tx.query(`DELETE FROM scim_group_members WHERE group_id = $1`, [groupId]);
      for (const externalId of group.memberExternalIds) {
        await tx.query(
          `INSERT INTO scim_group_members (group_id, user_id, created_at)
           SELECT $1, user_id, $3 FROM scim_users
           WHERE (external_id = $2 OR user_id = $2) AND tenant_namespace = $4
           ON CONFLICT (group_id, user_id) DO NOTHING`,
          [groupId, externalId, now, binding.namespace],
        );
      }
      const current = await tx.query(
        `SELECT user_id FROM scim_group_members WHERE group_id = $1`, [groupId],
      );
      const affected = new Set<string>([
        ...previous.rows.map((row) => String(row.user_id)),
        ...current.rows.map((row) => String(row.user_id)),
      ]);
      for (const userId of affected) await this.reconcileUserAuthority(tx, userId);
    });
  }

  private async reconcileUserAuthority(tx: Db, userId: string): Promise<void> {
    const memberships = await tx.query(
      `SELECT sg.external_id FROM scim_group_members sgm
       JOIN scim_groups sg ON sg.id = sgm.group_id
       WHERE sgm.user_id = $1 AND sg.tenant_namespace = $2`,
      [userId, this.tenantNamespace],
    );
    const bindings = memberships.rows.flatMap((row) => {
      const binding = this.groupBindings[String(row.external_id)];
      return binding ? [binding] : [];
    });
    const binding = selectAuthorityBinding(bindings, this.defaultBinding);
    if (!binding) {
      await tx.query(
        `UPDATE users SET status = 'disabled' WHERE id = $1 AND namespace = $2`,
        [userId, this.tenantNamespace],
      );
      return;
    }
    await tx.query(
      `UPDATE users SET namespace = $2, role = $3, status = 'active'
       WHERE id = $1 AND namespace = $2`,
      [userId, binding.namespace, binding.role],
    );
  }

  async getUser(id: string): Promise<ScimUserResource | null> {
    const result = await this.db.query(
      `SELECT su.external_id, su.user_id, u.email, u.display_name, u.status,
         COALESCE(jsonb_agg(DISTINCT sg.external_id)
           FILTER (WHERE sg.external_id IS NOT NULL), '[]'::jsonb) AS groups
       FROM scim_users su
       JOIN users u ON u.id = su.user_id
       LEFT JOIN scim_group_members sgm ON sgm.user_id = u.id
       LEFT JOIN scim_groups sg ON sg.id = sgm.group_id AND sg.tenant_namespace = su.tenant_namespace
       WHERE su.tenant_namespace = $1 AND su.user_id = $2
       GROUP BY su.external_id, su.user_id, u.email, u.display_name, u.status`,
      [this.tenantNamespace, id],
    );
    return result.rows[0] ? userRow(result.rows[0] as Record<string, unknown>) : null;
  }

  async listUsers(filter?: string): Promise<ScimUserResource[]> {
    const parsed = parseFilter(filter, new Set(["externalId", "userName"]));
    const params: unknown[] = [this.tenantNamespace];
    const filterSql = parsed
      ? parsed.attribute === "externalId"
        ? `AND su.external_id = $2`
        : `AND LOWER(u.email) = LOWER($2)`
      : "";
    if (parsed) params.push(parsed.value);
    const result = await this.db.query(
      `SELECT su.external_id, su.user_id, u.email, u.display_name, u.status,
         COALESCE(jsonb_agg(DISTINCT sg.external_id)
           FILTER (WHERE sg.external_id IS NOT NULL), '[]'::jsonb) AS groups
       FROM scim_users su
       JOIN users u ON u.id = su.user_id
       LEFT JOIN scim_group_members sgm ON sgm.user_id = u.id
       LEFT JOIN scim_groups sg ON sg.id = sgm.group_id AND sg.tenant_namespace = su.tenant_namespace
       WHERE su.tenant_namespace = $1 ${filterSql}
       GROUP BY su.external_id, su.user_id, u.email, u.display_name, u.status
       ORDER BY su.user_id`,
      params,
    );
    return (result.rows as Record<string, unknown>[]).map(userRow);
  }

  async deleteUser(id: string): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      const mapped = await tx.query(
        `DELETE FROM scim_users WHERE tenant_namespace = $1 AND user_id = $2 RETURNING user_id`,
        [this.tenantNamespace, id],
      );
      if (mapped.rows.length === 0) return false;
      await tx.query(`DELETE FROM scim_group_members WHERE user_id = $1`, [id]);
      await tx.query(`UPDATE users SET status = 'disabled' WHERE id = $1 AND namespace = $2`,
        [id, this.tenantNamespace]);
      return true;
    });
  }

  async getGroup(id: string): Promise<ScimGroupResource | null> {
    const result = await this.db.query(
      `SELECT sg.id, sg.external_id, sg.display_name,
         COALESCE(jsonb_agg(DISTINCT sgm.user_id)
           FILTER (WHERE sgm.user_id IS NOT NULL), '[]'::jsonb) AS members
       FROM scim_groups sg
       LEFT JOIN scim_group_members sgm ON sgm.group_id = sg.id
       WHERE sg.tenant_namespace = $1 AND sg.id = $2
       GROUP BY sg.id, sg.external_id, sg.display_name`,
      [this.tenantNamespace, id],
    );
    return result.rows[0] ? groupRow(result.rows[0] as Record<string, unknown>) : null;
  }

  async listGroups(filter?: string): Promise<ScimGroupResource[]> {
    const parsed = parseFilter(filter, new Set(["externalId", "displayName"]));
    const params: unknown[] = [this.tenantNamespace];
    const filterSql = parsed
      ? parsed.attribute === "externalId"
        ? `AND sg.external_id = $2`
        : `AND sg.display_name = $2`
      : "";
    if (parsed) params.push(parsed.value);
    const result = await this.db.query(
      `SELECT sg.id, sg.external_id, sg.display_name,
         COALESCE(jsonb_agg(DISTINCT sgm.user_id)
           FILTER (WHERE sgm.user_id IS NOT NULL), '[]'::jsonb) AS members
       FROM scim_groups sg
       LEFT JOIN scim_group_members sgm ON sgm.group_id = sg.id
       WHERE sg.tenant_namespace = $1 ${filterSql}
       GROUP BY sg.id, sg.external_id, sg.display_name
       ORDER BY sg.id`,
      params,
    );
    return (result.rows as Record<string, unknown>[]).map(groupRow);
  }

  async deleteGroup(id: string): Promise<boolean> {
    return this.db.transaction(async (tx) => {
      const members = await tx.query(
        `SELECT sgm.user_id
         FROM scim_group_members sgm
         JOIN scim_groups sg ON sg.id = sgm.group_id
         WHERE sg.tenant_namespace = $1 AND sg.id = $2`,
        [this.tenantNamespace, id],
      );
      const result = await tx.query(
        `DELETE FROM scim_groups WHERE tenant_namespace = $1 AND id = $2 RETURNING id`,
        [this.tenantNamespace, id],
      );
      if (result.rows.length !== 1) return false;
      for (const row of members.rows) {
        await this.reconcileUserAuthority(tx, String(row.user_id));
      }
      return true;
    });
  }
}

function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value === "string") {
    try { return stringArray(JSON.parse(value)); } catch { return []; }
  }
  return [];
}

function userRow(row: Record<string, unknown>): ScimUserResource {
  return {
    schemas: [SCIM_USER_SCHEMA], id: String(row.user_id), externalId: String(row.external_id),
    userName: String(row.email), displayName: String(row.display_name),
    active: String(row.status) === "active",
    groups: stringArray(row.groups).map((value) => ({ value })),
  };
}

function groupRow(row: Record<string, unknown>): ScimGroupResource {
  return {
    schemas: [SCIM_GROUP_SCHEMA], id: String(row.id), externalId: String(row.external_id),
    displayName: String(row.display_name),
    members: stringArray(row.members).map((value) => ({ value })),
  };
}

function parseFilter(
  filter: string | undefined,
  allowed: Set<string>,
): { attribute: string; value: string } | null {
  if (!filter) return null;
  const match = /^([A-Za-z][A-Za-z0-9]*)\s+eq\s+"((?:[^"\\]|\\.)*)"$/i.exec(filter.trim());
  if (!match || !match[1] || !match[2] || !allowed.has(match[1])) {
    throw new ScimValidationError("SCIM filter is unsupported");
  }
  return { attribute: match[1], value: match[2].replace(/\\(["\\])/g, "$1") };
}
