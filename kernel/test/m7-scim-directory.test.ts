import { afterEach, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createDb, type Db } from "../src/db/client.js";
import { migrate } from "../src/db/migrate.js";
import {
  DbScimDirectory,
  SCIM_GROUP_SCHEMA,
  SCIM_PATCH_SCHEMA,
  SCIM_USER_SCHEMA,
  ScimProvisioningService,
  ScimValidationError,
} from "../src/iam/scim.js";

const opened: Db[] = [];
afterEach(async () => Promise.all(opened.splice(0).map((db) => db.close())));

it("persists tenant-scoped SCIM users/groups and supports lifecycle operations", async () => {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 3 }));
  opened.push(db);
  await migrate(db, 3);
  const defaultBinding = { namespace: "acme", role: "member" as const };
  const groups = {
    employees: defaultBinding,
    admins: { namespace: "acme", role: "admin" as const },
  };
  const service = new ScimProvisioningService(
    new DbScimDirectory(db, groups, defaultBinding), { groups, defaultBinding },
  );

  const user = await service.provisionUser({
    schemas: [SCIM_USER_SCHEMA], externalId: "idp-user-1", userName: "user@acme.test",
    displayName: "First User",
    active: true,
  });
  expect(user.id).not.toBe("idp-user-1");
  expect((await service.listUsers('externalId eq "idp-user-1"'))[0]?.id).toBe(user.id);

  const second = await service.provisionUser({
    schemas: [SCIM_USER_SCHEMA], externalId: "idp-user-2", userName: "second@acme.test",
    displayName: "Second User",
    active: true,
  });

  const group = await service.provisionGroup({
    schemas: [SCIM_GROUP_SCHEMA], externalId: "employees", displayName: "Employees",
    members: [{ value: user.id }],
  });
  expect((await service.getGroup(group.id))?.members).toEqual([{ value: user.id }]);

  const admins = await service.provisionGroup({
    schemas: [SCIM_GROUP_SCHEMA], externalId: "admins", displayName: "Admins",
    members: [{ value: user.id }],
  });
  const added = await service.patchGroup(admins.id, {
    schemas: [SCIM_PATCH_SCHEMA],
    Operations: [{ op: "add", path: "members", value: [{ value: second.id }] }],
  });
  expect(added?.members).toEqual(expect.arrayContaining([{ value: user.id }, { value: second.id }]));
  const adminRoles = await db.query(`SELECT id, role FROM users WHERE id IN ($1, $2)`,
    [user.id, second.id]);
  expect(adminRoles.rows.map((row) => row.role)).toEqual(["admin", "admin"]);

  const removed = await service.patchGroup(admins.id, {
    schemas: [SCIM_PATCH_SCHEMA],
    Operations: [{ op: "remove", path: `members[value eq "${user.id}"]` }],
  });
  expect(removed?.members).toEqual([{ value: second.id }]);
  expect((await db.query(`SELECT role FROM users WHERE id = $1`, [user.id])).rows[0]?.role)
    .toBe("member");

  const disabled = await service.patchUser(user.id, {
    schemas: [SCIM_PATCH_SCHEMA], Operations: [{ op: "replace", path: "active", value: false }],
  });
  expect(disabled?.active).toBe(false);
  expect(await service.deleteGroup(group.id)).toBe(true);
  expect(await service.deleteGroup(admins.id)).toBe(true);
  expect(await service.deleteUser(second.id)).toBe(true);
  expect(await service.deleteUser(user.id)).toBe(true);
  expect(await service.getUser(user.id)).toBeNull();
});

it("rejects one SCIM credential spanning more than one tenant", async () => {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 3 }));
  opened.push(db);
  await migrate(db, 3);
  expect(() => new DbScimDirectory(db, {
    a: { namespace: "tenant-a", role: "member" },
    b: { namespace: "tenant-b", role: "member" },
  })).toThrow(ScimValidationError);
});

it("renames only the mapped SCIM user and rejects another tenant user's email", async () => {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 3 }));
  opened.push(db);
  await migrate(db, 3);
  const defaultBinding = { namespace: "acme", role: "member" as const };
  const groups = { employees: defaultBinding };
  const service = new ScimProvisioningService(
    new DbScimDirectory(db, groups, defaultBinding), { groups, defaultBinding },
  );

  const first = await service.provisionUser({
    schemas: [SCIM_USER_SCHEMA], externalId: "first", userName: "first@acme.test",
    displayName: "First User",
  });
  const second = await service.provisionUser({
    schemas: [SCIM_USER_SCHEMA], externalId: "second", userName: "second@acme.test",
    displayName: "Second User",
  });

  const renamed = await service.patchUser(first.id, {
    schemas: [SCIM_PATCH_SCHEMA],
    Operations: [{ op: "replace", path: "userName", value: "renamed@acme.test" }],
  });
  expect(renamed).toMatchObject({ id: first.id, userName: "renamed@acme.test" });
  expect(await service.listUsers('userName eq "first@acme.test"')).toEqual([]);

  await expect(service.patchUser(first.id, {
    schemas: [SCIM_PATCH_SCHEMA],
    Operations: [{ op: "replace", path: "userName", value: "second@acme.test" }],
  })).rejects.toThrow(ScimValidationError);
  expect(await service.getUser(first.id)).toMatchObject({ userName: "renamed@acme.test" });
  expect(await service.getUser(second.id)).toMatchObject({ userName: "second@acme.test" });
});

it("reconciles former member authority when deleting a SCIM group", async () => {
  const db = await createDb(loadConfig({ databaseUrl: "", pgliteDataDir: "", embedDim: 3 }));
  opened.push(db);
  await migrate(db, 3);
  const defaultBinding = { namespace: "acme", role: "member" as const };
  const groups = {
    employees: defaultBinding,
    admins: { namespace: "acme", role: "admin" as const },
  };
  const service = new ScimProvisioningService(
    new DbScimDirectory(db, groups, defaultBinding), { groups, defaultBinding },
  );
  const user = await service.provisionUser({
    schemas: [SCIM_USER_SCHEMA], externalId: "group-delete-user", userName: "delete@acme.test",
    displayName: "Delete User",
  });
  const admins = await service.provisionGroup({
    schemas: [SCIM_GROUP_SCHEMA], externalId: "admins", displayName: "Admins",
    members: [{ value: user.id }],
  });
  expect((await db.query(`SELECT role FROM users WHERE id = $1`, [user.id])).rows[0]?.role)
    .toBe("admin");

  expect(await service.deleteGroup(admins.id)).toBe(true);
  expect((await db.query(`SELECT role, status FROM users WHERE id = $1`, [user.id])).rows[0])
    .toMatchObject({ role: "member", status: "active" });
});
