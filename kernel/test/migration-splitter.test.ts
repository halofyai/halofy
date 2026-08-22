/**
 * splitStatements() contract.
 *
 * The runner executes one statement per query() call, so this splitter decides
 * what a statement IS. It used to be `split(";")`, which is correct only while
 * no migration carries a semicolon inside a literal or a dollar-quoted body.
 * Migration 76 carries a PL/pgSQL DO block, and a naive split tore it apart at
 * its first internal semicolon — the backend then rejected the fragment with
 * "unterminated dollar-quoted string".
 *
 * These cases pin the boundary conditions so the splitter cannot regress to a
 * form that silently mangles a block.
 */

import { describe, expect, it } from "vitest";

import { MIGRATIONS, splitStatements } from "../src/db/migrations.js";

describe("splitStatements", () => {
  it("splits ordinary statements on top-level semicolons", () => {
    expect(splitStatements("SELECT 1; SELECT 2")).toEqual(["SELECT 1", "SELECT 2"]);
  });

  it("drops empty fragments from trailing and repeated separators", () => {
    expect(splitStatements("SELECT 1;;  ; SELECT 2;")).toEqual(["SELECT 1", "SELECT 2"]);
  });

  it("keeps a semicolon inside a single-quoted literal", () => {
    const sql = "INSERT INTO t VALUES ('a;b'); SELECT 1";
    expect(splitStatements(sql)).toEqual(["INSERT INTO t VALUES ('a;b')", "SELECT 1"]);
  });

  it("treats '' inside a literal as an escaped quote, not a close", () => {
    const sql = "INSERT INTO t VALUES ('it''s; fine'); SELECT 1";
    expect(splitStatements(sql)).toEqual(["INSERT INTO t VALUES ('it''s; fine')", "SELECT 1"]);
  });

  it("keeps a whole dollar-quoted block together", () => {
    const sql = "DO $x$ BEGIN a; b; END $x$; SELECT 1";
    expect(splitStatements(sql)).toEqual(["DO $x$ BEGIN a; b; END $x$", "SELECT 1"]);
  });

  it("handles an anonymous $$ body", () => {
    const sql = "DO $$ BEGIN a; END $$; SELECT 1";
    expect(splitStatements(sql)).toEqual(["DO $$ BEGIN a; END $$", "SELECT 1"]);
  });

  it("does not treat a different tag as the close of an open body", () => {
    const sql = "DO $outer$ BEGIN x $inner$ y; END $outer$; SELECT 1";
    expect(splitStatements(sql)).toEqual([
      "DO $outer$ BEGIN x $inner$ y; END $outer$",
      "SELECT 1",
    ]);
  });

  it("leaves an unterminated body intact so the backend reports it", () => {
    // Silently splitting inside a malformed block would turn one clear backend
    // error into two confusing ones.
    expect(splitStatements("DO $x$ BEGIN a; b")).toEqual(["DO $x$ BEGIN a; b"]);
  });

  it("produces a non-empty statement list for every declared migration", () => {
    for (const migration of MIGRATIONS) {
      const statements = splitStatements(migration.sql(256));
      expect(statements.length, `migration ${migration.version} ${migration.name}`)
        .toBeGreaterThan(0);
      for (const statement of statements) {
        expect(statement.trim().length).toBeGreaterThan(0);
      }
    }
  });
});
