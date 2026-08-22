import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

const CONSOLE_DIR = fileURLToPath(new URL("../console", import.meta.url));

async function consoleJavaScriptFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async (entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return consoleJavaScriptFiles(entryPath);
    return entry.isFile() && entry.name.endsWith(".js") ? [entryPath] : [];
  }));
  return nested.flat();
}

function hasExportModifier(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) &&
    (ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false);
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  return name.elements.flatMap((element) =>
    ts.isOmittedExpression(element) ? [] : bindingNames(element.name));
}

describe("console JavaScript module contracts", () => {
  it("only imports names exported by local console modules", async () => {
    const files = await consoleJavaScriptFiles(CONSOLE_DIR);
    const sources = new Map<string, ts.SourceFile>();
    const exportCache = new Map<string, Set<string>>();

    async function sourceFor(file: string): Promise<ts.SourceFile> {
      const cached = sources.get(file);
      if (cached) return cached;
      const source = ts.createSourceFile(
        file,
        await readFile(file, "utf8"),
        ts.ScriptTarget.ESNext,
        true,
        ts.ScriptKind.JS,
      );
      sources.set(file, source);
      return source;
    }

    async function exportsFor(file: string, visiting = new Set<string>()): Promise<Set<string>> {
      const cached = exportCache.get(file);
      if (cached) return cached;
      if (visiting.has(file)) return new Set();
      visiting.add(file);

      const exports = new Set<string>();
      const source = await sourceFor(file);
      for (const statement of source.statements) {
        if (ts.isExportAssignment(statement)) exports.add("default");
        if (
          (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
          hasExportModifier(statement)
        ) {
          if (statement.name) exports.add(statement.name.text);
          if (ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword)) {
            exports.add("default");
          }
        }
        if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
          for (const declaration of statement.declarationList.declarations) {
            for (const name of bindingNames(declaration.name)) exports.add(name);
          }
        }
        if (!ts.isExportDeclaration(statement)) continue;
        if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
          for (const element of statement.exportClause.elements) exports.add(element.name.text);
        } else if (!statement.exportClause && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) {
          const target = path.resolve(path.dirname(file), statement.moduleSpecifier.text);
          for (const name of await exportsFor(target, visiting)) exports.add(name);
        }
      }
      visiting.delete(file);
      exportCache.set(file, exports);
      return exports;
    }

    const errors: string[] = [];
    for (const importer of files) {
      const source = await sourceFor(importer);
      for (const statement of source.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
        const specifier = statement.moduleSpecifier.text;
        if (!specifier.startsWith(".")) continue;
        const imported = path.resolve(path.dirname(importer), specifier);
        const available = await exportsFor(imported);
        const clause = statement.importClause;
        if (clause?.name && !available.has("default")) {
          errors.push(`${path.relative(CONSOLE_DIR, importer)} imports the missing default export from ${specifier}`);
        }
        if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            const requested = element.propertyName?.text ?? element.name.text;
            if (!available.has(requested)) {
              errors.push(
                `${path.relative(CONSOLE_DIR, importer)} imports missing ${requested} from ${specifier}`,
              );
            }
          }
        }
      }
    }

    expect(errors).toEqual([]);
  });
});
