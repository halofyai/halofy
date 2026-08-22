/**
 * CSV parsing + deterministic per-table aggregates for FilesystemConnector.
 *
 * A CSV row is already an atomic, structured fact — it does not need an LLM
 * to "extract" it (that's what produced whole-file blob facts and 15s
 * extraction timeouts before this). Each row becomes one small verbatim fact
 * directly. A handful of tables also get a few computed aggregate facts
 * (top customers, low stock, best sellers, ...) since no amount of per-row
 * search resolves a ranking question — the arithmetic has to happen once, at
 * import time, in code.
 *
 * Pure functions only — no I/O, no kernel imports (D10).
 */

export interface CsvTable {
  header: string[];
  rows: Record<string, string>[];
}

/** RFC4180-ish CSV parser: quoted fields, embedded commas, doubled-quote escapes. */
export function parseCsv(text: string): CsvTable {
  const rows: string[][] = [];
  let field = "";
  let row: string[] = [];
  let inQuotes = false;
  let i = 0;

  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    pushField();
    rows.push(row);
    row = [];
  };

  while (i < text.length) {
    const c = text[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      field += c;
      i += 1;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }
    if (c === ",") {
      pushField();
      i += 1;
      continue;
    }
    if (c === "\r") {
      i += 1;
      continue;
    }
    if (c === "\n") {
      pushRow();
      i += 1;
      continue;
    }
    field += c;
    i += 1;
  }
  if (inQuotes) throw new Error("CSV contains an unterminated quoted field");
  if (field.length > 0 || row.length > 0) pushRow();
  // A trailing newline leaves one bogus single-empty-field row — drop it.
  while (rows.length > 0) {
    const last = rows[rows.length - 1]!;
    if (last.length === 1 && last[0] === "") rows.pop();
    else break;
  }

  const header = rows[0] ?? [];
  const dataRows = rows.slice(1).map((r) => {
    const rec: Record<string, string> = {};
    header.forEach((h, idx) => {
      rec[h] = r[idx] ?? "";
    });
    return rec;
  });
  return { header, rows: dataRows };
}

/** Compact "key: value, key: value" fact string for one row — small, embeds cleanly. */
export function rowToFact(row: Record<string, string>): string {
  return Object.entries(row)
    .filter(([, v]) => v !== "")
    .map(([k, v]) => `${k}: ${v}`)
    .join(", ");
}

/**
 * Stable per-row id: every table in this schema family leads with an id
 * column (sku, customer_id, order_id, ...) — use its value. Falls back to a
 * positional index so a schema without a leading id column still gets a
 * stable-within-this-parse key.
 */
export function rowKey(header: string[], row: Record<string, string>, index: number): string {
  const first = header[0];
  const value = first ? row[first] : "";
  return value && value.length > 0 ? value : `row${index}`;
}

function parseNum(v: string | undefined): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Deterministic, zero-LLM aggregate facts for tables where a ranking answer needs real arithmetic. */
export function aggregateFacts(basename: string, table: CsvTable): string[] {
  switch (basename.toLowerCase()) {
    case "customers":
      return topCustomersFact(table);
    case "inventory":
      return lowStockFact(table);
    case "order_items":
      return bestSellersFact(table);
    case "employee_shifts":
      return lateShiftsFact(table);
    case "campaign_performance":
      return topCampaignsFact(table);
    default:
      return [];
  }
}

function topCustomersFact(table: CsvTable): string[] {
  const ranked = table.rows
    .filter((r) => r.lifetime_value !== undefined && r.lifetime_value !== "")
    .sort((a, b) => parseNum(b.lifetime_value) - parseNum(a.lifetime_value))
    .slice(0, 3);
  if (ranked.length === 0) return [];
  const parts = ranked.map((r) => {
    const name = [r.first_name, r.last_name].filter(Boolean).join(" ") || r.customer_id || "unknown";
    return `${name} (${r.customer_id ?? "?"}) - lifetime value ${r.lifetime_value}, segment ${r.segment || "unknown"}`;
  });
  return [`Top customers by lifetime value: ${parts.join("; ")}.`];
}

function lowStockFact(table: CsvTable): string[] {
  const low = table.rows.filter((r) => parseNum(r.stock) <= parseNum(r.reorder_point));
  if (low.length === 0) return [];
  const shown = low
    .slice(0, 15)
    .map((r) => `${r.product_name || r.sku} (${r.sku ?? "?"}) - ${r.stock} left, reorder point ${r.reorder_point}`);
  const suffix = low.length > 15 ? ` (+${low.length - 15} more)` : "";
  return [`Reorder candidates - stock at or below reorder point: ${shown.join("; ")}${suffix}.`];
}

function bestSellersFact(table: CsvTable): string[] {
  const totals = new Map<string, { name: string; units: number }>();
  for (const r of table.rows) {
    const sku = r.sku;
    if (!sku) continue;
    const cur = totals.get(sku) ?? { name: r.product_name || sku, units: 0 };
    cur.units += parseNum(r.quantity);
    totals.set(sku, cur);
  }
  const ranked = [...totals.entries()].sort((a, b) => b[1].units - a[1].units).slice(0, 5);
  if (ranked.length === 0) return [];
  const parts = ranked.map(([sku, v]) => `${v.name} (${sku}) - ${v.units} units sold`);
  return [`Best selling products by units sold: ${parts.join("; ")}.`];
}

function lateShiftsFact(table: CsvTable): string[] {
  const late = table.rows.filter((r) => (r.attendance_status ?? "").toLowerCase().includes("late"));
  if (late.length === 0) return [];
  const shown = late
    .slice(0, 15)
    .map((r) => `employee ${r.employee_id ?? "?"} on ${r.shift_date ?? "?"} (${r.attendance_status})`);
  const suffix = late.length > 15 ? ` (+${late.length - 15} more)` : "";
  return [`Late or attendance-exception shifts in this dataset: ${shown.join("; ")}${suffix}.`];
}

function topCampaignsFact(table: CsvTable): string[] {
  const totals = new Map<string, { conversions: number; visits: number; revenue: number; cost: number }>();
  for (const r of table.rows) {
    const id = r.campaign_id;
    if (!id) continue;
    const cur = totals.get(id) ?? { conversions: 0, visits: 0, revenue: 0, cost: 0 };
    cur.conversions += parseNum(r.conversions);
    cur.visits += parseNum(r.website_visits);
    cur.revenue += parseNum(r.revenue);
    cur.cost += parseNum(r.cost);
    totals.set(id, cur);
  }
  const ranked = [...totals.entries()].sort((a, b) => b[1].conversions - a[1].conversions).slice(0, 3);
  if (ranked.length === 0) return [];
  const parts = ranked.map(
    ([id, v]) =>
      `${id} - ${v.conversions} conversions from ${v.visits} visits, revenue ${v.revenue.toFixed(2)}, cost ${v.cost.toFixed(2)}`,
  );
  return [`Top campaigns by conversions: ${parts.join("; ")}.`];
}
