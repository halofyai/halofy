/**
 * Structured logger (M1 module F).
 *
 * Single-line JSON to stderr: { ts, level, msg, ...fields }. stdout stays
 * clean for the stdio MCP transport. Level filter comes from
 * HALOMEM_LOG_LEVEL (default "info") and is re-read on every emit so tests
 * and operators can flip it at runtime; an explicit `level` option pins it.
 *
 * `child(fields)` returns a logger with fields bound (e.g. op/namespace) —
 * call-site fields override bound fields on key collision.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogFields = Record<string, unknown>;

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function parseLevel(raw: string | undefined): LogLevel | null {
  if (raw === undefined) return null;
  const lowered = raw.toLowerCase();
  return lowered in LEVEL_ORDER ? (lowered as LogLevel) : null;
}

export interface LoggerOptions {
  /** Pin the level; omit to follow HALOMEM_LOG_LEVEL (default "info"). */
  level?: LogLevel;
  /** Line sink; default writes `line + "\n"` to process.stderr. */
  sink?: (line: string) => void;
  /** Fields bound into every entry (child bindings). */
  fields?: LogFields;
}

const stderrSink = (line: string): void => {
  process.stderr.write(line + "\n");
};

export class Logger {
  private readonly explicitLevel: LogLevel | undefined;
  private readonly sink: (line: string) => void;
  private readonly bound: LogFields;

  constructor(options: LoggerOptions = {}) {
    this.explicitLevel = options.level;
    this.sink = options.sink ?? stderrSink;
    this.bound = options.fields ?? {};
  }

  /** New logger with extra bound fields; inherits level pin + sink. */
  child(fields: LogFields): Logger {
    return new Logger({
      level: this.explicitLevel,
      sink: this.sink,
      fields: { ...this.bound, ...fields },
    });
  }

  debug(msg: string, fields?: LogFields): void {
    this.emit("debug", msg, fields);
  }

  info(msg: string, fields?: LogFields): void {
    this.emit("info", msg, fields);
  }

  warn(msg: string, fields?: LogFields): void {
    this.emit("warn", msg, fields);
  }

  error(msg: string, fields?: LogFields): void {
    this.emit("error", msg, fields);
  }

  private effectiveLevel(): LogLevel {
    return this.explicitLevel ?? parseLevel(process.env.HALOMEM_LOG_LEVEL) ?? "info";
  }

  private emit(level: LogLevel, msg: string, fields?: LogFields): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.effectiveLevel()]) return;
    // ts/level/msg first, then bound fields, then call-site fields (which
    // win on collision). Reserved keys cannot be shadowed.
    const entry: LogFields = {
      ...this.bound,
      ...fields,
      ts: new Date().toISOString(),
      level,
      msg,
    };
    // Reorder for readability: reserved keys lead the line.
    const { ts, level: lvl, msg: message, ...rest } = entry;
    let line: string;
    try {
      line = JSON.stringify({ ts, level: lvl, msg: message, ...rest });
    } catch {
      // Circular / non-serializable fields must never crash the caller.
      line = JSON.stringify({ ts, level: lvl, msg: message, logError: "unserializable fields dropped" });
    }
    this.sink(line);
  }
}

export function createLogger(options: LoggerOptions = {}): Logger {
  return new Logger(options);
}

/** Process-wide default logger (stderr, HALOMEM_LOG_LEVEL-filtered). */
export const log = createLogger();
