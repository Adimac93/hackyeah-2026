// Tool steps of a console chat reply: what the model asked the gateway's MCP tools to do,
// and the rows the gateway delivered to the user (the model never sees them). Pure, so the
// mapping is unit-testable; the HTTP lives in `llm/providers.ts`.
//
// Input is the gateway's `x_control_layer.tool_calls` (`gateway/src/proxy/agent.rs`):
// `{ tool, arguments, status: "ok" | "refused", trace_id, result_id, content }`.

/** Rows of one `resources__query`, from `GET /v1/results/{id}`, already redacted. */
export interface StepResult {
  columns: string[];
  row_count: number;
  rows: Record<string, unknown>[];
}

/** One stored step, as `chat_messages.tool_calls` holds it. */
export interface ToolStep {
  tool: string;
  status: "ok" | "refused";
  /** one line for the collapsed view */
  summary: string;
  arguments: unknown;
  /** what the tool said, when it refused (shown expanded) */
  detail?: string;
  /** where the rows wait; dropped once fetched */
  resultId?: string;
  result?: StepResult;
  /** set when the rows could not be fetched */
  resultError?: string;
}

const MAX_DETAIL = 500;
const MAX_SQL_IN_SUMMARY = 80;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function oneLine(text: string, max: number): string {
  const flat = text.replaceAll(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function refusalOf(content: string): string {
  return content.replace(/^refused:\s*/, "");
}

function summarise(
  tool: string,
  status: ToolStep["status"],
  callArguments: unknown,
  content: string,
): string {
  const input = isRecord(callArguments) ? callArguments : {};
  const ack = parseJson(content);
  switch (tool) {
    case "resources__query": {
      const sql =
        typeof input.sql === "string"
          ? oneLine(input.sql, MAX_SQL_IN_SUMMARY)
          : "query";
      if (status === "refused") {
        return `${sql} → refused`;
      }
      const rows =
        isRecord(ack) && typeof ack.row_count === "number"
          ? ack.row_count
          : null;
      return rows === null
        ? sql
        : `${sql} → ${String(rows)} ${rows === 1 ? "row" : "rows"}`;
    }
    case "resources__describe": {
      const tables = Array.isArray(input.tables)
        ? input.tables.filter((t): t is string => typeof t === "string")
        : [];
      const what =
        tables.length === 0 ? "list tables" : `describe ${tables.join(", ")}`;
      return status === "refused" ? `${what} → refused` : what;
    }
    case "control__request_access": {
      const target =
        typeof input.table === "string"
          ? `table ${input.table}`
          : typeof input.tool === "string"
            ? input.tool
            : "access";
      const outcome =
        status === "refused"
          ? "refused"
          : isRecord(ack) && typeof ack.status === "string"
            ? ack.status.replaceAll("_", " ")
            : "answered";
      return `requested ${target} → ${outcome}`;
    }
    default: {
      return status === "refused" ? `${tool} → refused` : tool;
    }
  }
}

/** The gateway's `tool_calls` as steps. Anything malformed is dropped. */
export function toSteps(toolCalls: unknown): ToolStep[] {
  if (!Array.isArray(toolCalls)) {
    return [];
  }
  const steps: ToolStep[] = [];
  for (const call of toolCalls) {
    if (!isRecord(call) || typeof call.tool !== "string") {
      continue;
    }
    const status = call.status === "ok" ? "ok" : "refused";
    const content = typeof call.content === "string" ? call.content : "";
    const step: ToolStep = {
      tool: call.tool,
      status,
      summary: summarise(call.tool, status, call.arguments, content),
      arguments: call.arguments ?? null,
    };
    if (status === "refused" && content !== "") {
      step.detail = oneLine(refusalOf(content), MAX_DETAIL);
    }
    if (typeof call.result_id === "string" && call.result_id !== "") {
      step.resultId = call.result_id;
    }
    steps.push(step);
  }
  return steps;
}

/** A `GET /v1/results/{id}` body, or null when it is not one. */
export function parseResult(body: unknown): StepResult | null {
  if (
    !isRecord(body) ||
    !Array.isArray(body.columns) ||
    !Array.isArray(body.rows) ||
    typeof body.row_count !== "number"
  ) {
    return null;
  }
  return {
    columns: body.columns.filter((c): c is string => typeof c === "string"),
    row_count: body.row_count,
    rows: body.rows.filter(isRecord),
  };
}

/**
 * Attach fetched rows to their steps. `fetched` maps a result id to its rows, or to null
 * when the fetch failed; a step whose rows are missing says so instead of failing the reply.
 */
export function mergeResults(
  steps: ToolStep[],
  fetched: Map<string, StepResult | null>,
): ToolStep[] {
  return steps.map((step) => {
    if (step.resultId === undefined) {
      return step;
    }
    const { resultId, ...rest } = step;
    const result = fetched.get(resultId);
    return result === undefined || result === null
      ? { ...rest, resultError: "result unavailable" }
      : { ...rest, result };
  });
}

/** Stored steps read back from `chat_messages.tool_calls`; anything else is no steps. */
export function storedSteps(value: unknown): ToolStep[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (step): step is ToolStep =>
      isRecord(step) &&
      typeof step.tool === "string" &&
      (step.status === "ok" || step.status === "refused") &&
      typeof step.summary === "string",
  );
}

/** A cell as text: `[REDACTED:…]` markers stay visible, objects become JSON. */
export function cellText(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value);
}

/** Sort rows by one column: numbers numerically, everything else as text; empty cells last. */
export function sortRows(
  rows: Record<string, unknown>[],
  column: string,
  direction: "asc" | "desc",
): Record<string, unknown>[] {
  const sign = direction === "asc" ? 1 : -1;
  return rows.toSorted((a, b) => {
    const left = a[column];
    const right = b[column];
    const leftEmpty = left === null || left === undefined || left === "";
    const rightEmpty = right === null || right === undefined || right === "";
    if (leftEmpty || rightEmpty) {
      return leftEmpty === rightEmpty ? 0 : leftEmpty ? 1 : -1;
    }
    if (typeof left === "number" && typeof right === "number") {
      return (left - right) * sign;
    }
    return (
      cellText(left).localeCompare(cellText(right), undefined, {
        numeric: true,
      }) * sign
    );
  });
}
