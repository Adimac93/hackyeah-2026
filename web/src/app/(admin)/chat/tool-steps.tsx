"use client";

import { useState } from "react";

import { cellText, sortRows } from "@/lib/tool-steps";
import type { StepResult, ToolStep } from "@/lib/tool-steps";

const REDACTED = /^\[REDACTED[^\]]*\]$/;
/** Not a column name a query can produce (columns are SQL identifiers). */
const ROW_KEY = "\u0000row";

/** The SQL of a query, or the arguments as JSON. */
function argumentsText(step: ToolStep): string {
  const callArguments = step.arguments;
  if (
    typeof callArguments === "object" &&
    callArguments !== null &&
    "sql" in callArguments &&
    typeof callArguments.sql === "string"
  ) {
    return callArguments.sql;
  }
  return JSON.stringify(callArguments, null, 2);
}

/** One call, collapsed to its summary; expands to the SQL or arguments and any refusal. */
function StepLine({ step }: { step: ToolStep }) {
  const refused = step.status === "refused";
  return (
    <details className="group rounded-lg border border-zinc-800 bg-zinc-900/60 text-xs">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-1.5 text-zinc-300 select-none hover:text-zinc-100">
        {refused ? (
          <span
            aria-label="refused"
            className="rounded-sm bg-red-500/10 px-1.5 py-0.5 text-[9px] leading-none font-semibold tracking-[0.1em] text-red-300 uppercase ring-1 ring-red-500/30 ring-inset"
          >
            Refused
          </span>
        ) : (
          <span
            aria-label="ok"
            className="bg-cogut h-1.5 w-1.5 shrink-0 rounded-full"
          />
        )}
        <span className="font-mono text-zinc-500">{step.tool}</span>
        <span className="min-w-0 flex-1 truncate">{step.summary}</span>
        <span className="text-zinc-600 transition-transform group-open:rotate-90">
          ›
        </span>
      </summary>
      <div className="space-y-2 border-t border-zinc-800 px-3 py-2">
        <pre className="overflow-x-auto font-mono whitespace-pre-wrap text-zinc-300">
          {argumentsText(step)}
        </pre>
        {step.detail === undefined ? null : (
          <p className="text-red-300">{step.detail}</p>
        )}
        {step.resultError === undefined ? null : (
          <p className="text-amber-300">
            The rows could not be fetched ({step.resultError}).
          </p>
        )}
      </div>
    </details>
  );
}

/** Rows the gateway delivered to the user: sortable, redaction markers left visible. */
function ResultTable({ result }: { result: StepResult }) {
  const [sort, setSort] = useState<{
    column: string;
    direction: "asc" | "desc";
  } | null>(null);
  // a key per row that survives sorting: rows have no id of their own
  const keyed = result.rows.map((row, position): Record<string, unknown> => ({
    ...row,
    [ROW_KEY]: position,
  }));
  const rows =
    sort === null ? keyed : sortRows(keyed, sort.column, sort.direction);

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="max-h-96 overflow-auto">
        <table className="min-w-full text-left text-xs">
          <thead className="sticky top-0 bg-zinc-900">
            <tr>
              {result.columns.map((column) => {
                const active = sort?.column === column;
                return (
                  <th
                    key={column}
                    scope="col"
                    aria-sort={
                      active
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                    className="border-b border-zinc-800 px-3 py-2 font-mono font-semibold whitespace-nowrap text-zinc-500"
                  >
                    <button
                      type="button"
                      className="hover:text-zinc-100"
                      onClick={() => {
                        setSort({
                          column,
                          direction:
                            active && sort.direction === "asc" ? "desc" : "asc",
                        });
                      }}
                    >
                      {column}
                      {active ? (sort.direction === "asc" ? " ▲" : " ▼") : ""}
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-900">
            {rows.map((row) => (
              <tr key={String(row[ROW_KEY])} className="hover:bg-zinc-900/60">
                {result.columns.map((column) => {
                  const text = cellText(row[column]);
                  return (
                    <td
                      key={column}
                      className={`px-3 py-1.5 font-mono whitespace-nowrap ${
                        REDACTED.test(text) ? "text-amber-300" : "text-zinc-200"
                      }`}
                    >
                      {text}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="border-t border-zinc-800 px-3 py-2 font-serif text-xs text-zinc-500 italic">
        {result.row_count} {result.row_count === 1 ? "row" : "rows"} · delivered
        to you by the AI Control Layer; the model saw only the row count
      </p>
    </div>
  );
}

/** What the model asked the data tools to do, and the rows that came back to the user. */
export function ToolSteps({ steps }: { steps: ToolStep[] }) {
  if (steps.length === 0) {
    return null;
  }
  return (
    <div className="w-full max-w-[85%] space-y-2">
      {steps.map((step, index) => (
        <StepLine key={`${step.tool}-${String(index)}`} step={step} />
      ))}
      {steps.map((step, index) =>
        step.result === undefined ? null : (
          <ResultTable key={`result-${String(index)}`} result={step.result} />
        ),
      )}
    </div>
  );
}
