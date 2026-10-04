"use client";

import { useEffect, useState } from "react";

import type { ToolCallSummary } from "@/lib/assistant";

interface ResultRows {
  columns: string[];
  row_count: number;
  rows: Record<string, unknown>[];
}

type Loaded =
  | { state: "loading" }
  | { state: "error"; error: string }
  | { state: "ready"; result: ResultRows };

function cell(value: unknown): string {
  if (value === null || value === undefined) {
    return "—";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value as string | number | boolean);
}

/** Rows the gateway delivered to this user for one query. Loaded on view; they expire after an hour. */
function ResultTable({ resultId }: { resultId: string }) {
  const [loaded, setLoaded] = useState<Loaded>({ state: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`/api/results/${resultId}`, {
          signal: controller.signal,
        });
        const body = (await response.json()) as ResultRows & {
          error?: string;
        };
        setLoaded(
          response.ok
            ? { state: "ready", result: body }
            : {
                state: "error",
                error: body.error ?? "Couldn't load the results.",
              },
        );
      } catch {
        if (!controller.signal.aborted) {
          setLoaded({ state: "error", error: "Couldn't load the results." });
        }
      }
    })();
    return () => {
      controller.abort();
    };
  }, [resultId]);

  if (loaded.state === "loading") {
    return <p className="text-xs text-zinc-500">Loading results…</p>;
  }
  if (loaded.state === "error") {
    return <p className="text-xs text-zinc-500">{loaded.error}</p>;
  }
  const { columns, rows } = loaded.result;
  if (rows.length === 0) {
    return <p className="text-xs text-zinc-500">No rows.</p>;
  }
  return (
    <div className="scrollbar-subtle max-h-72 overflow-auto rounded-lg ring-1 ring-zinc-700/60">
      <table className="w-full text-left text-xs whitespace-nowrap">
        <thead className="sticky top-0 bg-zinc-900 text-zinc-400">
          <tr>
            {columns.map((column) => (
              <th key={column} className="px-3 py-2 font-medium">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 text-zinc-200">
          {rows.map((row, index) => (
            // rows have no id of their own; the order is the query's
            // eslint-disable-next-line react/no-array-index-key
            <tr key={index}>
              {columns.map((column) => (
                <td key={column} className="px-3 py-1.5">
                  {cell(row[column])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The MCP tool calls behind a reply, as the access layer ran them. Query rows went to the
 * user, not the model; they show here, under the answer.
 */
export function ToolCalls({ calls }: { calls: ToolCallSummary[] }) {
  if (calls.length === 0) {
    return null;
  }
  return (
    <div className="mt-3 space-y-2 border-t border-zinc-700/60 pt-3 whitespace-normal">
      {calls.map((call, index) => (
        // the same tool may run twice in one reply; the order is the model's
        // eslint-disable-next-line react/no-array-index-key
        <div key={index} className="space-y-2">
          <p className="flex flex-wrap items-center gap-1.5 text-xs text-zinc-400">
            <span aria-hidden>{call.status === "ok" ? "🔧" : "🛡"}</span>
            <code className="text-zinc-300">{call.tool}</code>
            {call.status === "refused" ? (
              <span className="text-amber-300">
                refused{call.detail === null ? "" : `: ${call.detail}`}
              </span>
            ) : call.rowCount === null ? null : (
              <span>
                {call.rowCount} {call.rowCount === 1 ? "row" : "rows"}, shown to
                you only
              </span>
            )}
          </p>
          {call.resultId === null ? null : (
            <ResultTable resultId={call.resultId} />
          )}
        </div>
      ))}
    </div>
  );
}
