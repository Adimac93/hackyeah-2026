"use client";

import { useEffect, useRef, useState } from "react";

import { Card, buttonClass } from "@/components/ui";

function lineClass(line: string): string {
  if (line.startsWith("[PASS]") || line === "RESULT: PASS") {
    return "text-emerald-400";
  }
  if (line.startsWith("[FAIL]") || line === "RESULT: FAIL") {
    return "text-red-400";
  }
  if (line.startsWith("===")) {
    return "text-zinc-100 font-semibold";
  }
  return "text-zinc-400";
}

/** The Perform self-test button and the log the gateway streams back while the suite runs. */
export function SelftestRunner({ canRun }: { canRun: boolean }) {
  const [log, setLog] = useState("");
  const [running, setRunning] = useState(false);
  const output = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (output.current !== null) {
      output.current.scrollTop = output.current.scrollHeight;
    }
  }, [log]);

  async function perform() {
    setRunning(true);
    setLog("");
    try {
      const response = await fetch("/api/selftest", { method: "POST" });
      if (!response.ok || response.body === null) {
        setLog(`Self-test could not start: ${await response.text()}`);
        return;
      }
      const reader = response.body
        .pipeThrough(new TextDecoderStream())
        .getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        setLog((previous) => previous + value);
      }
    } catch (error) {
      setLog(
        (previous) =>
          `${previous}\nSelf-test interrupted: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      setRunning(false);
    }
  }

  return (
    <Card
      title="Log"
      actions={
        <button
          type="button"
          className={buttonClass}
          disabled={!canRun || running}
          onClick={() => void perform()}
        >
          {running ? "Running…" : "Perform self-test"}
        </button>
      }
    >
      {canRun ? null : (
        <p className="mb-3 text-sm text-zinc-500">
          Only a security team admin can run the self-test.
        </p>
      )}
      <pre
        ref={output}
        className="max-h-[70vh] overflow-auto font-mono text-xs leading-5 whitespace-pre-wrap"
      >
        {log === "" ? (
          <span className="text-zinc-600">
            {running ? "Starting…" : "No run yet."}
          </span>
        ) : (
          log.split("\n").map((line, index) => (
            // eslint-disable-next-line react/no-array-index-key -- the log only grows; a line never moves
            <div key={index} className={lineClass(line)}>
              {line === "" ? " " : line}
            </div>
          ))
        )}
      </pre>
    </Card>
  );
}
