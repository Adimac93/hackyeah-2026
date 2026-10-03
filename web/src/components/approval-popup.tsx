"use client";

import { useEffect, useState, useTransition } from "react";

import { decideAccess } from "@/app/(admin)/approvals/actions";
import {
  TTL_CHOICES,
  applyEvent,
  parseApprovalEvent,
  secondsLeft,
} from "@/lib/approvals";
import type { AccessRequest } from "@/lib/approvals";

import { Field, Select, inputClass } from "./ui";

/**
 * Agent access requests, pushed live from the gateway. Mounted once in the
 * console layout so it pops over whatever page the analyst is on.
 */
export function ApprovalPopup({ canDecide }: { canDecide: boolean }) {
  const [queue, setQueue] = useState<AccessRequest[]>([]);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    // EventSource reconnects by itself; the gateway replays pending requests.
    const source = new EventSource("/api/approvals/stream");
    source.addEventListener("message", (message: MessageEvent<string>) => {
      const event = parseApprovalEvent(message.data);
      if (event !== null) {
        setQueue((previous) => applyEvent(previous, event));
      }
    });
    return () => {
      source.close();
    };
  }, []);

  const pending = queue.filter((r) => secondsLeft(r, now) > 0);
  const current = pending.at(0);

  useEffect(() => {
    if (current === undefined) {
      return;
    }
    const tick = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    const title = document.title;
    document.title = `(${String(pending.length)}) Access request — ${title}`;
    return () => {
      clearInterval(tick);
      document.title = title;
    };
  }, [current, pending.length]);

  if (current === undefined) {
    return null;
  }
  return (
    <RequestDialog
      key={current.id}
      request={current}
      waiting={pending.length - 1}
      seconds={secondsLeft(current, now)}
      canDecide={canDecide}
      onDone={() => {
        setQueue((previous) => previous.filter((r) => r.id !== current.id));
      }}
    />
  );
}

function RequestDialog({
  request,
  waiting,
  seconds,
  canDecide,
  onDone,
}: {
  request: AccessRequest;
  waiting: number;
  seconds: number;
  canDecide: boolean;
  onDone: () => void;
}) {
  const [ttl, setTtl] = useState(String(request.ttl_minutes));
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();

  const decide = (decision: "approve" | "deny") => {
    startTransition(async () => {
      const result = await decideAccess(
        request.id,
        decision,
        Number(ttl),
        note,
      );
      if (result.error === null) {
        onDone();
      } else {
        setError(result.error);
      }
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-title"
    >
      <div className="w-full max-w-lg space-y-5 rounded-xl border border-amber-500/40 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium tracking-wide text-amber-400 uppercase">
              Agent access request
            </p>
            <h2
              id="approval-title"
              className="mt-1 text-lg font-semibold text-zinc-50"
            >
              <span className="font-mono">{request.principal}</span> wants{" "}
              <span className="font-mono text-amber-300">{request.tool}</span>
            </h2>
          </div>
          <span
            className={`shrink-0 rounded-md px-2 py-1 font-mono text-sm tabular-nums ring-1 ${
              seconds <= 20
                ? "text-red-300 ring-red-500/40"
                : "text-zinc-300 ring-zinc-700"
            }`}
            title="The agent stops waiting when this reaches zero"
          >
            {seconds}s
          </span>
        </div>

        <div className="space-y-1.5">
          <p className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
            Reason given by the agent (untrusted, already scanned)
          </p>
          <p className="max-h-40 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm whitespace-pre-wrap text-zinc-200">
            {request.reason}
          </p>
        </div>

        {canDecide ? (
          <div className="grid gap-4 sm:grid-cols-[8rem_1fr]">
            <Field label="Grant for">
              <Select
                value={ttl}
                onChange={(event) => {
                  setTtl(event.target.value);
                }}
                options={TTL_CHOICES.map((m) => ({
                  value: String(m),
                  label: `${String(m)} min`,
                }))}
              />
            </Field>
            <Field label="Note (optional)">
              <input
                className={inputClass}
                value={note}
                maxLength={500}
                onChange={(event) => {
                  setNote(event.target.value);
                }}
                placeholder="Shown to the agent"
              />
            </Field>
          </div>
        ) : (
          <p className="text-sm text-zinc-400">
            Your role is read-only — an admin or analyst must decide.
          </p>
        )}

        {error === null ? null : (
          <p className="text-sm text-red-300">{error}</p>
        )}

        <div className="flex items-center justify-between gap-3">
          <span className="text-xs text-zinc-500">
            {waiting > 0 ? `${String(waiting)} more waiting` : ""}
          </span>
          {canDecide ? (
            <div className="flex gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  decide("deny");
                }}
                className="rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-60"
              >
                Deny
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  decide("approve");
                }}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-60"
              >
                Approve
              </button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
