"use client";

import { useEffect, useState, useTransition } from "react";

import { decideAccess } from "@/app/(admin)/approvals/actions";
import {
  TTL_CHOICES,
  applyEvent,
  parseApprovalEvent,
  requestTarget,
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
  const target = requestTarget(request);
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
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#102c42]/40 p-4 backdrop-blur-[2px]"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-title"
    >
      <div className="animate-enter w-full max-w-lg overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950 shadow-[0_24px_60px_rgb(16_44_66/0.25)]">
        {/* the landing's navy "event" card */}
        <div className="bg-navy p-5 text-[#fafaf7]">
          <div className="flex items-center justify-between gap-3 text-[10px] font-semibold tracking-[0.12em] text-[#a8cada] uppercase">
            <span>Agent access request</span>
            <span className="flex items-center gap-2">
              <span className="rounded-sm bg-[#a94d3f] px-2 py-1 text-[#fafaf7]">
                Awaiting decision
              </span>
              <span
                className={`rounded-sm px-2 py-1 font-mono text-[11px] tracking-normal tabular-nums ring-1 ${
                  seconds <= 20
                    ? "text-[#f2cfc6] ring-[#a94d3f]"
                    : "text-[#e4ecf1] ring-[#2c5068]"
                }`}
                title="The agent stops waiting when this reaches zero"
              >
                {seconds}s
              </span>
            </span>
          </div>
          <h2
            id="approval-title"
            className="mt-5 font-mono text-[13px] leading-relaxed text-[#e4ecf1]"
          >
            <span className="rounded-sm bg-[#20455c] px-1.5 py-0.5">
              {request.principal}
            </span>{" "}
            wants {target.kind === "table" ? "table " : null}
            <span className="rounded-sm bg-[#20455c] px-1.5 py-0.5 text-[#f2cfc6]">
              {target.name}
            </span>
          </h2>
          <p className="mt-5 flex flex-wrap justify-between gap-x-3 gap-y-1 border-t border-[#2c5068] pt-3 text-[11px] text-[#c2d3de]">
            <span>
              <strong className="font-medium text-[#a8cada]">Policy</strong>{" "}
              human approval required
              {request.end_user === request.principal ? null : (
                <>
                  {" "}
                  · for{" "}
                  <span className="font-mono text-[#e4ecf1]">
                    {request.end_user}
                  </span>{" "}
                  only
                </>
              )}
            </span>
            <span>{waiting > 0 ? `${String(waiting)} more waiting` : ""}</span>
          </p>
        </div>

        <div className="space-y-5 p-6">
          <div className="space-y-1.5">
            <p className="eyebrow text-zinc-400">
              Reason given by the agent (untrusted, already scanned)
            </p>
            <p className="max-h-40 overflow-y-auto rounded-md border border-zinc-800 bg-zinc-900 p-3 text-sm whitespace-pre-wrap text-zinc-200">
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

          <div className="flex items-center justify-end gap-3">
            {canDecide ? (
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    decide("deny");
                  }}
                  className="inline-flex items-center justify-center rounded-md border border-zinc-700 px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] text-zinc-200 transition hover:bg-zinc-900 disabled:opacity-60"
                >
                  Deny
                </button>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    decide("approve");
                  }}
                  className="inline-flex items-center justify-center gap-2 rounded-md bg-emerald-500 px-4 py-2.5 text-[13px] font-semibold tracking-[0.02em] text-zinc-950 transition hover:-translate-y-px hover:bg-emerald-600 disabled:pointer-events-none disabled:opacity-50"
                >
                  Approve
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}
