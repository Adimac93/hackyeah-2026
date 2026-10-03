import Link from "next/link";

import {
  ButtonLink,
  EmptyRow,
  PageHeader,
  StatusBadge,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { POLICY_STATUSES, canWrite, isReviewOverdue } from "@/lib/domain";
import type { Policy, TeamMember } from "@/lib/domain";
import { fmtDate } from "@/lib/format";

export default async function PoliciesPage({
  searchParams,
}: PageProps<"/policies">) {
  const { supabase, member } = await requireMember();
  const { status: rawStatus } = await searchParams;
  const status =
    typeof rawStatus === "string" &&
    (POLICY_STATUSES as readonly string[]).includes(rawStatus)
      ? rawStatus
      : null;

  let query = supabase
    .from("policies")
    .select("*")
    .order("category")
    .order("title");
  if (status !== null) {
    query = query.eq("status", status);
  }
  const [{ data }, { data: team }] = await Promise.all([
    query,
    supabase.from("team_members").select("user_id, email, full_name"),
  ]);
  const policies = (data ?? []) as Policy[];
  const names = new Map(
    ((team ?? []) as TeamMember[]).map((m) => [
      m.user_id,
      m.full_name ?? m.email,
    ]),
  );

  const tabs = [
    { label: "All", value: null },
    ...POLICY_STATUSES.map((s) => ({ label: s, value: s })),
  ];

  return (
    <>
      <PageHeader
        title="Company policies"
        subtitle="Security policies every employee is bound by"
        actions={
          canWrite(member.role) && (
            <ButtonLink href="/policies/new">New policy</ButtonLink>
          )
        }
      />

      <div className="mb-4 flex gap-1">
        {tabs.map((t) => (
          <Link
            key={t.label}
            href={t.value ? `/policies?status=${t.value}` : "/policies"}
            className={`rounded-lg px-3 py-1.5 text-sm capitalize ${
              status === t.value
                ? "bg-zinc-800 text-zinc-50"
                : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {t.label}
          </Link>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60">
        <table className={tableClass}>
          <thead className="border-b border-zinc-800">
            <tr>
              <th className={thClass}>Policy</th>
              <th className={`${thClass} hidden md:table-cell`}>Category</th>
              <th className={thClass}>Status</th>
              <th className={`${thClass} hidden lg:table-cell`}>Owner</th>
              <th className={`${thClass} text-right`}>Next review</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {policies.length === 0 && (
              <EmptyRow cols={5}>No policies here yet.</EmptyRow>
            )}
            {policies.map((p) => (
              <tr key={p.id} className="hover:bg-zinc-800/40">
                <td className={tdClass}>
                  <Link
                    href={`/policies/${p.id}`}
                    className="font-medium text-zinc-100 hover:underline"
                  >
                    {p.title}
                  </Link>
                  <span className="ml-2 text-xs text-zinc-500">
                    v{p.version}
                  </span>
                  {p.summary ? (
                    <p className="max-w-xl truncate text-xs text-zinc-500">
                      {p.summary}
                    </p>
                  ) : null}
                </td>
                <td className={`${tdClass} hidden text-zinc-400 md:table-cell`}>
                  {p.category}
                </td>
                <td className={tdClass}>
                  <StatusBadge status={p.status} />
                </td>
                <td className={`${tdClass} hidden text-zinc-400 lg:table-cell`}>
                  {p.owner_id === null ? "—" : (names.get(p.owner_id) ?? "—")}
                </td>
                <td
                  className={`${tdClass} text-right text-xs whitespace-nowrap ${isReviewOverdue(p) ? "font-medium text-amber-400" : "text-zinc-500"}`}
                >
                  {isReviewOverdue(p) && "Overdue · "}
                  {fmtDate(p.review_due)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
