import { ActionForm } from "@/components/action-form";
import {
  Card,
  Field,
  PageHeader,
  Select,
  StatusBadge,
  inputClass,
  tableClass,
  tdClass,
  thClass,
} from "@/components/ui";
import { requireMember } from "@/lib/auth";
import { TEAM_ROLES } from "@/lib/domain";
import type { TeamMember } from "@/lib/domain";
import { fmtDate } from "@/lib/format";

import { addMember, changeRole, removeMember } from "./actions";

const ROLE_HELP: Record<string, string> = {
  admin: "Everything, including team management",
  analyst: "Manage incidents and policies",
  viewer: "Read-only",
  developer: "AI security assistant only",
};

export default async function TeamPage() {
  const { supabase, member } = await requireMember();
  const { data } = await supabase
    .from("team_members")
    .select("*")
    .order("created_at");
  const team = (data ?? []) as TeamMember[];
  const isAdmin = member.role === "admin";

  return (
    <>
      <PageHeader
        title="Security team"
        subtitle="Who can access this console, and what they can do"
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60 xl:col-span-2">
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>Member</th>
                <th className={thClass}>Role</th>
                <th className={`${thClass} hidden sm:table-cell`}>Since</th>
                {isAdmin ? <th className={thClass} /> : null}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {team.map((m) => {
                const self = m.user_id === member.user_id;
                return (
                  <tr key={m.user_id}>
                    <td className={tdClass}>
                      <p className="text-zinc-100">
                        {m.full_name ?? m.email}
                        {self ? (
                          <span className="ml-2 text-xs text-zinc-500">
                            (you)
                          </span>
                        ) : null}
                      </p>
                      {m.full_name === null ? null : (
                        <p className="text-xs text-zinc-500">{m.email}</p>
                      )}
                    </td>
                    <td className={tdClass}>
                      {isAdmin && !self ? (
                        <ActionForm
                          action={changeRole.bind(null, m.user_id)}
                          submitLabel="Set"
                          className="flex items-center gap-2"
                        >
                          <select
                            name="role"
                            defaultValue={m.role}
                            className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm"
                          >
                            {TEAM_ROLES.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        </ActionForm>
                      ) : (
                        <StatusBadge status={m.role} />
                      )}
                    </td>
                    <td
                      className={`${tdClass} hidden text-xs text-zinc-500 sm:table-cell`}
                    >
                      {fmtDate(m.created_at)}
                    </td>
                    {isAdmin ? (
                      <td className={`${tdClass} text-right`}>
                        {!self && (
                          <form action={removeMember.bind(null, m.user_id)}>
                            <button className="text-xs text-red-400 hover:text-red-300">
                              Remove
                            </button>
                          </form>
                        )}
                      </td>
                    ) : null}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="space-y-6">
          {isAdmin ? (
            <Card title="Add team member">
              <ActionForm
                action={addMember}
                submitLabel="Grant access"
                pendingLabel="Granting…"
              >
                <Field
                  label="Email"
                  hint="They must have created an account on the sign-in page first."
                >
                  <input
                    name="email"
                    type="email"
                    required
                    className={inputClass}
                    placeholder="analyst@company.com"
                  />
                </Field>
                <Field label="Role">
                  <Select
                    name="role"
                    defaultValue="analyst"
                    options={TEAM_ROLES}
                  />
                </Field>
              </ActionForm>
            </Card>
          ) : null}
          <Card title="Roles">
            <dl className="space-y-3 text-sm">
              {TEAM_ROLES.map((r) => (
                <div key={r} className="flex items-center gap-3">
                  <dt className="w-20">
                    <StatusBadge status={r} />
                  </dt>
                  <dd className="text-zinc-400">{ROLE_HELP[r]}</dd>
                </div>
              ))}
            </dl>
          </Card>
        </div>
      </div>
    </>
  );
}
