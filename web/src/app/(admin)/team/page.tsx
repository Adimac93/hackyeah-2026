import { ActionForm } from "@/components/action-form";
import { ConfirmButton } from "@/components/confirm-button";
import { InlineAction } from "@/components/inline-action";
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
import type { RegisteredUser, TeamInvite, TeamMember } from "@/lib/domain";
import { fmtDate } from "@/lib/format";

import {
  cancelInvite,
  changeRole,
  inviteMember,
  removeMember,
  sendPasswordReset,
} from "./actions";

const ROLE_HELP: Record<string, string> = {
  admin: "Everything, including team management",
  analyst: "Manage incidents and policies",
  viewer: "Read-only",
  developer: "AI security assistant only",
};

export default async function TeamPage() {
  const { supabase, member } = await requireMember();
  const isAdmin = member.role === "admin";

  // admins see every signed-up account; everyone else only the team itself
  let users: RegisteredUser[];
  let invites: TeamInvite[] = [];
  if (isAdmin) {
    const [{ data }, { data: inviteData }] = await Promise.all([
      supabase
        .rpc("registered_users")
        .overrideTypes<RegisteredUser[], { merge: false }>(),
      supabase.from("team_invites").select("*").order("created_at"),
    ]);
    users = (data ?? []) as RegisteredUser[];
    invites = (inviteData ?? []) as TeamInvite[];
  } else {
    const { data } = await supabase
      .from("team_members")
      .select("*")
      .order("created_at");
    users = ((data ?? []) as TeamMember[]).map((m) => ({
      user_id: m.user_id,
      email: m.email,
      full_name: m.full_name,
      role: m.role,
      registered_at: m.created_at,
      last_sign_in_at: null,
    }));
  }
  const pending = users.filter((u) => u.role === null).length;

  return (
    <>
      <PageHeader
        title="Security team"
        subtitle={
          isAdmin
            ? "Every registered account. Assign a role to grant access to this console."
            : "Who can access this console, and what they can do"
        }
      />

      <div className="grid gap-6 xl:grid-cols-3">
        <div className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/60 xl:col-span-2">
          {isAdmin && pending > 0 ? (
            <p className="border-b border-zinc-800 px-4 py-2.5 text-xs text-amber-300">
              {pending} {pending === 1 ? "account is" : "accounts are"} waiting
              for access.
            </p>
          ) : null}
          <table className={tableClass}>
            <thead className="border-b border-zinc-800">
              <tr>
                <th className={thClass}>User</th>
                <th className={thClass}>Role</th>
                <th className={`${thClass} hidden sm:table-cell`}>
                  {isAdmin ? "Registered" : "Since"}
                </th>
                {isAdmin ? <th className={thClass} /> : null}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {users.map((u) => {
                const self = u.user_id === member.user_id;
                return (
                  <tr key={u.user_id}>
                    <td className={tdClass}>
                      <p className="text-zinc-100">
                        {u.full_name ?? u.email}
                        {self ? (
                          <span className="ml-2 text-xs text-zinc-500">
                            (you)
                          </span>
                        ) : null}
                      </p>
                      {u.full_name === null ? null : (
                        <p className="text-xs text-zinc-500">{u.email}</p>
                      )}
                    </td>
                    <td className={tdClass}>
                      {isAdmin && !self ? (
                        <ActionForm
                          action={changeRole.bind(null, u.user_id)}
                          submitLabel={u.role === null ? "Assign" : "Set"}
                          className="flex items-center gap-2"
                        >
                          <select
                            name="role"
                            defaultValue={u.role ?? ""}
                            required
                            className="rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-sm"
                          >
                            {u.role === null ? (
                              <option value="" disabled>
                                No access
                              </option>
                            ) : null}
                            {TEAM_ROLES.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        </ActionForm>
                      ) : u.role === null ? (
                        <span className="text-xs text-zinc-500">No access</span>
                      ) : (
                        <StatusBadge status={u.role} />
                      )}
                    </td>
                    <td
                      className={`${tdClass} hidden text-xs text-zinc-500 sm:table-cell`}
                    >
                      {fmtDate(u.registered_at)}
                    </td>
                    {isAdmin ? (
                      <td className={`${tdClass} text-right`}>
                        <div className="flex flex-col items-end gap-1.5">
                          <InlineAction
                            action={sendPasswordReset.bind(null, u.email)}
                            label="Send reset link"
                            pendingLabel="Sending…"
                            showOk={false}
                          />
                          {!self && u.role !== null && (
                            <form action={removeMember.bind(null, u.user_id)}>
                              <button className="text-xs text-red-400 hover:text-red-300">
                                Revoke
                              </button>
                            </form>
                          )}
                        </div>
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
            <Card title="Invite by email">
              <ActionForm
                action={inviteMember}
                submitLabel="Invite"
                pendingLabel="Inviting…"
              >
                <Field
                  label="Email"
                  hint="No account yet? They get this role as soon as they sign up and confirm their email."
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
          {isAdmin && invites.length > 0 ? (
            <Card title={`Pending invites (${String(invites.length)})`}>
              <ul className="-my-1 divide-y divide-zinc-800 text-sm">
                {invites.map((inv) => (
                  <li
                    key={inv.email}
                    className="flex items-center justify-between gap-3 py-2"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-zinc-200">{inv.email}</p>
                      <p className="text-xs text-zinc-500">
                        Invited {fmtDate(inv.created_at)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <StatusBadge status={inv.role} />
                      <form action={cancelInvite.bind(null, inv.email)}>
                        <ConfirmButton confirmLabel="Cancel?">
                          Cancel
                        </ConfirmButton>
                      </form>
                    </div>
                  </li>
                ))}
              </ul>
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
