import { Field, Select, inputClass } from "@/components/ui";
import { POLICY_CATEGORIES, POLICY_STATUSES } from "@/lib/domain";
import type { Policy, TeamMember } from "@/lib/domain";

export function PolicyFields({
  policy,
  team,
  disabled,
}: {
  policy?: Policy;
  team: TeamMember[];
  disabled?: boolean;
}) {
  return (
    <fieldset disabled={disabled} className="space-y-4">
      <Field label="Title">
        <input
          name="title"
          required
          minLength={3}
          maxLength={200}
          defaultValue={policy?.title}
          className={inputClass}
        />
      </Field>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field label="Category">
          <Select
            name="category"
            defaultValue={policy?.category}
            options={POLICY_CATEGORIES}
          />
        </Field>
        <Field label="Status">
          <Select
            name="status"
            defaultValue={policy?.status ?? "draft"}
            options={POLICY_STATUSES}
          />
        </Field>
        <Field label="Owner">
          <Select
            name="owner_id"
            defaultValue={policy?.owner_id ?? ""}
            options={[
              { value: "", label: policy === undefined ? "Me" : "No owner" },
              ...team.map((m) => ({
                value: m.user_id,
                label: m.full_name ?? m.email,
              })),
            ]}
          />
        </Field>
        <Field label="Next review">
          <input
            name="review_due"
            type="date"
            defaultValue={policy?.review_due ?? ""}
            className={inputClass}
          />
        </Field>
      </div>
      <Field label="Summary">
        <input
          name="summary"
          defaultValue={policy?.summary}
          className={inputClass}
          placeholder="One sentence employees will see first"
        />
      </Field>
      <Field
        label="Policy text"
        hint="Changing the text of a published policy creates a new version."
      >
        <textarea
          name="body"
          rows={12}
          defaultValue={policy?.body}
          className={`${inputClass} font-mono`}
        />
      </Field>
    </fieldset>
  );
}
