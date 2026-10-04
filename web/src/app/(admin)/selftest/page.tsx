import { PageHeader } from "@/components/ui";
import { requireMember } from "@/lib/auth";

import { SelftestRunner } from "./selftest-runner";

export default async function SelftestPage() {
  const { member } = await requireMember();
  return (
    <>
      <PageHeader
        eyebrow="Proof of controls"
        title="Self-test"
        subtitle="Sends every self-test prompt and tool call through the live gateway — its catalog, database, semantic judge and mcp-demo — and logs what each control did with it, the risk score and the time it took."
      />
      <SelftestRunner canRun={member.role === "admin"} />
    </>
  );
}
