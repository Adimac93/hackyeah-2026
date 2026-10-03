// Server-only: talks to the gateway's admin API as the `secops-console`
// principal (GATEWAY_ADMIN_KEY). Never import from a client component.

export function gatewayAdmin(): { base: string; key: string } | null {
  const base = (process.env.GATEWAY_URL ?? "").trim().replace(/\/+$/, "");
  const key = (process.env.GATEWAY_ADMIN_KEY ?? "").trim();
  if (base === "" || key === "") {
    return null;
  }
  return { base, key };
}
