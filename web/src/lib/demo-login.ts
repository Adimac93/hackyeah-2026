// Server-only: the one-click demo sign-in buttons on /login ("Log in as admin",
// "Log in as developer"), so judges don't have to create accounts. All of
// them are off unless DEMO_ADMIN_LOGIN=true; each button also needs its own
// email and password set. Credentials stay on the server and never reach the
// browser or the repo. Never import from a client component.

export type DemoAccount = "admin" | "developer";

export const DEMO_ACCOUNTS: readonly DemoAccount[] = ["admin", "developer"];

const ENV: Record<DemoAccount, { email: string; password: string }> = {
  admin: { email: "DEMO_ADMIN_EMAIL", password: "DEMO_ADMIN_PASSWORD" },
  developer: {
    email: "DEMO_DEVELOPER_EMAIL",
    password: "DEMO_DEVELOPER_PASSWORD",
  },
};

/** The credentials of a demo account, or null when demo sign-in is off or it isn't configured. */
export function demoAccount(
  account: DemoAccount,
): { email: string; password: string } | null {
  if ((process.env.DEMO_ADMIN_LOGIN ?? "").trim().toLowerCase() !== "true") {
    return null;
  }
  const email = (process.env[ENV[account].email] ?? "").trim();
  const password = process.env[ENV[account].password] ?? "";
  if (email === "" || password === "") {
    return null;
  }
  return { email, password };
}

/** Which demo buttons to show. */
export function availableDemoAccounts(): DemoAccount[] {
  return DEMO_ACCOUNTS.filter((account) => demoAccount(account) !== null);
}
