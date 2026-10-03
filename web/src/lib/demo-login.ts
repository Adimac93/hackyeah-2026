// Server-only: the one-click "Log in as admin" button on /login, so demo judges
// don't have to create accounts. Off unless DEMO_ADMIN_LOGIN=true and both
// credentials are set. Never import from a client component.

export function demoAdmin(): { email: string; password: string } | null {
  if ((process.env.DEMO_ADMIN_LOGIN ?? "").trim().toLowerCase() !== "true") {
    return null;
  }
  const email = (process.env.DEMO_ADMIN_EMAIL ?? "").trim();
  const password = process.env.DEMO_ADMIN_PASSWORD ?? "";
  if (email === "" || password === "") {
    return null;
  }
  return { email, password };
}
