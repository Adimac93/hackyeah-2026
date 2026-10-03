import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  // web/Dockerfile sets this to ship a self-contained server; `pnpm dev` and
  // `pnpm start` keep the default output.
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
};

export default nextConfig;
