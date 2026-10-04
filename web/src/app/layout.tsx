import type { Metadata, Viewport } from "next";
import Script from "next/script";

import { THEME_SCRIPT } from "@/lib/theme";

import "./globals.css";

const GTM_ID = "GTM-WKG5T38S";
// Only production loads GTM (and the Clarity tag it carries). Clarity replays
// by fetching each page's stylesheets from its own servers, and `next dev`
// refuses those cross-origin fetches, so dev sessions replay with no CSS.
const ANALYTICS = process.env.NODE_ENV === "production";

export const metadata: Metadata = {
  title: { default: "Cogut Console", template: "%s · Cogut" },
  description:
    "Cogut is the control layer for AI agents: central policy, hybrid guardrails and a traceable audit trail.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#fafaf7" },
    { media: "(prefers-color-scheme: dark)", color: "#0b1620" },
  ],
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    // the pre-paint script sets `dark` on <html> before React hydrates
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        {/* eslint-disable-next-line react/no-danger -- static, first-party, must run before paint */}
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        {ANALYTICS ? (
          <Script id="gtm" strategy="afterInteractive">
            {`(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','${GTM_ID}');`}
          </Script>
        ) : null}
      </head>
      <body className="min-h-full bg-zinc-950 text-zinc-100 antialiased">
        {ANALYTICS ? (
          <noscript>
            <iframe
              title="Google Tag Manager"
              src={`https://www.googletagmanager.com/ns.html?id=${GTM_ID}`}
              height="0"
              width="0"
              style={{ display: "none", visibility: "hidden" }}
            />
          </noscript>
        ) : null}
        {children}
      </body>
    </html>
  );
}
