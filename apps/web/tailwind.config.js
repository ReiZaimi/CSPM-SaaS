/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // --- shadcn semantic surface tokens ------------------------------
        //
        // Written by hand rather than by the CLI, which emits the Tailwind v4
        // form (`@theme inline`) and left this v3 config untouched -- so every
        // `bg-background` in a generated component referred to a class that did
        // not exist and the build failed outright.
        //
        // Declared as `var(--x)` rather than `hsl(var(--x))` because the CSS
        // variables hold complete oklch colours, not channel triplets. Wrapping
        // them in `hsl()` is the usual v3 recipe and would silently produce
        // black.
        border: "var(--border)",
        input: "var(--input)",
        ring: "var(--ring)",
        background: "var(--background)",
        foreground: "var(--foreground)",
        primary: {
          DEFAULT: "var(--primary)",
          foreground: "var(--primary-foreground)",
        },
        secondary: {
          DEFAULT: "var(--secondary)",
          foreground: "var(--secondary-foreground)",
        },
        destructive: {
          DEFAULT: "var(--destructive)",
          foreground: "var(--primary-foreground)",
        },
        muted: {
          DEFAULT: "var(--muted)",
          foreground: "var(--muted-foreground)",
        },
        accent: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-foreground)",
        },
        popover: {
          DEFAULT: "var(--popover)",
          foreground: "var(--popover-foreground)",
        },
        card: {
          DEFAULT: "var(--card)",
          foreground: "var(--card-foreground)",
        },
        sidebar: {
          DEFAULT: "var(--sidebar)",
          foreground: "var(--sidebar-foreground)",
          primary: "var(--sidebar-primary)",
          "primary-foreground": "var(--sidebar-primary-foreground)",
          accent: "var(--sidebar-accent)",
          "accent-foreground": "var(--sidebar-accent-foreground)",
          border: "var(--sidebar-border)",
          ring: "var(--sidebar-ring)",
        },

        // --- CloudGuard's own vocabulary ---------------------------------
        //
        // Kept, and kept *separate* from the semantic tokens above. Severity is
        // a first-class visual language in a security product: the same colour
        // must mean the same thing on every screen, and it must not drift when
        // somebody changes the theme's accent.
        //
        // These are deliberately not expressed as `primary`/`destructive`.
        // `destructive` means "this button deletes something"; `critical` means
        // "an attacker can reach your data". Collapsing the two would make a
        // cancel button and a public storage account the same colour.
        critical: {
          DEFAULT: "var(--sev-critical)",
          bg: "var(--sev-critical-bg)",
          border: "var(--sev-critical-border)",
        },
        high: {
          DEFAULT: "var(--sev-high)",
          bg: "var(--sev-high-bg)",
          border: "var(--sev-high-border)",
        },
        medium: {
          DEFAULT: "var(--sev-medium)",
          bg: "var(--sev-medium-bg)",
          border: "var(--sev-medium-border)",
        },
        low: {
          DEFAULT: "var(--sev-low)",
          bg: "var(--sev-low-bg)",
          border: "var(--sev-low-border)",
        },
        // Its own colour rather than a shade of LOW, because a gap in knowledge
        // is not a mild problem. Everything that renders UNKNOWN also carries a
        // dashed border (see `format.ts`), so it stays distinguishable to
        // someone who cannot separate the hues.
        unknown: {
          DEFAULT: "var(--sev-unknown)",
          bg: "var(--sev-unknown-bg)",
          border: "var(--sev-unknown-border)",
        },
        ok: {
          DEFAULT: "var(--sev-ok)",
          bg: "var(--sev-ok-bg)",
          border: "var(--sev-ok-border)",
        },
      },
      borderRadius: {
        xl: "calc(var(--radius) + 4px)",
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [],
};
