/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Severity is a first-class visual language in a security product:
        // the same colour must mean the same thing on every screen.
        critical: { DEFAULT: "#b91c1c", bg: "#fef2f2", border: "#fecaca" },
        high: { DEFAULT: "#c2410c", bg: "#fff7ed", border: "#fed7aa" },
        medium: { DEFAULT: "#a16207", bg: "#fefce8", border: "#fde68a" },
        low: { DEFAULT: "#1d4ed8", bg: "#eff6ff", border: "#bfdbfe" },
        unknown: { DEFAULT: "#57534e", bg: "#fafaf9", border: "#e7e5e4" },
        ok: { DEFAULT: "#15803d", bg: "#f0fdf4", border: "#bbf7d0" },
      },
    },
  },
  plugins: [],
};
