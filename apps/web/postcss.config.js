export default {
  // Tailwind v4 is its own PostCSS plugin and carries vendor prefixing and
  // `@import` inlining itself, so autoprefixer and postcss-import are gone
  // rather than merely unused.
  plugins: { "@tailwindcss/postcss": {} },
};
