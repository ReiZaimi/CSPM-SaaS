import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

/**
 * Flat config, because ESLint 9 removed the `.eslintrc` format and the `--ext`
 * flag along with it.
 *
 * There was no config here at all: `npm run lint` pointed at a file that did
 * not exist, with ESLint itself absent from the dependencies and arriving only
 * as somebody else's transitive install. It failed the same way whether the
 * code was clean or not, and nothing noticed because the CI job runs types,
 * tests and build and never called it. That is the actual bug -- a lint script
 * nobody runs is a lint script that stops working -- so the CI job now runs it.
 */
export default tseslint.config(
  {
    // Build output and the vendored registry components are not ours to lint.
    ignores: ["dist", "node_modules", "coverage"],
  },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // Vite's fast refresh only works when a module exports components and
      // nothing else. A warning rather than an error: several pages
      // legitimately export a helper beside their component, and breaking the
      // build over a development-time convenience would be the wrong trade.
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // The type checker already fails the build on an unused local
      // (`noUnusedLocals`), and having both report it means fixing the same
      // thing twice in two vocabularies.
      "@typescript-eslint/no-unused-vars": "off",

      // `any` is worth arguing about, and it is not worth failing a build over
      // while there are still a handful in code that predates this config.
      "@typescript-eslint/no-explicit-any": "warn",
    },
  },
  {
    // shadcn components are vendored source: they are ours to edit, but they
    // arrive from the registry in the registry's own style and re-formatting
    // them on arrival would make every future `add --diff` unreadable.
    files: ["src/components/ui/**"],
    rules: {
      "react-refresh/only-export-components": "off",
      "@typescript-eslint/no-empty-object-type": "off",
    },
  },
  {
    // A provider and the hook that reads it belong in one file: splitting them
    // to satisfy a development-time refresh optimisation would put the context
    // and its only consumer in different modules for no reader's benefit.
    files: ["src/i18n/index.tsx"],
    rules: { "react-refresh/only-export-components": "off" },
  },
  {
    files: ["**/*.test.{ts,tsx}", "src/test/**"],
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
    },
  },
);
