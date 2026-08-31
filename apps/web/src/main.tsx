import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { I18nProvider } from "@/i18n";
import { App } from "@/App";
import { configProblems } from "@/lib/config";
import { ConfigError } from "@/components/ConfigError";
import { initTheme } from "@/lib/theme";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
  },
});

// The inline script in index.html has already put the class on the document;
// this re-reads the same stored choice so React's view of it is derived
// rather than assumed, and starts following the OS while the tab is open.
initTheme();

// A misconfigured production build cannot reach its API at all, so there is
// nothing useful to render -- say why instead of failing silently.
const problems = configProblems();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    {problems.length > 0 ? (
      <ConfigError problems={problems} />
    ) : (
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <I18nProvider>
            <App />
          </I18nProvider>
        </BrowserRouter>
      </QueryClientProvider>
    )}
  </React.StrictMode>,
);
