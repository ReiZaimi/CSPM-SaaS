import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/Shell";
import { useAuthToken } from "@/lib/useAuth";
import { authReady } from "@/lib/supabase";
import { Spinner } from "@/components/ui";
import { SignInPage } from "@/pages/SignIn";
import { OnboardingPage } from "@/pages/Onboarding";
import { ConnectPage } from "@/pages/Connect";
import { ConnectResultPage } from "@/pages/ConnectResult";
import { DashboardPage } from "@/pages/Dashboard";
import { AssetsPage } from "@/pages/Assets";
import { AssetDetailPage } from "@/pages/AssetDetail";
import { FindingsPage } from "@/pages/Findings";
import { FindingDetailPage } from "@/pages/FindingDetail";
import { RisksPage } from "@/pages/Risks";
import { ScansPage } from "@/pages/Scans";
import { RulesPage } from "@/pages/Rules";
import { RemediationPage } from "@/pages/Remediation";

function RequireAuth({ children }: { children: JSX.Element }) {
  // Subscribed rather than read once, so a session that arrives late — or a
  // token that refreshes an hour in — re-renders instead of stranding the user.
  const token = useAuthToken();
  return token ? children : <Navigate to="/sign-in" replace />;
}

/**
 * Waits for the initial Supabase session check before the router decides
 * anything. Without this, a page load mid-magic-link-redirect would see
 * `auth.token` still null (the session hasn't finished parsing out of the URL
 * fragment yet) and bounce straight back to /sign-in.
 */
function useAuthReady(): boolean {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    authReady.then(() => setReady(true));
  }, []);
  return ready;
}

export function App() {
  const ready = useAuthReady();
  if (!ready) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  }

  return (
    <Routes>
      <Route path="/sign-in" element={<SignInPage />} />
      <Route path="/onboarding" element={<RequireAuth><OnboardingPage /></RequireAuth>} />
      <Route path="/connect/result" element={<ConnectResultPage />} />

      <Route
        element={
          <RequireAuth>
            <Shell />
          </RequireAuth>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/assets/:assetId" element={<AssetDetailPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:findingId" element={<FindingDetailPage />} />
        <Route path="/risks" element={<RisksPage />} />
        <Route path="/remediation" element={<RemediationPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/connections" element={<ConnectPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
