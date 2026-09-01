import { Suspense, lazy, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/Shell";
import { useAuthToken } from "@/lib/useAuth";
import { authReady } from "@/lib/supabase";
import { Spinner } from "@/components/ui/spinner";

/**
 * Every page behind a dynamic import.
 *
 * The whole product used to arrive in one file, so somebody landing on the
 * sign-in screen downloaded the compliance tables, the attack-path renderer and
 * the charting library before they could type a password. Splitting per route
 * means a page's code is fetched when it is first opened and cached after.
 *
 * `lazy` rather than a router-level loader because this app has no data router:
 * the boundary is the component, and one `Suspense` around the route tree is
 * the whole mechanism.
 *
 * Named exports, so each of these unwraps the one it wants -- `lazy` resolves a
 * module's `default` and nothing here has one.
 */
const SignInPage = lazy(() =>
  import("@/pages/SignIn").then((m) => ({ default: m.SignInPage })),
);
const ResetPasswordPage = lazy(() =>
  import("@/pages/ResetPassword").then((m) => ({
    default: m.ResetPasswordPage,
  })),
);
const OnboardingPage = lazy(() =>
  import("@/pages/Onboarding").then((m) => ({ default: m.OnboardingPage })),
);
const ConnectPage = lazy(() =>
  import("@/pages/Connect").then((m) => ({ default: m.ConnectPage })),
);
const ConnectionSetupPage = lazy(() =>
  import("@/pages/ConnectionSetup").then((m) => ({
    default: m.ConnectionSetupPage,
  })),
);
const DashboardPage = lazy(() =>
  import("@/pages/Dashboard").then((m) => ({ default: m.DashboardPage })),
);
const ChangesPage = lazy(() =>
  import("@/pages/Changes").then((m) => ({ default: m.ChangesPage })),
);
const ReportsPage = lazy(() =>
  import("@/pages/Reports").then((m) => ({ default: m.ReportsPage })),
);
const SettingsPage = lazy(() =>
  import("@/pages/Settings").then((m) => ({ default: m.SettingsPage })),
);
const AssetsPage = lazy(() =>
  import("@/pages/Assets").then((m) => ({ default: m.AssetsPage })),
);
const AssetDetailPage = lazy(() =>
  import("@/pages/AssetDetail").then((m) => ({ default: m.AssetDetailPage })),
);
const FindingsPage = lazy(() =>
  import("@/pages/Findings").then((m) => ({ default: m.FindingsPage })),
);
const FindingDetailPage = lazy(() =>
  import("@/pages/FindingDetail").then((m) => ({
    default: m.FindingDetailPage,
  })),
);
const RisksPage = lazy(() =>
  import("@/pages/Risks").then((m) => ({ default: m.RisksPage })),
);
const RiskDetailPage = lazy(() =>
  import("@/pages/RiskDetail").then((m) => ({ default: m.RiskDetailPage })),
);
const AttackPathsPage = lazy(() =>
  import("@/pages/AttackPaths").then((m) => ({ default: m.AttackPathsPage })),
);
const ScansPage = lazy(() =>
  import("@/pages/Scans").then((m) => ({ default: m.ScansPage })),
);
const RulesPage = lazy(() =>
  import("@/pages/Rules").then((m) => ({ default: m.RulesPage })),
);
const CompliancePage = lazy(() =>
  import("@/pages/Compliance").then((m) => ({ default: m.CompliancePage })),
);
const ComplianceFrameworkPage = lazy(() =>
  import("@/pages/ComplianceFramework").then((m) => ({
    default: m.ComplianceFrameworkPage,
  })),
);
const RemediationPage = lazy(() =>
  import("@/pages/Remediation").then((m) => ({ default: m.RemediationPage })),
);

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
    // One boundary around the whole tree. A per-route boundary would let each
    // page choose its own placeholder, which sounds better and is worse: the
    // Shell stays mounted across a navigation, so what a reader actually sees
    // is the chrome they already had plus a spinner where the page will be.
    <Suspense fallback={<PageLoading />}>
      <Routes>
        <Route path="/sign-in" element={<SignInPage />} />
        {/* Not behind RequireAuth: a recovery link carries its own session, and
          an expired one needs to say so rather than bounce to sign-in. */}
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route
          path="/onboarding"
          element={
            <RequireAuth>
              <OnboardingPage />
            </RequireAuth>
          }
        />
        <Route
          element={
            <RequireAuth>
              <Shell />
            </RequireAuth>
          }
        >
          <Route path="/" element={<DashboardPage />} />
          <Route path="/changes" element={<ChangesPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/assets/:assetId" element={<AssetDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/findings/:findingId" element={<FindingDetailPage />} />
          <Route path="/risks" element={<RisksPage />} />
          <Route path="/risks/:riskId" element={<RiskDetailPage />} />
          <Route path="/attack-paths" element={<AttackPathsPage />} />
          <Route path="/remediation" element={<RemediationPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/compliance" element={<CompliancePage />} />
          <Route
            path="/compliance/:frameworkId"
            element={<ComplianceFrameworkPage />}
          />
          <Route path="/connections" element={<ConnectPage />} />
          {/* The wizard has its own URLs because setup leaves the browser for
              Microsoft and for Azure Portal and comes back through a full page
              load. A dialog over the list could not survive either trip. */}
          <Route path="/connections/new" element={<ConnectionSetupPage />} />
          <Route
            path="/connections/:connectionId/setup"
            element={<ConnectionSetupPage />}
          />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

function PageLoading() {
  return (
    <div className="flex min-h-64 items-center justify-center">
      <Spinner />
    </div>
  );
}
