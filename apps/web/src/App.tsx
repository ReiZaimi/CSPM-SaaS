import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/Shell";
import { auth } from "@/lib/api";
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
  return auth.token ? children : <Navigate to="/sign-in" replace />;
}

export function App() {
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
